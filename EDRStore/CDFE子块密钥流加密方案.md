# CDFE 子块密钥流加密：第一版实验方案

## 1. 实验目标

当前整块流加密会让密钥流绑定块内偏移：明文发生插入或删除后，后续相同内容虽然仍然存在，但会落在不同偏移并使用不同密钥流，导致密文相似性迅速消失。

第一版改为：先用 CDFE 将待加密数据切成内容定义子块，再独立加密每个子块。子块密钥不包含子块位置，因此 CDFE 在插入/删除后重新同步时，未变化的子块仍会产生相同的密文，供 local/global 的 CDFE 检测和 xdelta 利用。

该实验不改变现有 Finesse/CDFE 的职责划分：

- 客户端明文特征及 KeyServer 聚类、seed 分配继续使用 Finesse。
- 客户端和服务端的密文相似性检测继续使用 CDFE。
- U（未压缩表示）和 C（压缩表示）的上传、cache、全局检测及存储流程不变。
- 只替换客户端 `TwoPhaseEnc` 内部的加解密格式，并恢复 seed 派生密钥，去掉“所有块固定为 0x42 密钥”的临时实验。

## 2. 密钥层次

KeyServer 返回聚类 seed 后，客户端先派生该聚类的主密钥：

```text
master_key = HMAC-SHA256(user_secret,
                         "EDR-CLUSTER-MASTER-V1" || keyserver_seed)
```

相同 Finesse 聚类 seed 和相同用户密钥会得到相同 `master_key`。最终的 32 字节 `master_key` 仍写入现有 key recipe，因此不需要修改 recipe 格式和下载流程。

对每个 CDFE 子块：

```text
plain_hash = SHA256(plain_subblock)
content_id = HMAC-SHA256(master_key,
                         "EDR-CONTENT-ID-V1" || plain_hash)[0..15]

subkey = HMAC-SHA256(master_key,
                     "EDR-SUBSTREAM-V1" || cdfe_feature || content_id)

cipher_subblock = AES-256-CTR(subkey, zero_iv, plain_subblock)
```

`subkey` 不使用 offset、rank 或子块序号。因此，同一 master key 下，内容和 CDFE feature 都相同的子块即使移动到不同位置，也会得到相同密文。

这里没有直接采用 `PRF(master_key, feature)`。CDFE feature 是近似特征，不保证两个不同子块的 feature 唯一；若只按 feature 复用 CTR 密钥流，不同明文可能复用同一密钥流，攻击者可由两个密文得到两个明文的异或。加入 128 位 keyed `content_id` 后，只有实际内容相同（或发生极低概率碰撞）的子块才复用密钥流。

## 3. 密文帧格式

每个加密后的 U 或 C 都保存为一个自描述帧：

```text
+----------------------+ 20 bytes
| magic/version/flags  |
| original_size        |
| subblock_count       |
| descriptor_size      |
| body_offset          |
+----------------------+
| descriptor[0]        | length + CDFE feature + 16-byte content_id
| ...                  |
| descriptor[n-1]      |
+----------------------+
| cipher subblock 0    |
| ...                  |
| cipher subblock n-1  |
+----------------------+
| authentication tag   | HMAC-SHA256 截断为 16 bytes
+----------------------+
```

认证密钥由 `master_key` 和独立标签 `EDR-AUTH-V1` 派生，认证范围是 header、全部 descriptors 和 ciphertext body。解密时先验证 tag，再解密，并重新计算每个子块的 keyed `content_id`，避免错误密钥或损坏数据被静默接受。

整数使用固定小端编码，避免依赖 C++ 结构体填充。最大帧空间从原来的约 16 KiB 增加到 20 KiB，以容纳描述符和 tag。

## 4. 与当前 EDRStore 流程的衔接

### U：未压缩块

原始 FastCDC 块直接进入 CDFE 子块加密。服务端仍把完整加密 U 用于 local cache/base；客户端判定相似块时上传 U+C 的既有逻辑不变。

### C：压缩块

客户端先执行现有通用压缩与 padding，再对压缩后的字节串执行 CDFE 子块加密。服务端仍对收到的加密 C 做精确去重、CDFE 全局相似检测和最终存储。

### 恢复

key recipe 中保存的是 `master_key`。客户端从密文帧读取子块描述符，逐个派生 `subkey` 并解密；C 再走现有解压流程。服务端返回压缩 base 后，客户端已有的“解密 C、解压、重新加密成 U”路径继续工作。

### 旧数据

第一版保留旧 TwoPhase 密文的只读解密兼容：没有新帧 magic 的密文仍按旧 AES-CTR + AES-ECB 逆流程处理。新上传数据只写新格式。因为主密钥派生逻辑已经改变，做可比压缩实验时仍建议使用干净的服务端容器、索引、cache 和客户端 recipe。

## 5. 预期效果与观测指标

预期可改善“插入/删除造成偏移”的相似密文：CDFE 边界重新同步后，未变子块的 descriptor 和 ciphertext body 都能复用，xdelta 可跨位置匹配这些字节。

测试时至少比较：

- client similar chunk num；
- server similar chunk num (l) 与有效 local delta 数；
- server similar chunk num (g) 与有效 global delta 数；
- local/global delta 实际字节数；
- 总上传量、container 写入量；
- 新密文帧描述符带来的固定开销；
- 上传后下载文件的逐字节一致性。

## 6. 当前边界与后续方向

这是一版压缩效果原型，不是最终密码协议：

- 确定性子块密文会泄露“同一 master key 下子块是否相同”；这是服务端密文相似检测得以工作的直接代价。
- descriptor 当前明文携带 CDFE feature 和 keyed content ID；虽然 content ID 不是裸 SHA-256，仍会暴露重复关系和结构信息。
- U 与 C 目前复用同一个接口和 master key。安全版通过 content ID 区分不同内容；当前 feature-only 对照版不会区分 feature 相同但内容不同的子块。正式版本可再加入 representation domain（U/C）做更严格的域隔离。
- 服务端当前对完整密文帧重新提取 CDFE 特征，header/descriptor 也会参与特征提取。第一版优先验证压缩收益；若元数据干扰明显，后续应让相似检测只扫描 ciphertext body。
- CDFE 的边界稳定性决定可复用范围。需要用真实插入、删除、替换数据集测量，而不能只看完全相同块。

### 当前实验切换：feature-only

为了单独观察最大化密文相似性后的压缩效果，当前代码已切换为高风险的 `feature-only` 对照模式：

```text
subkey = HMAC-SHA256(master_key,
                     "EDR-SUBSTREAM-FEATURE-ONLY-V1" || cdfe_feature)
```

新写入帧的 flags 为 `FEATURE_ONLY`；解密端仍兼容上一版 flags=0 的 `feature + content_id` 安全模式。

该模式会让同一 master key 下所有 feature 相同的子块复用 AES-CTR 密钥流，即使子块实际内容不同。若出现 feature 碰撞，攻击者可以计算 `cipher1 XOR cipher2 = plain1 XOR plain2`，因此只用于隔离压缩实验，不应用于真实数据存储或生产环境。

## 7. 第一版 smoke test 记录

使用两个 12 KiB 随机块做结构测试：第二个块在偏移 3000 处插入 256 字节，并从尾部删除相同长度，使总长度不变。两个版本使用同一 master key。

- 新格式加密、解密往返正确，重复加密结果一致，旧 TwoPhase 密文可正常读取。
- 两个新密文帧中有 15 个完全一致的 CDFE 子块，共 10,848 字节。
- `feature + content_id` 安全版 xdelta 大小为 1,549 / 12,800 字节，约 12.1%。
- 切换到 feature-only 后，xdelta 大小进一步降为 1,053 / 12,800 字节，约 8.2%。
- 旧整块 AES-CTR + AES-ECB 格式 xdelta 大小为 9,337 / 12,304 字节，约 75.9%。

该结果只验证机制在插入偏移场景下生效，不等同于真实数据集收益；最终效果需要按第 5 节指标跑完整上传/下载实验。
