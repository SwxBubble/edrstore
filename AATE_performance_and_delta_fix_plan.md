# AATE 性能与 Delta 收益修复方案

## 1. 背景与现状

当前 AATE 原型已经验证了以下核心正确性：

- 固定窗口内容 anchor 可以在插入/删除后重新同步；
- anchor 后相同 region 可以生成相同 ciphertext payload；
- region payload 可以保持 length-preserving；
- recipe 可以支持解密与边界恢复。

但 GCC tar 实验暴露出两个独立问题：

1. **空间收益没有提升**：旧方案本地 delta 平均约 214B，而当前 AATE envelope
   平均增加约 476.6B metadata，metadata 开销已经超过旧方案的整个 delta。
2. **运行速度下降约 14.6 倍**：累计 16.2GB 数据中，AATE 加密耗时约 5968 秒，
   占总运行时间约 97%，吞吐只有约 2.59MiB/s。

根因包括：

- `ANCHOR_PATTERN = 0` 使 48B 全零窗口必然成为 anchor；
- 没有 `min_region_size`，连续零区会产生大量 1B region；
- encrypted recipe 和 payload 被一起送入 xdelta；
- 客户端与服务端部分路径计算 ciphertext feature 的范围不一致；
- 每个 16B block 都执行 HMAC、动态内存分配和多次单块 EVP 调用。

本方案的目标不是继续堆叠策略，而是先消除这些确定性的工程问题，再判断 AATE
payload 本身是否真正改善 delta compression。

---

## 2. 修复目标

修复后必须满足：

1. 全零窗口不会成为 anchor。
2. 不会出现大量连续 1B region。
3. xdelta 只比较和编码 ciphertext payload，不处理 encrypted recipe。
4. 所有 ciphertext resemblance feature 只从 payload 计算。
5. 完整 block 的 mask 生成不再逐 block 调用 HMAC。
6. AATE 加密吞吐至少高于整体上传管线吞吐，不能继续成为瓶颈。
7. 日志同时给出 payload-only 和 metadata-inclusive 两组结果。
8. 只有当 `payload delta + metadata` 小于旧方案总存储时，才能认定 AATE 有收益。

---

## 3. P0：修复 anchor 风暴

### 3.1 使用非零 ANCHOR_PATTERN

参数改为：

```text
WINDOW_SIZE    = 48
ANCHOR_MASK    = 0x3FF
ANCHOR_PATTERN = 0x2A5
```

判断条件：

```text
(rolling_fp & ANCHOR_MASK) == ANCHOR_PATTERN
```

选择 `0x2A5` 没有特殊密码学含义，只要求：

- 非零；
- 小于等于 `ANCHOR_MASK`；
- 固定写入格式版本，不能随进程随机变化。

这样 48B 全零窗口的 Rabin fingerprint 即使为 0，也不会成为 anchor；普通高熵数据仍
保持平均约 1024B 一个 candidate。

### 3.2 加入最小 region 大小

建议第一轮参数：

```text
MIN_REGION_SIZE = 256B
```

candidate 的定义仍然只由当前窗口内容决定，但 candidate 是否被接受为 boundary 还需要：

```text
candidate_boundary - previous_boundary >= MIN_REGION_SIZE
```

伪代码：

```text
if hash_matches_pattern(window):
    candidate_count++

    if boundary - previous_boundary >= MIN_REGION_SIZE:
        accept boundary
        previous_boundary = boundary
    else:
        suppressed_candidate_count++
```

该策略会使“是否接受 candidate”依赖上一个已接受 boundary，因此理论上可能将重新同步
推迟到后续 candidate，但一旦双方接受同一个稳定 anchor，后续 region 会重新同步。
第一版优先避免 region 风暴；后续如需更严格的内容局部选择，可改为固定邻域内的
min-hash/winnowing。

### 3.3 低熵区域保护

第一版不必计算昂贵的 Shannon entropy。采用以下轻量保护即可：

```text
if all bytes in current anchor window are identical:
    reject candidate
```

该检查主要覆盖全零和重复填充。实现时维护窗口内字节频次或不同字节计数，避免每个窗口
重新扫描 48B。

### 3.4 Anchor 数量安全上界

对最大 AATE plaintext，理论边界数量上限为：

```text
MAX_ANCHORS = ceil(AATE_MAX_PLAIN_SIZE / MIN_REGION_SIZE)
```

发现超过上限说明实现或输入校验异常，应终止该 chunk 加密，不能退化成无界 metadata。

### 3.5 参数实验矩阵

至少测试：

```text
ANCHOR_MASK:     0x1FF, 0x3FF, 0x7FF
MIN_REGION_SIZE: 128B, 256B, 512B
```

记录 payload-only delta 后再决定最终参数，不应只根据 anchor 数量选择。

---

## 4. P0：metadata 与 payload 分离

### 4.1 逻辑对象格式

将当前单一 envelope 改为逻辑上的两个部分：

```text
struct AATECipherObject {
    metadata: encrypted recipe,
    payload:  length-preserving region ciphertext,
}
```

其中：

- `metadata` 由 AES-GCM 认证加密；
- `payload` 长度等于被加密数据长度；
- 服务端保存 metadata，但不解密、不解析 boundary；
- Finesse、相似块选择和 xdelta 只处理 payload。

### 4.2 网络格式

扩展 chunk header：

```text
struct SendChunkHeader {
    ... existing fields ...
    uint32_t metadata_size;
    uint32_t payload_size;
}
```

网络字节布局：

```text
[SendChunkHeader] [encrypted_metadata] [ciphertext_payload]
```

服务端只根据长度拆分两部分。metadata 对服务端仍然是不透明字节串。

必须验证：

```text
metadata_size <= AATE_MAX_METADATA_SIZE
payload_size  <= AATE_MAX_PLAIN_SIZE
metadata_size + payload_size 不溢出接收缓冲区
```

### 4.3 存储格式

非 delta chunk：

```text
[ObjectHeader] [metadata] [payload]
```

delta chunk：

```text
[ObjectHeader] [target_metadata] [delta(payload_base, payload_target)]
```

数据库地址结构至少记录：

```text
metadata_len
stored_payload_len
original_payload_len
```

恢复 target 时：

1. 服务端读取 base payload；
2. 对 payload delta decode；
3. 取出 target 自己的 metadata；
4. 向客户端发送 `target_metadata + restored_target_payload`。

Full EDR 中如果客户端需要解密一个辅助 compressed base，服务端必须同时返回该 base
对象自己的 metadata，不能复用 target metadata。

### 4.4 指纹与去重

精确 dedup fingerprint 建议计算：

```text
object_fp = SHA256(metadata || payload)
```

相似特征只计算：

```text
cipher_features = Finesse(payload)
```

这两个概念不能混用：

- fingerprint 用于判断完整对象完全相同；
- feature 用于为 payload delta 选择 base。

### 4.5 metadata 编码

加入 `MIN_REGION_SIZE` 后最大 boundary 数量已经较小，优先使用 delta 编码：

```text
first_boundary
boundary_delta_1
boundary_delta_2
...
```

对于最大 16KiB chunk 和 `MIN_REGION_SIZE=256B`，最多约 64 个 region。可以使用
`uint16_be`，或使用有严格长度上限的 varint。

保留 bitmap 仅作为兼容解析格式；正常数据不应再进入 2KiB bitmap recipe。

---

## 5. P0：统一 feature 计算范围

以下所有路径必须调用同一个公共函数取得 payload：

```text
GetAATEPayload(object) -> payload_ptr, payload_size
```

需要检查并修改：

1. 客户端 `CipherSimilarThd`；
2. 服务端 `DataRecvThd` 的 NORMAL_CHUNK 路径；
3. 服务端 `DualDedupThd` 的 CHUNK_PAIR 路径；
4. cache 插入与 cache 查询路径；
5. global feature index 更新路径。

禁止再次出现：

```text
一部分 feature = Finesse(payload)
另一部分 feature = Finesse(metadata || payload)
```

修复后应验证同一个对象在客户端和服务端得到完全相同的三个 super feature。

---

## 6. P0：去掉逐 block HMAC 和动态分配

### 6.1 Counter block 直接编码

当前每个 16B block 调用 HMAC 生成 AES 输入，成本过高。改为：

```text
region_nonce = first_12_bytes(region_salt)
counter_block_j = region_nonce || uint32_be(local_counter_j)
mask_j = AES_encrypt(K_mask, counter_block_j)
```

约束：

- local counter 从 0 开始；
- counter 只属于当前 region；
- 一个 region 的 block 数必须小于 `2^32`；
- `region_salt` 仍由 left anchor tag 派生，因此不同 region 使用不同 nonce。

这不会重新引入 chunk offset、region index 或 global block index。

### 6.2 批量生成 mask

每个 region 预先构造连续 counter block：

```text
counter_blocks[0 ... full_block_count-1]
```

然后一次调用 EVP：

```text
EVP_EncryptUpdate(mask_ctx, masks, ..., counter_blocks, full_block_count * 16)
```

完成 XOR 后，再一次批量调用 AES permutation：

```text
EVP_EncryptUpdate(perm_ctx, cipher_blocks, ..., x_blocks, full_block_count * 16)
```

不要对每个 block 单独调用 `EVP_EncryptUpdate`。

### 6.3 内存管理

每个 `TwoPhaseEnc` 实例预分配可复用 scratch buffer：

```text
counter_buf[AATE_MAX_PLAIN_SIZE rounded to block]
mask_buf[AATE_MAX_PLAIN_SIZE rounded to block]
x_buf[AATE_MAX_PLAIN_SIZE rounded to block]
```

禁止在 block 循环内创建：

```text
std::vector
std::string
EVP_CIPHER_CTX
EVP_PKEY
```

### 6.4 Tail

region tail 继续使用 length-preserving XOR，但只生成一次 mask block：

```text
tail_counter_block = region_nonce || uint32_be(full_block_count)
tail_mask = AES(K_mask, tail_counter_block)
tail_perm = AES(K_tail, tail_counter_block XOR TAIL_DOMAIN_CONSTANT)
tail_cipher = tail_plain XOR tail_mask XOR tail_perm
```

这样 tail 不再额外调用 HMAC。`TAIL_DOMAIN_CONSTANT` 必须固定且只用于 tail 域分离。

### 6.5 HMAC 保留位置

HMAC 只保留在：

- chunk 级子密钥派生；
- anchor tag；
- region salt；
- metadata 认证/nonce 派生。

正常情况下 HMAC 次数应与 region 数量同阶，而不是与 16B block 数量同阶。

---

## 7. P1：增加 payload-only 统计

### 7.1 客户端统计

每个文件输出：

```text
total_anchor_candidates
accepted_anchor_count
suppressed_anchor_count
identical_window_reject_count
region_count
min_region_size_observed
avg_region_size
max_region_size_observed
metadata_bytes
payload_bytes
anchor_scan_time
key_derivation_time
payload_encrypt_time
metadata_encrypt_time
```

### 7.2 服务端统计

分别记录 local cache delta 和 global delta：

```text
similar_payload_bytes
payload_delta_bytes
metadata_bytes
stored_object_bytes = payload_delta_bytes + metadata_bytes + object_header_bytes
payload_delta_ratio = payload_delta_bytes / similar_payload_bytes
total_storage_ratio = stored_object_bytes / corresponding_plain_or_payload_bytes
```

旧的 `delta size` 字段必须明确是：

```text
payload delta only
```

同时新增完整对象存储字段，避免只看 payload delta 得出虚假收益。

### 7.3 调试统计

在实验构建中增加：

```text
same_similarity_seed_pair_count
different_similarity_seed_pair_count
aligned_region_bytes
equal_cipher_block_count
```

如果 base 与 target 的 similarity seed 不同，则相同 anchor 内容也不会生成相同密文。
该统计可以验证 key server 的分组是否真的与服务端选择的 delta base 一致。

生产构建不需要把 seed 或其可关联标识写入日志。

---

## 8. 测试计划

### 8.1 Anchor 测试

必须覆盖：

1. 16KiB 全零数据：接受 anchor 数应为 0。
2. 16KiB 单一重复字节：接受 anchor 数应为 0。
3. 随机数据：平均 anchor 间距接近 mask 期望值。
4. 任意相邻 accepted boundary 间距不小于 `MIN_REGION_SIZE`。
5. 前插入和删除后，在后续稳定 anchor 处重新同步。

### 8.2 密码与长度测试

继续覆盖：

- 1B、15B、16B、17B region；
- 最大 plaintext；
- encrypt/decrypt round trip；
- 相同 seed 的确定性输出；
- 错误 seed 和 metadata 篡改失败；
- payload 长度严格等于 plaintext 长度。

### 8.3 Metadata 分离测试

1. 修改 metadata 不影响服务端解析 payload 长度，但客户端认证必须失败。
2. xdelta 输入中不得出现 metadata 字节。
3. target payload 经 delta decode 后，与 target metadata 重新组合可以成功解密。
4. Full EDR 辅助 base 必须使用 base 自己的 metadata 解密。

### 8.4 Feature 一致性测试

同一 ciphertext object 分别经过客户端和服务端 feature 路径，断言：

```text
client_features == server_features
```

### 8.5 性能测试

单线程测试至少包括：

- 190MB `gcc-3.4.1.tar`；
- 全零 190MB 合成数据；
- 高熵随机 190MB 数据；
- 带固定间隔插入/删除的版本化数据。

记录：

```text
MiB/s
cycles/byte（如果可用）
HMAC calls/chunk
EVP calls/chunk
accepted anchors/chunk
```

---

## 9. 实验方法

每次新旧对比必须：

1. 使用相同 GCC 文件顺序；
2. 使用相同 chunker 参数；
3. 分别清空并重建 server DB、container、cache 和 client cache metadata；
4. 确认逻辑 chunk 数、逻辑原始字节数完全相同；
5. 至少重复三次，报告均值与标准差；
6. 分开报告冷缓存和热缓存结果；
7. 同时报告 payload-only 和 metadata-inclusive 结果。

建议增加两类数据集：

### 9.1 目标场景合成数据

构造：

```text
version_a = prefix || body
version_b = prefix || inserted_bytes || body
version_c = prefix || body_with_deletion
```

插入长度选择：

```text
1B, 3B, 7B, 15B, 31B, 100B
```

这类数据用于验证 AATE 的核心假设。

### 9.2 真实数据

继续使用 GCC tar，但需要认识到：外层 FastCDC 已经消除了大量跨文件偏移，旧方案本地
delta 比例已经约为 2.18%，可提升空间很小。GCC 结果用于判断总成本，而不能单独用于
证明 anchor-aligned encryption 的机制收益。

---

## 10. 验收标准

### 10.1 正确性

- 所有 round-trip 和篡改测试通过；
- 插入/删除后稳定 region 的 ciphertext payload 完全一致；
- 客户端与服务端 feature 完全一致；
- Full EDR 上传与恢复通过。

### 10.2 Anchor

- 全零 16KiB chunk 的 accepted anchor 为 0；
- 所有 accepted region 至少 256B，最后一个尾 region 除外；
- 正常随机数据 anchor 密度与参数预期基本一致；
- GCC 数据不再出现百万级零窗口 accepted anchor。

### 10.3 性能

第一阶段最低要求：

```text
AATE payload encryption throughput >= 100MiB/s（单线程）
```

目标要求：

```text
AATE payload encryption throughput >= 300MiB/s（单线程）
```

并且端到端上传速度不低于旧方案的 80%。

### 10.4 空间

必须同时满足：

```text
payload_delta_ratio < old_delta_ratio
metadata_bytes + payload_delta_bytes < old_stored_delta_bytes
final_storage_size <= old_final_storage_size
```

如果只满足第一项，说明核心 payload 机制有效，但 metadata 设计仍不合格，不能宣称系统
总存储收益提升。

---

## 11. 推荐实施顺序

### 阶段 A：先获得可信测量

1. 增加 anchor、region、metadata 和 payload-only delta 统计。
2. 修复客户端/服务端 feature 范围不一致。
3. 在不改变其他逻辑的情况下重新跑小规模 GCC 和合成数据。

### 阶段 B：消除 anchor 风暴和性能瓶颈

1. 使用非零 `ANCHOR_PATTERN`。
2. 加入 `MIN_REGION_SIZE=256B` 和相同字节窗口拒绝。
3. direct counter block 替代逐 block HMAC。
4. 批量 AES，移除 block 循环动态分配。
5. 完成单线程性能验收。

### 阶段 C：拆分 metadata 与 payload

1. 修改网络 header 和内存数据结构。
2. 修改 container/object 存储格式。
3. xdelta 只编码 payload。
4. 恢复路径携带 target/base 各自 metadata。
5. 完成 Full EDR 端到端上传与恢复测试。

### 阶段 D：重新评估方案价值

1. 比较旧方案、AATE payload-only、AATE total 三组结果。
2. 分析 GCC 与合成插入/删除数据的差异。
3. 如果 payload-only 仍没有改善，停止增加工程复杂度，重新审视 anchor salt、key group
   和 base selection 的设计。

---

## 12. 最终判断原则

下一轮实验必须回答两个不同问题：

1. **机制问题**：去掉 metadata 后，AATE payload 是否比旧密文产生更小的 delta？
2. **系统问题**：加回 metadata、索引和计算成本后，AATE 是否减少总存储且保持可接受吞吐？

只有两个答案都为“是”，AATE 才算在 EDRStore 上取得实际改进。

---

## 13. 本轮实现记录（2026-07-05）

已完成：

- 非零 `ANCHOR_MASK=0x1ff`、`ANCHOR_PATTERN=0x0a5` 和相同字节窗口拒绝；当前实验版已
  移除历史相关的 `MIN_REGION_SIZE`，由 bitmap 编码继续提供 metadata 固定上界；
- direct counter block、region 级批量 AES、复用临时缓冲区；
- 客户端与服务端所有 ciphertext feature 路径统一为 `Finesse(payload)`；
- local/global xdelta 均只处理 payload；delta 对象保存 target 自己的 metadata，所有
  服务端和客户端恢复路径在解码 payload 后重新组装完整 AATE 对象；
- 客户端 anchor/region/metadata/分阶段耗时统计，以及服务端 payload delta、metadata、
  完整 delta 对象大小和两组 ratio 统计；
- 全零、重复字节、插入/删除同步、payload-only xdelta 重组和认证解密测试。

当前网络仍发送自描述的连续 AATE 对象
`[AATE header + encrypted recipe metadata][payload]`，没有在 `SendChunkHeader_t` 中重复增加
`metadata_size/payload_size`。服务端通过经过边界校验的 AATE 外层头拆分两段；落盘 delta
使用独立的 `AADL` 头记录 `metadata_size/payload_size/delta_size`。这保持了现有上传协议，
同时保证 feature 和 xdelta 不接触 metadata。若以后需要服务端完全不识别 AATE 外层格式，
再把这两个长度提升到网络 header 即可。
