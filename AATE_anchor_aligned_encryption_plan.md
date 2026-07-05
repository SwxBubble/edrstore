# AATE 第一版实现方案：Anchor-Aligned Two-Phase Encryption

本文档用于交给 Codex 作为编码说明。目标是实现一个**锚点对齐的相似性保持加密原型**，用于改进 EDRStore 类方案在“插入/删除导致内容偏移”场景下的密文增量压缩效果。

---

## 1. 总目标

现有 EDRStore 类 two-phase encryption 的问题是：加密时的 keystream/counter 通常与 chunk 内的全局 block 位置相关。  
如果一个 chunk 前面插入几个字节，后续相同内容的全局位置发生变化，导致相同明文片段使用不同 keystream，最终密文不再相同，云端 delta compression 很难发现这些偏移后的相同内容。

本方案的目标是：

> 在 chunk 内部通过内容定义 anchor 建立同步点，使 anchor 后面的 region 使用由 anchor 内容派生的 keystream，而不是由 chunk 内绝对位置或 region 序号派生 keystream。这样即使前面发生插入或删除，后续相同内容仍有机会产生相同密文片段，从而提高密文增量压缩收益。

---

## 2. 第一版实现范围

第一版只实现核心机制，不加入过多策略。

### 2.1 第一版必须实现

1. 在 chunk 内部用 rolling hash 找 anchor。
2. anchor 判断只依赖当前窗口内容。
3. 在 anchor window 之后切分 region。
4. 每个 region 使用左侧 anchor 派生 `region_salt`。
5. region 的 keystream 不依赖以下任何位置因素：
   - region 是第几个 region；
   - region 在 chunk 中的起始偏移；
   - block 在 chunk 中的全局编号；
   - chunk 前面插入或删除了多少数据。
6. region 内部的 block 使用局部 counter，从 0 开始。
7. 实现加密与解密。
8. 输出必要 metadata/recipe 以支持解密。
9. 提供基础测试，验证偏移后 anchor 对齐 region 的密文可保持一致。

### 2.2 第一版暂不实现

第一版先不设置：

```text
min_region_size
max_region_size
```

也就是说：

```text
只要当前窗口满足 anchor 条件，就在 anchor window 后切分。
```

第一版也暂不实现：

```text
低熵区域回退
region 自适应大小
右 anchor 参与 salt
安全泄露评估
metadata 压缩
生产级密码学安全证明
```

后续版本再加入这些策略。

### 2.3 接入 EDRStore 前必须落实的修正

以下事项不是可选优化，而是第一版接入当前代码时必须满足的正确性条件：

1. **相似组内主密钥必须稳定。** 当前 EDRStore 使用
   `SHA256(chunk 前 32B || key_server_seed)` 生成最终 key；前部插入或删除会改变该
   key，使所有 anchor tag 和 region keystream 同时改变。AATE 第一版改为直接以 key
   server 返回、在相似组内一致的 `S` 为输入，通过带版本标签的 KDF 派生主密钥，
   不再混入 chunk 前 32B。
2. **region 加密必须 length-preserving。** 当前固定密文缓冲区无法容纳逐 region
   padding 的累计膨胀。每个 region 的密文长度必须严格等于其明文长度。
3. **metadata 必须和实际密文对象绑定。** EDRStore 会分别加密原块、压缩块，并在
   Full EDR 恢复时使用辅助 base 密文。边界 recipe 不能只绑定逻辑 chunk。本实现把
   经过认证加密的 recipe 放入密文 envelope；服务端只负责原样保存和重建，不解析
   recipe。
4. **完整 AES block 必须使用关闭 padding 的原始 AES-ECB primitive。** 不能逐块
   调用当前启用 PKCS padding 的 ECB 包装，否则一个 16B block 会膨胀成 32B。
5. **所有长度、边界数量和 envelope 字段都必须在解密前校验。** metadata 使用
   AES-256-GCM 认证加密，认证失败时不得继续解析或输出明文。

第一版仍不使用 `min_region_size` 和 `max_region_size`。为避免极端 anchor 数量造成
recipe 无界增长，边界采用稀疏 `uint16` 列表和固定大小 bitmap 两种编码中较短的一种；
对 16KiB 最大 raw chunk（以及压缩层可能追加的 4B 长度字段），bitmap 上界约为
2KiB。

---

## 3. 关键原则

### 3.1 anchor candidate 只取决于当前窗口内容

假设窗口大小为 `WINDOW_SIZE`，当前窗口为：

```text
W_i = chunk[i - WINDOW_SIZE + 1 : i + 1]
```

则：

```text
h_i = RollingHash(W_i)
```

如果：

```text
(h_i & ANCHOR_MASK) == ANCHOR_PATTERN
```

则当前位置 `i` 是一个 anchor candidate。

注意：

```text
anchor candidate 是否成立，只取决于 W_i 的内容；
不能依赖 i；
不能依赖前面已经扫描了多少字节；
不能依赖上一个 region 的序号；
不能依赖全局 offset。
```

rolling hash 在实现上可以利用前一个 hash 值快速更新，但从语义上必须等价于“当前窗口内容的 hash”。

### 3.2 region keystream 不受 region 位置影响

这是最重要的要求。

禁止这样做：

```text
region_salt = HMAC(K_salt, anchor_tag || region_index)
region_salt = HMAC(K_salt, anchor_tag || chunk_offset)
region_salt = HMAC(K_salt, anchor_tag || global_block_id)
mask_i = AES(K_mask, chunk_global_block_index)
```

正确做法：

```text
anchor_tag = HMAC(K_anchor, anchor_window)
region_salt = HMAC(K_salt, anchor_tag)
mask_j = AES_or_PRF(K_mask, region_salt || local_counter_j)
```

其中：

```text
local_counter_j = region 内部的局部 block 编号，从 0 开始。
```

`local_counter_j` 是必要的，因为同一个 region 内不同 block 需要不同 mask。  
但是它不是全局位置，也不是 region 位置，只是 region 内部从 0 开始的局部编号。

---

## 4. 数据结构设计

可以根据项目语言进行调整，下面用通用结构表示。

### 4.1 Anchor

```text
struct Anchor {
    anchor_start: usize,   // anchor window 起始位置，包含
    anchor_end: usize,     // anchor window 结束位置，包含
    boundary: usize,       // 切分边界，等于 anchor_end + 1
    anchor_tag: bytes,     // HMAC(K_anchor, anchor_window)
}
```

### 4.2 Region

```text
struct Region {
    start: usize,          // region 在明文 chunk 中的起始位置，包含
    end: usize,            // region 在明文 chunk 中的结束位置，不包含
    left_anchor_tag: bytes,
    region_salt: bytes,
}
```

### 4.3 Recipe / Metadata

解密时客户端无法从密文重新计算 anchor，所以必须保存 region 边界信息。

由于 region 密文与明文等长，recipe 只需要保存内部边界：

```text
struct ChunkRecipe {
    original_chunk_len: usize,
    internal_boundaries: Vec<uint16>,
}
```

`region_salt` 不需要写入 recipe。解密 region0 后，客户端已经恢复了第一个 anchor
window，可以从该窗口顺序派生下一个 region 的 salt。

边界使用两种格式中较短的一种：

```text
SPARSE: boundary_count || uint16_be boundaries[]
BITMAP: chunk 内每个可能 boundary 占 1 bit
```

recipe 使用 `K_meta` 和 AES-256-GCM 认证加密，并放入对应密文对象的 envelope：

```text
AATEEnvelope = header || encrypted_recipe || region_ciphertext
```

为保持相同输入产生相同 envelope，GCM nonce 确定性地派生自
`original_chunk_len || serialized_recipe`。这相当于原型中的 synthetic nonce：不同
recipe 获得不同 nonce，相同 recipe 获得相同密文。生产版本应进一步使用标准
misuse-resistant deterministic AEAD（如 AES-GCM-SIV 或 AES-SIV）。

---

## 5. 密钥派生

输入：

```text
S: key server 返回、在相似 chunk 组内严格一致的 similarity seed
```

生成 chunk 主密钥：

```text
K = HKDF-SHA256(S, info = "AATE-v1-master")
```

从 `K` 派生子密钥：

```text
K_anchor = HMAC(K, "AATE-anchor")
K_salt   = HMAC(K, "AATE-salt")
K_mask   = HMAC(K, "AATE-mask")
K_perm   = HMAC(K, "AATE-perm")
K_meta   = HMAC(K, "AATE-meta")
K_nonce  = HMAC(K, "AATE-meta-nonce")
K_tail   = HMAC(K, "AATE-tail")
```

说明：

- `K_anchor`：用于生成 anchor_tag。
- `K_salt`：用于生成 region_salt。
- `K_mask`：用于第一阶段 mask stream。
- `K_perm`：用于第二阶段确定性 block 加密。
- `K_meta`：用于加密 recipe/metadata。
- `K_nonce`：用于从 recipe 确定性派生 metadata nonce。
- `K_tail`：用于处理不足 16B 的 region 尾部。

这里最重要的约束是：只要两个 chunk 被 key server 分入同一相似组，它们得到的 `S`
就必须逐字节相同。不得再混入 chunk offset、chunk 前 32B 或其他会因插入/删除变化的
采样值。

---

## 6. Anchor 生成逻辑

### 6.1 参数

第一版建议参数：

```text
WINDOW_SIZE = 48 
ANCHOR_MASK = 0x3FF       // 平均约 1024B 一个 anchor
ANCHOR_PATTERN = 0
```

如果想要更多 anchor，可以使用：

```text
ANCHOR_MASK = 0x1FF       // 平均约 512B 一个 anchor
```

第一版不使用 `min_region_size` 和 `max_region_size`。

### 6.2 伪代码

```text
function find_anchors(chunk, K_anchor):
    anchors = []

    if len(chunk) < WINDOW_SIZE:
        return anchors

    rolling = RollingHash.init(chunk[0 : WINDOW_SIZE])

    for i from WINDOW_SIZE - 1 to len(chunk) - 1:
        if i == WINDOW_SIZE - 1:
            h = RollingHash.hash(chunk[0 : WINDOW_SIZE])
        else:
            h = RollingHash.roll(
                old_byte = chunk[i - WINDOW_SIZE],
                new_byte = chunk[i]
            )

        if (h & ANCHOR_MASK) == ANCHOR_PATTERN:
            anchor_start = i - WINDOW_SIZE + 1
            anchor_end = i
            boundary = i + 1

            anchor_window = chunk[anchor_start : anchor_end + 1]
            anchor_tag = HMAC(K_anchor, anchor_window)

            anchors.push(Anchor {
                anchor_start,
                anchor_end,
                boundary,
                anchor_tag
            })

    return anchors
```

### 6.3 注意

如果使用 Gear hash，需要保证实现语义上等价于“当前窗口内容决定 hash”。  
不要使用会长期依赖整个前缀内容的 hash 作为 anchor 判断依据。

推荐第一版直接实现 Rabin rolling hash 或一个明确的固定窗口 rolling hash，避免歧义。

---

## 7. Region 切分逻辑

### 7.1 切分原则

当窗口 `[anchor_start, anchor_end]` 满足 anchor 条件时：

```text
boundary = anchor_end + 1
```

也就是：

```text
... [anchor window] | [new region starts here]
```

推荐采用：

```text
anchor 后切分
```

原因：anchor 作为同步点，anchor 后面的内容使用新的局部 counter，从而实现偏移后的重新对齐。

### 7.2 region 定义

假设 anchor boundaries 为：

```text
b1, b2, b3, ...
```

其中：

```text
b_i = anchor_i.anchor_end + 1
```

则 region 为：

```text
region0 = chunk[0  : b1]
region1 = chunk[b1 : b2]
region2 = chunk[b2 : b3]
...
regionN = chunk[bN : chunk_len]
```

每个 region 使用左侧 anchor 派生 salt：

```text
region0 使用特殊 START anchor
region1 使用 anchor1
region2 使用 anchor2
region3 使用 anchor3
```

### 7.3 START anchor

chunk 开头到第一个 anchor 后边界之前的 region 没有左侧 anchor。

定义特殊 anchor：

```text
START_ANCHOR_TAG = HMAC(K_anchor, "AATE-CHUNK-START")
```

region0 的 salt：

```text
region0_salt = HMAC(K_salt, START_ANCHOR_TAG)
```

这部分不具备 anchor 后重新对齐能力，但第一个稳定 anchor 之后的 region 可以重新对齐。

### 7.4 伪代码

```text
function build_regions(chunk, anchors, K_salt, K_anchor):
    regions = []

    prev_boundary = 0
    prev_anchor_tag = HMAC(K_anchor, "AATE-CHUNK-START")

    for anchor in anchors:
        boundary = anchor.boundary

        if boundary <= prev_boundary:
            continue

        region_salt = HMAC(K_salt, prev_anchor_tag)

        regions.push(Region {
            start = prev_boundary,
            end = boundary,
            left_anchor_tag = prev_anchor_tag,
            region_salt = region_salt
        })

        prev_boundary = boundary
        prev_anchor_tag = anchor.anchor_tag

    if prev_boundary < len(chunk):
        region_salt = HMAC(K_salt, prev_anchor_tag)

        regions.push(Region {
            start = prev_boundary,
            end = len(chunk),
            left_anchor_tag = prev_anchor_tag,
            region_salt = region_salt
        })

    return regions
```

---

## 8. Region 加密逻辑

### 8.1 目标

对每个 region 独立加密。  
region 内部 counter 从 0 开始。  
不同 region 的 keystream 由不同 `region_salt` 决定。

### 8.2 加密单位

第一版建议使用 16B AES block 作为内部加密单位。

由于 region 边界由 anchor 决定，不保证 16B 对齐。第一版采用 length-preserving
处理，要求：

```text
len(region_cipher) == len(region_plain)
```

region 中每个完整 16B block 继续执行 mask + AES permutation。最后不足 16B 的 tail
不 padding，使用与完整 block 域隔离的两个 keystream 做等长 XOR：

```text
tail_mask = AES(K_mask, PRF(region_salt, "tail-mask" || local_counter))
tail_perm = HMAC(K_tail, region_salt || "tail-perm" || local_counter)
tail_cipher = tail_plain XOR tail_mask[0:tail_len] XOR tail_perm[0:tail_len]
```

解密执行相同 XOR。该 tail 是第一版工程折中；它保持同步与等长性质，但安全性质不等同
于完整 block 上的 AES permutation，后续可替换为经过审查的 ciphertext-stealing 或
其他确定性、misuse-resistant 的 length-preserving 构造。

### 8.3 两阶段加密

对 region 内第 `j` 个 16B block：

```text
mask_j = AES_encrypt(K_mask, region_salt || local_counter_j)

x_j = plain_block_j XOR mask_j

cipher_block_j = AES_encrypt(K_perm, x_j)
```

注意：

```text
local_counter_j 从 0 开始；
不能使用 chunk 内全局 block 编号；
不能使用 region index；
不能使用 region 在 chunk 中的偏移。
```

### 8.4 region 加密伪代码

```text
function encrypt_region(region_plain, region_salt, K_mask, K_perm, K_tail):
    cipher = empty bytes

    full_block_count = len(region_plain) / 16

    for j from 0 to full_block_count - 1:
        plain_block = region_plain[j*16 : (j+1)*16]

        counter_block = encode_128(region_salt, j)
        mask_block = AES_encrypt(K_mask, counter_block)

        x_block = xor(plain_block, mask_block)

        cipher_block = AES_encrypt(K_perm, x_block)

        cipher.append(cipher_block)

    tail = region_plain[full_block_count*16 :]
    if len(tail) != 0:
        j = full_block_count
        tail_mask = make_tail_mask(K_mask, region_salt, j)
        tail_perm = HMAC(K_tail, region_salt || "tail-perm" || uint64_be(j))
        cipher.append(tail XOR tail_mask[0:len(tail)] XOR tail_perm[0:len(tail)])

    return cipher
```

### 8.5 `encode_128(region_salt, j)`

AES input block 是 16B。  
可以把 `region_salt` 截断或扩展成 nonce，然后拼接局部 counter。

示例：

```text
region_nonce = first_12_bytes(region_salt)
counter = uint32_be(j)
counter_block = region_nonce || counter
```

或者：

```text
counter_block = first_16_bytes(HMAC(region_salt, uint64_be(j)))
```

推荐第一版使用：

```text
counter_block = first_16_bytes(HMAC(region_salt, "mask-counter" || uint64_be(j)))
mask_block = AES_encrypt(K_mask, counter_block)
```

这样不用担心 nonce 长度组织问题。

---

## 9. Chunk 加密流程

```text
function encrypt_chunk(chunk, S):
    K = HKDF-SHA256(S, info = "AATE-v1-master")

    K_anchor = HMAC(K, "AATE-anchor")
    K_salt   = HMAC(K, "AATE-salt")
    K_mask   = HMAC(K, "AATE-mask")
    K_perm   = HMAC(K, "AATE-perm")
    K_meta   = HMAC(K, "AATE-meta")

    anchors = find_anchors(chunk, K_anchor)

    regions = build_regions(chunk, anchors, K_salt, K_anchor)

    encrypted_chunk = empty bytes
    internal_boundaries = []

    for region in regions:
        region_plain = chunk[region.start : region.end]

        region_cipher = encrypt_region(
            region_plain,
            region.region_salt,
            K_mask,
            K_perm
        )

        encrypted_chunk.append(region_cipher)

        assert len(region_cipher) == len(region_plain)
        if region.end < len(chunk):
            internal_boundaries.push(region.end)

    recipe = ChunkRecipe {
        original_chunk_len = len(chunk),
        internal_boundaries = internal_boundaries
    }

    encrypted_recipe = authenticated_encrypt_recipe(recipe, K_meta, K_nonce)

    return build_envelope(encrypted_recipe, encrypted_chunk)
```

recipe 不允许以明文形式进入 envelope。加密失败时整个 chunk 加密必须失败，不能静默
回退到明文 metadata。

---

## 10. 解密流程

```text
function decrypt_chunk(envelope, S):
    K = HKDF-SHA256(S, info = "AATE-v1-master")

    K_anchor = HMAC(K, "AATE-anchor")
    K_salt   = HMAC(K, "AATE-salt")
    K_mask   = HMAC(K, "AATE-mask")
    K_perm   = HMAC(K, "AATE-perm")
    K_meta   = HMAC(K, "AATE-meta")
    K_nonce  = HMAC(K, "AATE-meta-nonce")
    K_tail   = HMAC(K, "AATE-tail")

    encrypted_recipe, encrypted_chunk = parse_and_validate_envelope(envelope)
    recipe = authenticated_decrypt_recipe(encrypted_recipe, K_meta, K_nonce)

    plain_chunk = bytearray(recipe.original_chunk_len)

    boundaries = recipe.internal_boundaries || [recipe.original_chunk_len]
    prev_boundary = 0
    prev_anchor_tag = HMAC(K_anchor, "AATE-CHUNK-START")

    for boundary in boundaries:
        region_salt = HMAC(K_salt, prev_anchor_tag)
        region_cipher = encrypted_chunk[prev_boundary : boundary]

        region_plain = decrypt_region(
            region_cipher,
            region_salt,
            K_mask,
            K_perm,
            K_tail
        )

        plain_chunk[prev_boundary : boundary] = region_plain

        if boundary < recipe.original_chunk_len:
            anchor_window = plain_chunk[boundary-WINDOW_SIZE : boundary]
            prev_anchor_tag = HMAC(K_anchor, anchor_window)
        prev_boundary = boundary

    return plain_chunk
```

### 10.1 region 解密

```text
function decrypt_region(region_cipher, region_salt, K_mask, K_perm, K_tail):
    plain = empty bytes

    full_block_count = len(region_cipher) / 16

    for j from 0 to full_block_count - 1:
        cipher_block = region_cipher[j*16 : (j+1)*16]

        x_block = AES_decrypt(K_perm, cipher_block)

        counter_block = first_16_bytes(
            HMAC(region_salt, "mask-counter" || uint64_be(j))
        )

        mask_block = AES_encrypt(K_mask, counter_block)

        plain_block = xor(x_block, mask_block)

        plain.append(plain_block)

    tail = region_cipher[full_block_count*16 :]
    if len(tail) != 0:
        j = full_block_count
        tail_mask = make_tail_mask(K_mask, region_salt, j)
        tail_perm = HMAC(K_tail, region_salt || "tail-perm" || uint64_be(j))
        plain.append(tail XOR tail_mask[0:len(tail)] XOR tail_perm[0:len(tail)])

    return plain
```

---

## 11. 正确性测试

### 11.1 加密解密一致性测试

输入随机 chunk：

```text
chunk = random bytes, size = 8KB
```

执行：

```text
envelope = encrypt_chunk(chunk, S)
recovered = decrypt_chunk(envelope, S)
```

断言：

```text
recovered == chunk
```

### 11.2 anchor 只依赖当前窗口测试

构造两个 chunk：

```text
chunk_a = prefix_a || W || suffix
chunk_b = prefix_b || W || suffix
```

其中 `prefix_a` 和 `prefix_b` 长度不同，但窗口 `W` 完全相同。

如果 `W` 满足 anchor 条件，则断言：

```text
W 在两个 chunk 中都被识别为 anchor candidate
anchor_tag 相同
```

### 11.3 region keystream 不依赖 region 位置测试

构造：

```text
chunk_a = H || R
chunk_b = X || H || R
```

其中：

```text
H 是满足 anchor 条件的 anchor window
R 是相同后续内容
X 是插入内容
```

要求：

```text
H 后面的 region_salt 在 chunk_a 和 chunk_b 中相同
H 后面 region 内相同明文 block 的 ciphertext block 相同
```

注意：由于 chunk_b 前面多了 X，H 在两个 chunk 中的全局位置不同。  
如果密文仍然相同，说明 keystream 没有依赖全局位置。

### 11.4 禁止 region_index 影响测试

构造：

```text
chunk_a = H1 || R
chunk_b = H0 || X || H1 || R
```

其中 `H1` 后面的 `R` 相同，但 `H1` 在 chunk_b 中变成了更靠后的 region。

要求：

```text
salt_after_H1(chunk_a) == salt_after_H1(chunk_b)
cipher_after_H1(chunk_a) == cipher_after_H1(chunk_b)
```

如果失败，说明实现中错误地引入了 region index 或全局 offset。

---

## 12. 输出用于 delta compression 的密文

云端保存完整 `AATEEnvelope`，但只需把它当作不透明字节串做：

```text
deduplication
resemblance detection
delta compression
```

云端不需要解析：

```text
anchor
region_salt
region boundaries
plaintext length
```

recipe 已由 `K_meta` 认证加密。envelope header 会暴露版本、总长度和 metadata 长度，
但不会暴露具体边界。delta compression 可以跳过不同的 metadata 前缀并继续匹配后面的
region ciphertext；相同 chunk、相同 `S` 必须产生完全相同的 deterministic envelope，
以免破坏现有 deduplication。

客户端计算 ciphertext resemblance feature 时只对 envelope 中的 region ciphertext
payload 计算，不把 header 和 encrypted recipe 纳入 Finesse 特征；服务端存储和 delta
编码时仍保存完整 envelope。

---

## 13. 第一版验收标准

Codex 实现完成后，至少需要满足：

1. 可以输入一个 bytes chunk，输出包含认证加密 recipe 的 AATE envelope。
2. 可以根据 envelope 和 similarity seed 恢复原始 chunk。
3. anchor candidate 判断只依赖当前窗口内容。
4. region 边界在 anchor window 后。
5. region_salt 只由 left_anchor_tag 派生。
6. region_salt 不包含：
   - region_index；
   - chunk offset；
   - global block index；
   - file offset。
7. region 内 block mask 使用 local counter，从 0 开始。
8. 对前插入数据的 chunk，anchor 后相同 region 能产生相同密文 block。
9. 第一版不使用 min_region_size 和 max_region_size。
10. 每个 region 的密文长度严格等于明文长度，chunk payload 不产生 padding。
11. metadata 被篡改、边界非法或 envelope 截断时，解密必须失败。
12. 相同 chunk 和相同 similarity seed 产生完全相同的 envelope。

### 13.1 格式兼容性说明

AATE envelope 和旧版 `CTR + ECB` 密文格式不兼容，同时 key recipe 的 32B 字段从
“chunk 前 32B 与 key seed 的哈希”改为直接保存相似组 seed。第一版不提供旧密文自动
迁移；测试或部署时需要使用新客户端重新上传数据。若后续需要滚动升级，应保留旧格式
解密器，并通过 envelope magic/version 分派。

---

## 14. 最重要的实现提醒

请在代码中避免以下错误：

```text
错误 1：region_salt = HMAC(K_salt, anchor_tag || region_index)

错误 2：region_salt = HMAC(K_salt, anchor_tag || region.start)

错误 3：mask = AES(K_mask, global_block_id)

错误 4：anchor 判断依赖 chunk offset 或 region offset

错误 5：切分边界放在 anchor 前，导致 anchor 后内容不能稳定重新对齐

错误 6：解密时试图从密文重新找 anchor
```

正确核心公式是：

```text
anchor_tag = HMAC(K_anchor, anchor_window)

region_salt = HMAC(K_salt, left_anchor_tag)

counter_block_j = PRF(region_salt, local_counter_j)

mask_j = AES_encrypt(K_mask, counter_block_j)

x_j = plain_block_j XOR mask_j

cipher_block_j = AES_encrypt(K_perm, x_j)
```

其中：

```text
local_counter_j 只表示 region 内部第几个 block。
```

---

## 15. 一句话目标总结

本方案第一版要实现的是：

> 基于内容 anchor 的 region-level 重新同步加密。anchor 的识别只依赖当前窗口内容；region 的 keystream 只依赖左侧 anchor 内容和 region 内局部 counter，不依赖 region 序号、chunk 偏移或全局 block 位置。这样可以在发生插入/删除造成偏移后，让 anchor 后面的相同内容仍然生成相同密文片段，从而提升云端密文增量压缩效果。
