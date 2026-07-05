/**
 * @file two_phase_enc.cc
 * @brief Anchor-Aligned Two-Phase Encryption (AATE) implementation.
 */

#include "../../include/client/two_phase_enc.h"

#include <algorithm>
#include <cstring>
#include <limits>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace {

constexpr uint8_t kMagic[4] = {'A', 'A', 'T', 'E'};
constexpr uint8_t kSparseRecipe = 0;
constexpr uint8_t kBitmapRecipe = 1;

void PutU16(uint8_t* out, uint16_t value) {
    out[0] = static_cast<uint8_t>(value >> 8);
    out[1] = static_cast<uint8_t>(value);
}

uint16_t GetU16(const uint8_t* in) {
    return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
}

void PutU32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>(value >> 24);
    out[1] = static_cast<uint8_t>(value >> 16);
    out[2] = static_cast<uint8_t>(value >> 8);
    out[3] = static_cast<uint8_t>(value);
}

uint32_t GetU32(const uint8_t* in) {
    return (static_cast<uint32_t>(in[0]) << 24) |
        (static_cast<uint32_t>(in[1]) << 16) |
        (static_cast<uint32_t>(in[2]) << 8) |
        static_cast<uint32_t>(in[3]);
}

void PutU64(uint8_t* out, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value);
        value >>= 8;
    }
}

bool HmacSha256(const uint8_t* key, size_t key_size, const uint8_t* data,
    size_t data_size, uint8_t out[32]) {
    unsigned int out_size = 0;
    return HMAC(EVP_sha256(), key, static_cast<int>(key_size), data, data_size,
        out, &out_size) != nullptr && out_size == 32;
}

bool HmacLabel(const uint8_t key[32], const char* label, uint8_t out[32]) {
    return HmacSha256(key, 32, reinterpret_cast<const uint8_t*>(label),
        std::strlen(label), out);
}

bool InitEcb(EVP_CIPHER_CTX* ctx, const uint8_t key[32], bool encrypt) {
    const int ok = encrypt
        ? EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr)
        : EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr);
    return ok == 1 && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
}

bool CryptBlock(EVP_CIPHER_CTX* ctx, const uint8_t in[16], uint8_t out[16],
    bool encrypt) {
    int out_size = 0;
    const int ok = encrypt
        ? EVP_EncryptUpdate(ctx, out, &out_size, in, 16)
        : EVP_DecryptUpdate(ctx, out, &out_size, in, 16);
    return ok == 1 && out_size == 16;
}

bool MakeCounterInput(const uint8_t region_salt[32], const char* label,
    uint64_t counter, uint8_t out[16]) {
    const size_t label_size = std::strlen(label);
    std::vector<uint8_t> input(label_size + 8);
    std::memcpy(input.data(), label, label_size);
    PutU64(input.data() + label_size, counter);
    uint8_t digest[32];
    if (!HmacSha256(region_salt, 32, input.data(), input.size(), digest)) {
        return false;
    }
    std::memcpy(out, digest, 16);
    OPENSSL_cleanse(digest, sizeof(digest));
    return true;
}

} // namespace

TwoPhaseEnc::TwoPhaseEnc() {
    rabin_util_ = new RabinFPUtil(AATE_WINDOW_SIZE);
}

TwoPhaseEnc::~TwoPhaseEnc() {
    delete rabin_util_;
}

bool TwoPhaseEnc::GetPayloadRange(const uint8_t* envelope, uint32_t envelope_size,
    uint32_t& payload_offset, uint32_t& payload_size) {
    if (envelope == nullptr || envelope_size < AATE_HEADER_SIZE ||
        std::memcmp(envelope, kMagic, sizeof(kMagic)) != 0 ||
        envelope[4] != AATE_VERSION) {
        return false;
    }
    payload_size = GetU32(envelope + 5);
    const uint32_t recipe_size = GetU32(envelope + 9);
    payload_offset = AATE_HEADER_SIZE + recipe_size;
    return payload_size != 0 && payload_size <= AATE_MAX_PLAIN_SIZE &&
        recipe_size != 0 && recipe_size <= AATE_MAX_RECIPE_SIZE &&
        payload_offset <= envelope_size &&
        envelope_size - payload_offset == payload_size;
}

bool TwoPhaseEnc::DeriveSubKeys(const uint8_t* similarity_seed,
    SubKeys& keys) const {
    uint8_t zero_salt[32] = {0};
    uint8_t prk[32];
    if (!HmacSha256(zero_salt, sizeof(zero_salt), similarity_seed,
        CHUNK_HASH_SIZE, prk)) {
        return false;
    }

    static constexpr char kInfo[] = "AATE-v1-master";
    uint8_t expand_input[sizeof(kInfo)];
    std::memcpy(expand_input, kInfo, sizeof(kInfo) - 1);
    expand_input[sizeof(kInfo) - 1] = 1;
    uint8_t master[32];
    if (!HmacSha256(prk, sizeof(prk), expand_input, sizeof(expand_input), master)) {
        OPENSSL_cleanse(prk, sizeof(prk));
        return false;
    }

    const bool ok = HmacLabel(master, "AATE-anchor", keys.anchor.data()) &&
        HmacLabel(master, "AATE-salt", keys.salt.data()) &&
        HmacLabel(master, "AATE-mask", keys.mask.data()) &&
        HmacLabel(master, "AATE-perm", keys.perm.data()) &&
        HmacLabel(master, "AATE-meta", keys.meta.data()) &&
        HmacLabel(master, "AATE-meta-nonce", keys.nonce.data()) &&
        HmacLabel(master, "AATE-tail", keys.tail.data());
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(master, sizeof(master));
    return ok;
}

bool TwoPhaseEnc::FindBoundaries(const uint8_t* data, uint32_t size,
    std::vector<uint16_t>& boundaries) const {
    boundaries.clear();
    if (size < AATE_WINDOW_SIZE) {
        return true;
    }

    RabinCtx_t ctx;
    rabin_util_->NewCtx(ctx);
    for (uint32_t i = 0; i < size; ++i) {
        const uint64_t fp = rabin_util_->SlideOneByte(ctx, data[i]);
        const uint32_t boundary = i + 1;
        if (boundary >= AATE_WINDOW_SIZE && boundary < size &&
            (fp & AATE_ANCHOR_MASK) == 0) {
            boundaries.push_back(static_cast<uint16_t>(boundary));
        }
    }
    rabin_util_->FreeCtx(ctx);
    return true;
}

bool TwoPhaseEnc::SerializeRecipe(uint32_t size,
    const std::vector<uint16_t>& boundaries, std::vector<uint8_t>& recipe) const {
    if (boundaries.size() > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    const size_t sparse_size = 3 + boundaries.size() * sizeof(uint16_t);
    const size_t bitmap_size = 1 + (size + 7) / 8;
    if (sparse_size <= bitmap_size) {
        recipe.assign(sparse_size, 0);
        recipe[0] = kSparseRecipe;
        PutU16(recipe.data() + 1, static_cast<uint16_t>(boundaries.size()));
        for (size_t i = 0; i < boundaries.size(); ++i) {
            PutU16(recipe.data() + 3 + i * 2, boundaries[i]);
        }
    } else {
        recipe.assign(bitmap_size, 0);
        recipe[0] = kBitmapRecipe;
        for (uint16_t boundary : boundaries) {
            recipe[1 + boundary / 8] |= static_cast<uint8_t>(1U << (boundary % 8));
        }
    }
    return true;
}

bool TwoPhaseEnc::DeserializeRecipe(uint32_t size, const uint8_t* recipe,
    uint32_t recipe_size, std::vector<uint16_t>& boundaries) const {
    boundaries.clear();
    if (recipe_size == 0) {
        return false;
    }
    if (recipe[0] == kSparseRecipe) {
        if (recipe_size < 3) {
            return false;
        }
        const uint16_t count = GetU16(recipe + 1);
        if (recipe_size != 3U + static_cast<uint32_t>(count) * 2U) {
            return false;
        }
        uint16_t previous = 0;
        for (uint32_t i = 0; i < count; ++i) {
            const uint16_t boundary = GetU16(recipe + 3 + i * 2);
            if (boundary < AATE_WINDOW_SIZE || boundary >= size ||
                boundary <= previous) {
                return false;
            }
            boundaries.push_back(boundary);
            previous = boundary;
        }
        return true;
    }
    if (recipe[0] != kBitmapRecipe || recipe_size != 1U + (size + 7U) / 8U) {
        return false;
    }
    if ((recipe[1] & 1U) != 0) {
        return false;
    }
    for (uint32_t boundary = 1; boundary < size; ++boundary) {
        if ((recipe[1 + boundary / 8] & (1U << (boundary % 8))) != 0) {
            if (boundary < AATE_WINDOW_SIZE) {
                return false;
            }
            boundaries.push_back(static_cast<uint16_t>(boundary));
        }
    }
    for (uint32_t boundary = size; boundary < ((size + 7U) / 8U) * 8U;
        ++boundary) {
        if ((recipe[1 + boundary / 8] & (1U << (boundary % 8))) != 0) {
            return false;
        }
    }
    return true;
}

bool TwoPhaseEnc::CryptPayload(const uint8_t* input, uint32_t size,
    const std::vector<uint16_t>& boundaries, const SubKeys& keys, bool encrypt,
    uint8_t* output) const {
    EVP_CIPHER_CTX* mask_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* perm_ctx = EVP_CIPHER_CTX_new();
    if (mask_ctx == nullptr || perm_ctx == nullptr ||
        !InitEcb(mask_ctx, keys.mask.data(), true) ||
        !InitEcb(perm_ctx, keys.perm.data(), encrypt)) {
        EVP_CIPHER_CTX_free(mask_ctx);
        EVP_CIPHER_CTX_free(perm_ctx);
        return false;
    }

    uint8_t anchor_tag[32];
    static constexpr char kStart[] = "AATE-CHUNK-START";
    if (!HmacSha256(keys.anchor.data(), keys.anchor.size(),
        reinterpret_cast<const uint8_t*>(kStart), sizeof(kStart) - 1,
        anchor_tag)) {
        EVP_CIPHER_CTX_free(mask_ctx);
        EVP_CIPHER_CTX_free(perm_ctx);
        return false;
    }

    std::vector<uint32_t> ends(boundaries.begin(), boundaries.end());
    ends.push_back(size);
    uint32_t start = 0;
    bool ok = true;
    for (uint32_t end : ends) {
        if (end <= start || end > size) {
            ok = false;
            break;
        }
        uint8_t region_salt[32];
        if (!HmacSha256(keys.salt.data(), keys.salt.size(), anchor_tag,
            sizeof(anchor_tag), region_salt)) {
            ok = false;
            break;
        }

        const uint32_t region_size = end - start;
        const uint32_t full_blocks = region_size / 16;
        for (uint32_t j = 0; j < full_blocks && ok; ++j) {
            uint8_t counter_input[16];
            uint8_t mask[16];
            uint8_t intermediate[16];
            if (!MakeCounterInput(region_salt, "mask-counter", j, counter_input) ||
                !CryptBlock(mask_ctx, counter_input, mask, true)) {
                ok = false;
                break;
            }
            if (encrypt) {
                for (uint32_t k = 0; k < 16; ++k) {
                    intermediate[k] = input[start + j * 16 + k] ^ mask[k];
                }
                ok = CryptBlock(perm_ctx, intermediate,
                    output + start + j * 16, true);
            } else {
                ok = CryptBlock(perm_ctx, input + start + j * 16,
                    intermediate, false);
                for (uint32_t k = 0; k < 16 && ok; ++k) {
                    output[start + j * 16 + k] = intermediate[k] ^ mask[k];
                }
            }
        }

        const uint32_t tail_size = region_size % 16;
        if (ok && tail_size != 0) {
            const uint32_t j = full_blocks;
            uint8_t counter_input[16];
            uint8_t tail_mask[16];
            if (!MakeCounterInput(region_salt, "tail-mask", j, counter_input) ||
                !CryptBlock(mask_ctx, counter_input, tail_mask, true)) {
                ok = false;
            } else {
                static constexpr char kTailLabel[] = "tail-perm";
                uint8_t tail_input[32 + sizeof(kTailLabel) - 1 + 8];
                std::memcpy(tail_input, region_salt, 32);
                std::memcpy(tail_input + 32, kTailLabel,
                    sizeof(kTailLabel) - 1);
                PutU64(tail_input + 32 + sizeof(kTailLabel) - 1, j);
                uint8_t tail_perm[32];
                ok = HmacSha256(keys.tail.data(), keys.tail.size(), tail_input,
                    sizeof(tail_input), tail_perm);
                const uint32_t tail_offset = start + full_blocks * 16;
                for (uint32_t k = 0; k < tail_size && ok; ++k) {
                    output[tail_offset + k] = input[tail_offset + k] ^
                        tail_mask[k] ^ tail_perm[k];
                }
                OPENSSL_cleanse(tail_perm, sizeof(tail_perm));
            }
        }

        if (ok && end < size) {
            const uint8_t* recovered = encrypt ? input : output;
            ok = HmacSha256(keys.anchor.data(), keys.anchor.size(),
                recovered + end - AATE_WINDOW_SIZE, AATE_WINDOW_SIZE,
                anchor_tag);
        }
        OPENSSL_cleanse(region_salt, sizeof(region_salt));
        if (!ok) {
            break;
        }
        start = end;
    }

    OPENSSL_cleanse(anchor_tag, sizeof(anchor_tag));
    EVP_CIPHER_CTX_free(mask_ctx);
    EVP_CIPHER_CTX_free(perm_ctx);
    return ok;
}

bool TwoPhaseEnc::EncryptRecipe(const uint8_t* recipe, uint32_t recipe_size,
    uint32_t original_size, const SubKeys& keys, const uint8_t* aad,
    uint32_t aad_size, uint8_t* nonce, uint8_t* cipher, uint8_t* tag) const {
    std::vector<uint8_t> nonce_input(4 + recipe_size);
    PutU32(nonce_input.data(), original_size);
    std::memcpy(nonce_input.data() + 4, recipe, recipe_size);
    uint8_t nonce_digest[32];
    if (!HmacSha256(keys.nonce.data(), keys.nonce.size(), nonce_input.data(),
        nonce_input.size(), nonce_digest)) {
        return false;
    }
    std::memcpy(nonce, nonce_digest, AATE_NONCE_SIZE);
    OPENSSL_cleanse(nonce_digest, sizeof(nonce_digest));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int total = 0;
    const bool ok = ctx != nullptr &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AATE_NONCE_SIZE,
            nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, keys.meta.data(), nonce) == 1 &&
        EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_size) == 1 &&
        EVP_EncryptUpdate(ctx, cipher, &len, recipe, recipe_size) == 1;
    if (ok) {
        total = len;
    }
    const bool final_ok = ok && EVP_EncryptFinal_ex(ctx, cipher + total, &len) == 1 &&
        static_cast<uint32_t>(total + len) == recipe_size &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AATE_TAG_SIZE, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return final_ok;
}

bool TwoPhaseEnc::DecryptRecipe(const uint8_t* cipher, uint32_t cipher_size,
    const SubKeys& keys, const uint8_t* aad, uint32_t aad_size,
    const uint8_t* nonce, const uint8_t* tag, uint8_t* recipe) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int total = 0;
    bool ok = ctx != nullptr &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AATE_NONCE_SIZE,
            nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, keys.meta.data(), nonce) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_size) == 1 &&
        EVP_DecryptUpdate(ctx, recipe, &len, cipher, cipher_size) == 1;
    if (ok) {
        total = len;
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AATE_TAG_SIZE,
            const_cast<uint8_t*>(tag)) == 1 &&
            EVP_DecryptFinal_ex(ctx, recipe + total, &len) == 1 &&
            static_cast<uint32_t>(total + len) == cipher_size;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

uint32_t TwoPhaseEnc::TwoPhaseEncChunk(uint8_t* plain_chunk, uint32_t size,
    uint8_t* similarity_seed, uint8_t* enc_chunk) {
    if (plain_chunk == nullptr || similarity_seed == nullptr || enc_chunk == nullptr ||
        size == 0 || size > AATE_MAX_PLAIN_SIZE) {
        return 0;
    }
    SubKeys keys;
    std::vector<uint16_t> boundaries;
    std::vector<uint8_t> recipe;
    if (!DeriveSubKeys(similarity_seed, keys) ||
        !FindBoundaries(plain_chunk, size, boundaries) ||
        !SerializeRecipe(size, boundaries, recipe)) {
        return 0;
    }
    const uint32_t total_size = AATE_HEADER_SIZE + recipe.size() + size;
    if (total_size > ENC_MAX_CHUNK_SIZE) {
        return 0;
    }

    std::memcpy(enc_chunk, kMagic, sizeof(kMagic));
    enc_chunk[4] = AATE_VERSION;
    PutU32(enc_chunk + 5, size);
    PutU32(enc_chunk + 9, static_cast<uint32_t>(recipe.size()));
    uint8_t* nonce = enc_chunk + 13;
    uint8_t* tag = enc_chunk + 25;
    uint8_t* recipe_cipher = enc_chunk + AATE_HEADER_SIZE;
    uint8_t* payload = recipe_cipher + recipe.size();
    if (!EncryptRecipe(recipe.data(), recipe.size(), size, keys, enc_chunk, 13,
        nonce, recipe_cipher, tag) ||
        !CryptPayload(plain_chunk, size, boundaries, keys, true, payload)) {
        return 0;
    }
    return total_size;
}

uint32_t TwoPhaseEnc::TwoPhaseDecChunk(uint8_t* enc_chunk, uint32_t size,
    uint8_t* similarity_seed, uint8_t* plain_chunk) {
    if (enc_chunk == nullptr || similarity_seed == nullptr || plain_chunk == nullptr ||
        size < AATE_HEADER_SIZE || std::memcmp(enc_chunk, kMagic, sizeof(kMagic)) != 0 ||
        enc_chunk[4] != AATE_VERSION) {
        return 0;
    }
    uint32_t payload_offset = 0;
    uint32_t original_size = 0;
    if (!GetPayloadRange(enc_chunk, size, payload_offset, original_size)) {
        return 0;
    }
    const uint32_t recipe_size = GetU32(enc_chunk + 9);

    SubKeys keys;
    if (!DeriveSubKeys(similarity_seed, keys)) {
        return 0;
    }
    const uint8_t* nonce = enc_chunk + 13;
    const uint8_t* tag = enc_chunk + 25;
    const uint8_t* recipe_cipher = enc_chunk + AATE_HEADER_SIZE;
    const uint8_t* payload = enc_chunk + payload_offset;
    std::vector<uint8_t> recipe(recipe_size);
    std::vector<uint16_t> boundaries;
    if (!DecryptRecipe(recipe_cipher, recipe_size, keys, enc_chunk, 13, nonce,
        tag, recipe.data()) ||
        !DeserializeRecipe(original_size, recipe.data(), recipe_size, boundaries) ||
        !CryptPayload(payload, original_size, boundaries, keys, false, plain_chunk)) {
        OPENSSL_cleanse(plain_chunk, original_size);
        return 0;
    }
    return original_size;
}
