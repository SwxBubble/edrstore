/**
 * @file two_phase_enc.h
 * @brief Anchor-Aligned Two-Phase Encryption (AATE).
 */

#ifndef EDRSTORE_TWO_PHASE_ENC_H
#define EDRSTORE_TWO_PHASE_ENC_H

#include "../const_var.h"
#include "../chunker/rabin_poly.h"

#include <array>
#include <cstdint>
#include <vector>

struct AATEStats {
    uint64_t chunk_count = 0;
    uint64_t global_chunk_count = 0;
    uint64_t anchor_chunk_count = 0;
    uint64_t total_anchor_candidates = 0;
    uint64_t accepted_anchor_count = 0;
    uint64_t suppressed_anchor_count = 0;
    uint64_t identical_window_reject_count = 0;
    uint64_t region_count = 0;
    uint64_t min_region_size_observed = 0;
    uint64_t max_region_size_observed = 0;
    uint64_t metadata_bytes = 0;
    uint64_t payload_bytes = 0;
    double anchor_scan_time = 0;
    double key_derivation_time = 0;
    double payload_encrypt_time = 0;
    double metadata_encrypt_time = 0;
};

enum class TwoPhaseEncMode : uint8_t {
    GLOBAL = 0,
    ANCHOR_ALIGNED = 1,
};

class TwoPhaseEnc {
    private:
        static constexpr uint32_t AATE_WINDOW_SIZE = 48;
        static constexpr uint64_t AATE_ANCHOR_MASK = 0x1ff;
        static constexpr uint64_t AATE_ANCHOR_PATTERN = 0x0a5;
        static constexpr uint8_t AATE_VERSION = 1;
        static constexpr uint32_t AATE_HEADER_SIZE = 41;
        static constexpr uint32_t AATE_NONCE_SIZE = 12;
        static constexpr uint32_t AATE_TAG_SIZE = 16;

        struct SubKeys {
            std::array<uint8_t, 32> anchor;
            std::array<uint8_t, 32> salt;
            std::array<uint8_t, 32> mask;
            std::array<uint8_t, 32> perm;
            std::array<uint8_t, 32> meta;
            std::array<uint8_t, 32> nonce;
            std::array<uint8_t, 32> tail;
        };

        RabinFPUtil* rabin_util_;
        std::vector<uint8_t> counter_buf_;
        std::vector<uint8_t> mask_buf_;
        std::vector<uint8_t> transform_buf_;
        AATEStats stats_;

        bool DeriveSubKeys(const uint8_t* similarity_seed, SubKeys& keys) const;
        bool FindBoundaries(const uint8_t* data, uint32_t size,
            std::vector<uint16_t>& boundaries);
        bool SerializeRecipe(uint32_t size, const std::vector<uint16_t>& boundaries,
            std::vector<uint8_t>& recipe) const;
        bool DeserializeRecipe(uint32_t size, const uint8_t* recipe,
            uint32_t recipe_size, std::vector<uint16_t>& boundaries) const;
        bool CryptPayload(const uint8_t* input, uint32_t size,
            const std::vector<uint16_t>& boundaries, const SubKeys& keys,
            bool encrypt, uint8_t* output);
        bool EncryptRecipe(const uint8_t* recipe, uint32_t recipe_size,
            uint32_t original_size, const SubKeys& keys, const uint8_t* aad,
            uint32_t aad_size, uint8_t* nonce, uint8_t* cipher,
            uint8_t* tag) const;
        bool DecryptRecipe(const uint8_t* cipher, uint32_t cipher_size,
            const SubKeys& keys, const uint8_t* aad, uint32_t aad_size,
            const uint8_t* nonce, const uint8_t* tag, uint8_t* recipe) const;
        uint32_t EncryptGlobal(uint8_t* plain_chunk, uint32_t size,
            uint8_t* similarity_seed, uint8_t* enc_chunk);
        uint32_t EncryptAnchorAligned(uint8_t* plain_chunk, uint32_t size,
            uint8_t* similarity_seed, uint8_t* enc_chunk);

    public:
        TwoPhaseEnc();
        ~TwoPhaseEnc();

        /** Locate the length-preserving region payload inside an envelope. */
        static bool GetPayloadRange(const uint8_t* envelope, uint32_t envelope_size,
            uint32_t& payload_offset, uint32_t& payload_size);

        const AATEStats& GetStats() const { return stats_; }

        /** Encrypt using GLOBAL mode, the storage-oriented default. */
        uint32_t TwoPhaseEncChunk(uint8_t* plain_chunk, uint32_t size,
            uint8_t* similarity_seed, uint8_t* enc_chunk);

        /** Encrypt with an explicit mode (used by selection logic and tests). */
        uint32_t TwoPhaseEncChunkWithMode(uint8_t* plain_chunk, uint32_t size,
            uint8_t* similarity_seed, uint8_t* enc_chunk,
            TwoPhaseEncMode mode);

        /** Auto-detect and decrypt a GLOBAL or anchor-aligned object. */
        uint32_t TwoPhaseDecChunk(uint8_t* enc_chunk, uint32_t size,
            uint8_t* similarity_seed, uint8_t* plain_chunk);
};

#endif
