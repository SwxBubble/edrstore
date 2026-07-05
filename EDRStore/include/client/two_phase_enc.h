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

class TwoPhaseEnc {
    private:
        static constexpr uint32_t AATE_WINDOW_SIZE = 48;
        static constexpr uint64_t AATE_ANCHOR_MASK = 0x3ff;
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

        bool DeriveSubKeys(const uint8_t* similarity_seed, SubKeys& keys) const;
        bool FindBoundaries(const uint8_t* data, uint32_t size,
            std::vector<uint16_t>& boundaries) const;
        bool SerializeRecipe(uint32_t size, const std::vector<uint16_t>& boundaries,
            std::vector<uint8_t>& recipe) const;
        bool DeserializeRecipe(uint32_t size, const uint8_t* recipe,
            uint32_t recipe_size, std::vector<uint16_t>& boundaries) const;
        bool CryptPayload(const uint8_t* input, uint32_t size,
            const std::vector<uint16_t>& boundaries, const SubKeys& keys,
            bool encrypt, uint8_t* output) const;
        bool EncryptRecipe(const uint8_t* recipe, uint32_t recipe_size,
            uint32_t original_size, const SubKeys& keys, const uint8_t* aad,
            uint32_t aad_size, uint8_t* nonce, uint8_t* cipher,
            uint8_t* tag) const;
        bool DecryptRecipe(const uint8_t* cipher, uint32_t cipher_size,
            const SubKeys& keys, const uint8_t* aad, uint32_t aad_size,
            const uint8_t* nonce, const uint8_t* tag, uint8_t* recipe) const;

    public:
        TwoPhaseEnc();
        ~TwoPhaseEnc();

        /** Locate the length-preserving region payload inside an envelope. */
        static bool GetPayloadRange(const uint8_t* envelope, uint32_t envelope_size,
            uint32_t& payload_offset, uint32_t& payload_size);

        /** Encrypt a chunk into a deterministic, self-contained AATE envelope. */
        uint32_t TwoPhaseEncChunk(uint8_t* plain_chunk, uint32_t size,
            uint8_t* similarity_seed, uint8_t* enc_chunk);

        /** Decrypt and authenticate an AATE envelope. Returns 0 on failure. */
        uint32_t TwoPhaseDecChunk(uint8_t* enc_chunk, uint32_t size,
            uint8_t* similarity_seed, uint8_t* plain_chunk);
};

#endif
