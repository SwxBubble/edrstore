/**
 * @file two_phase_enc.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief the ECB-only implementation (legacy TwoPhaseEnc API name)
 * @version 0.1
 * @date 2022-05-30
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../../include/client/two_phase_enc.h"

/**
 * @brief Construct a new Two Phase Enc object
 * 
 */
TwoPhaseEnc::TwoPhaseEnc() {
    crypto_util_ecb_ = new CryptoUtil(AES_256_ECB, SHA_256);
    cipher_ctx_ = EVP_CIPHER_CTX_new();
}

/**
 * @brief Destroy the Two Phase Enc object
 * 
 */
TwoPhaseEnc::~TwoPhaseEnc() {
    delete crypto_util_ecb_;
    EVP_CIPHER_CTX_free(cipher_ctx_);
}

/**
 * @brief encrypt a chunk with AES-256-ECB
 * 
 * @param plain_chunk the plain chunk
 * @param size the chunk size
 * @param key the enc key
 * @param enc_chunk the encrypted chunk
 * @return uint32_t the encrypted chunk size
 */
uint32_t TwoPhaseEnc::TwoPhaseEncChunk(uint8_t* plain_chunk, uint32_t size, uint8_t* key,
    uint8_t* enc_chunk) {
    return crypto_util_ecb_->EncryptWithKeyIV(cipher_ctx_, plain_chunk, size, key,
        nullptr, enc_chunk);
}

/**
 * @brief decrypt an AES-256-ECB chunk
 * 
 * @param enc_chunk the encrypted chunk
 * @param size the chunk size
 * @param key the dec key
 * @param plain_chunk the plain chunk
 * @return uint32_t the plain chunk size
 */
uint32_t TwoPhaseEnc::TwoPhaseDecChunk(uint8_t* enc_chunk, uint32_t size, uint8_t* key, 
    uint8_t* plain_chunk) {
    return crypto_util_ecb_->DecryptWithKeyIV(cipher_ctx_, enc_chunk, size, key,
        nullptr, plain_chunk);
}
