/**
 * @file const_var.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the const variables
 * @version 0.1
 * @date 2022-02-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef EDRSTORE_CONST_VAR_H
#define EDRSTORE_CONST_VAR_H

#include <bits/stdc++.h>

// performance breakdown
#define EDR_BREAKDOWN

// chunk type
static const size_t MAX_CHUNK_SIZE = (1 << 14);

static const uint32_t CHUNK_QUEUE_SIZE = (1024 * 4);
static const size_t THREAD_STACK_SIZE = (8*1024*1024);

// sketch & super-feature & feature settings
static const uint32_t SUPER_FEATURE_PER_CHUNK = 3; // 3 super-feature per chunk 
static const uint32_t FEATURE_PER_SUPER_FEATURE = 4; // 4 features per super-feature
static const uint32_t FEATURE_PER_CHUNK = SUPER_FEATURE_PER_CHUNK * 
    FEATURE_PER_SUPER_FEATURE; // 12 total features per chunk
// Content-defined landmarks retained with their plaintext positions.  They
// let the key manager distinguish insertion/deletion shifts from replacements.
static const uint32_t AATE_POSITION_SKETCH_SIZE = 8;

// for rabin fingerprint
static const uint64_t FINGERPRINT_PT = 0xbfe6b8a5bf378d83LL;

// data type enum
enum DATA_TYPE_SET {NORMAL_CHUNK = 0, COMPRESSED_NORMAL_CHUNK, RECIPE_CHUNK,
    FULL_EDR_CACHE_CHUNK, FULL_EDR_UNCOMPRESS_CHUNK, CACHE_RESTORE_DELTA,
    CACHE_RESTORE_BASE, COMP_NORMAL_CHUNK, UNCOMP_NORMAL_CHUNK};

// for crypto info 
enum ENCRYPT_SET {AES_256_GCM = 0, AES_128_GCM, AES_256_CFB, AES_128_CFB,
    AES_256_CBC, AES_128_CBC, AES_256_CTR, AES_128_CTR, AES_256_ECB, AES_128_ECB};
enum HASH_SET {SHA_256 = 0, MD5 = 1, SHA_1 = 2};
static const uint32_t CRYPTO_BLOCK_SIZE = 16;
static const uint32_t CHUNK_HASH_SIZE = 32;
static const int HASH_TYPE = SHA_256;
static const int CIPHER_TYPE = AES_256_CTR;

// the type of compression type
enum COMPRESS_TYPE_SET {LZ4_COMPRESS_TYPE = 0, ZSTD_COMPRESS_TYPE, ZLIB_COMPRESS_TYPE};
static const int COMPRESSION_TYPE = ZSTD_COMPRESS_TYPE;
static const int COMPRESSION_LEVEL = -1;

// the setting of the container
static const uint32_t MAX_CONTAINER_SIZE = (1 << 22); // container size: 4MB
static const uint32_t CONTAINER_ID_LENGTH = 8; // 8 bytes

// the operation type
enum CLIENT_OPT_TYPE_SET {UPLOAD_OPT = 0, DOWNLOAD_OPT};

// for SSL connection
static const int IN_SERVER_SIDE = 0;
static const int IN_CLIENT_SIDE = 1;

// for network protocol
enum NETWORK_PROTOCOL_SET {CLIENT_LOGIN_UPLOAD = 0, CLIENT_LOGIN_DOWNLOAD,
    SERVER_LOGIN_RESPONSE, CLIENT_UPLOAD_CHUNK, CLIENT_UPLOAD_RECIPE,
    CLIENT_UPLOAD_RECIPE_END, SERVER_FILE_NON_EXIST, SERVER_RESTORE_RECIPE,
    CLIENT_RESTORE_READY, CLIENT_KEY_GEN, KEY_MANAGER_KEY_GEN_REPLY,
    CLIENT_RESTORE_RECIPE_REPLY, SERVER_RESTORE_CHUNK, SERVER_RESTORE_FINAL,
    CLIENT_UPLOAD_FEATURE};

enum CHUNK_STATUS_SET {UNIQUE_CHUNK = 0, UNIQUE_CHUNK_AFTER_CACHE, DUPLICATE_CHUNK, SIMILAR_CHUNK,
    NON_SIMILAR_CHUNK, COMP_DELTA_CHUNK, UNCOMP_DELTA_CHUNK, COMP_BASE_CHUNK,
    UNCOMP_BASE_CHUNK, CACHE_INSERT_CHUNK, CACHE_DELTA_CHUNK, CACHE_EVICT_CHUNK,
    MULTI_LEVEL_DELTA_CHUNK, CHUNK_PAIR, SINGLE_CHUNK};

// for SSL connection 
static const char SERVER_CERT[] = "../key/server/server.crt";
static const char SERVER_KEY[] = "../key/server/server.key";
static const char CLIENT_CERT[] = "../key/client/client.crt";
static const char CLIENT_KEY[] = "../key/client/client.key";
static const char CA_CERT[] = "../key/ca/ca.crt";

// max client
static const int MAX_CLIENT_NUM = 10;

enum CLIENT_ENC_TYPE_SET {PLAIN = 0, SERVER_AIDED_MLE, ENC_COMP_MLE};

enum EDR_DESIGN_SET {ONLY_SIMILAR_ENC = 0, SIMILAR_ENC_COMP, FULL_EDR};

// CompressionWithPad may append its 4-byte original compressed length before
// encryption, so an AATE plaintext can be slightly larger than a raw chunk.
static const size_t AATE_MAX_PLAIN_SIZE = MAX_CHUNK_SIZE + sizeof(uint32_t);
// AATE payload is length-preserving. Its authenticated boundary recipe uses
// at most one bit per plaintext byte, plus a small fixed envelope header.
static const size_t AATE_MAX_RECIPE_SIZE = 1 + (AATE_MAX_PLAIN_SIZE + 7) / 8;
// GLOBAL objects contain only a magic/version prefix followed by a
// length-preserving payload.  The object length supplies the payload length.
static const size_t AATE_GLOBAL_HEADER_SIZE = 5;
static const size_t AATE_GLOBAL_DELTA_HEADER_SIZE = 5;
static const size_t AATE_ENVELOPE_HEADER_SIZE = 41;
static const size_t ENC_MAX_CHUNK_SIZE = AATE_MAX_PLAIN_SIZE + AATE_MAX_RECIPE_SIZE +
    AATE_ENVELOPE_HEADER_SIZE;
static const size_t AATE_DELTA_HEADER_SIZE = 17;
static const size_t STORAGE_MAX_CHUNK_SIZE = ENC_MAX_CHUNK_SIZE +
    AATE_ENVELOPE_HEADER_SIZE + AATE_MAX_RECIPE_SIZE + AATE_DELTA_HEADER_SIZE;

#endif
