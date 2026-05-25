/**
 * @file cipher_similar_thd.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief 
 * @version 0.1
 * @date 2022-06-29
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../../include/client/cipher_similar_thd.h"

#include <cstring>

/**
 * @brief Construct a new Cipher Similar Thd object
 * 
 */
CipherSimilarThd::CipherSimilarThd() {
    rabin_util_ = new RabinFPUtil(config.GetSimilarSlidingWinSize());
    finesse_util_ = new FinesseUtil(SUPER_FEATURE_PER_CHUNK,
        FEATURE_PER_CHUNK, FEATURE_PER_SUPER_FEATURE);
    cdfe_extractor_ = new CDFEFeatureExtractor();
    rabin_util_->NewCtx(rabin_ctx_);
}

/**
 * @brief Destroy the Cipher Similar Thd object
 * 
 */
CipherSimilarThd::~CipherSimilarThd() {
    rabin_util_->FreeCtx(rabin_ctx_);
    delete rabin_util_;
    delete finesse_util_;
    delete cdfe_extractor_;
}

/**
 * @brief the main thread
 * 
 * @param input_MQ the input MQ
 */
void CipherSimilarThd::Run(AbsMQ<EncFeatureChunk_t>* input_MQ, 
    AbsMQ<EncFeatureChunk_t>* output_MQ) {
    tool::Logging(my_name_.c_str(), "the main thread is running.\n");

    struct timeval stime;
    struct timeval etime;
    double total_running_time = 0;

    gettimeofday(&stime, NULL);
    // -------- main process --------

    EncFeatureChunk_t tmp_data;
    while (true) {
        if (input_MQ->_done && input_MQ->IsEmpty()) {
            tool::Logging(my_name_.c_str(), "no chunk in the MQ, all jobs are done.\n"); 
            break;
        }

        if (input_MQ->Pop(tmp_data)) {
            // extract a chunk from the MQ
#ifdef EDR_BREAKDOWN
            gettimeofday(&_cipher_feature_stime, NULL);
#endif

            switch (tmp_data.feature_chunk.chunk.type) {
                case NORMAL_CHUNK: {
                    // re-use the plaintext feature buffer to store features of ciphertext chunk
                    finesse_util_->ExtractFeature(rabin_ctx_, tmp_data.enc_data,
                        tmp_data.enc_size, tmp_data.feature_chunk.features);

                    ChunkInfo_t tmp_info;
                    memset(&tmp_info, 0, sizeof(ChunkInfo_t));
                    cdfe_extractor_->Extract(tmp_data.enc_data,
                        tmp_data.enc_size, &tmp_info);

                    uint32_t n = tmp_info.cdfe_feature_num;
                    if (n > MAX_CDFE_FEATURES) {
                        n = MAX_CDFE_FEATURES;
                    }
                    tmp_data.cdfe_feature_num = n;
                    for (uint32_t i = 0; i < n; i++) {
                        tmp_data.cdfe_features[i] = tmp_info.cdfe_features[i];
                    }
                    break;    
                }
                case RECIPE_CHUNK: {
                    tmp_data.cdfe_feature_num = 0;
                    break;
                }
                default: {
                    tool::Logging(my_name_.c_str(), "wrong chunk type.\n");
                    exit(EXIT_FAILURE);
                }
            }

#ifdef EDR_BREAKDOWN
            gettimeofday(&_cipher_feature_etime, NULL);
            _total_cipher_feature_time += tool::GetTimeDiff(
                _cipher_feature_stime, _cipher_feature_etime);
            if (tmp_data.feature_chunk.chunk.type != RECIPE_CHUNK) {
                _total_cipher_feature_size += tmp_data.enc_size;
            }
#endif

            // insert the chunk to the output MQ
            output_MQ->Push(tmp_data);
        }
    }

    output_MQ->_done = true;
    gettimeofday(&etime, NULL);
    total_running_time += tool::GetTimeDiff(stime, etime);

    tool::Logging(my_name_.c_str(), "thread exits, total running time: %lf\n",
        total_running_time);
    
    return ;
}
