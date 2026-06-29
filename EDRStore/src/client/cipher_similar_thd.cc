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

CipherSimilarThd::CipherSimilarThd() {
    extractor_ = new OdessSubfeatureExtractor();
}

CipherSimilarThd::~CipherSimilarThd() {
    delete extractor_;
}

void CipherSimilarThd::Run(AbsMQ<EncFeatureChunk_t>* input_MQ,
    AbsMQ<EncFeatureChunk_t>* output_MQ) {
    tool::Logging(my_name_.c_str(), "the main thread is running.\n");

    struct timeval stime;
    struct timeval etime;
    double total_running_time = 0;

    gettimeofday(&stime, NULL);

    EncFeatureChunk_t tmp_data;
    while (true) {
        if (input_MQ->_done && input_MQ->IsEmpty()) {
            tool::Logging(my_name_.c_str(), "no chunk in the MQ, all jobs are done.\n");
            break;
        }

        if (input_MQ->Pop(tmp_data)) {
#ifdef EDR_BREAKDOWN
            gettimeofday(&_cipher_feature_stime, NULL);
#endif

            switch (tmp_data.feature_chunk.chunk.type) {
                case NORMAL_CHUNK: {
                    // Re-use the plaintext feature buffer to store features of
                    // the ciphertext chunk (server consumes these via
                    // SendChunkHeader_t::cipher_features).
                    extractor_->ExtractFeature(tmp_data.enc_data,
                        tmp_data.enc_size, tmp_data.feature_chunk.features);
                    break;
                }
                case RECIPE_CHUNK: {
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

            output_MQ->Push(tmp_data);
        }
    }

    output_MQ->_done = true;
    gettimeofday(&etime, NULL);
    total_running_time += tool::GetTimeDiff(stime, etime);

    tool::Logging(my_name_.c_str(), "thread exits, total running time: %lf\n",
        total_running_time);
}
