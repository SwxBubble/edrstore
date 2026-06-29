/**
 * @file plain_similar_thd.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of PlainSimilarThd
 * @version 0.1
 * @date 2022-06-10
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "../../include/client/plain_similar_thd.h"

PlainSimilarThd::PlainSimilarThd() {
    extractor_ = new OdessSubfeatureExtractor();
}

PlainSimilarThd::~PlainSimilarThd() {
    delete extractor_;
}

void PlainSimilarThd::Run(AbsMQ<Chunk_t>* input_MQ,
    AbsMQ<FeatureChunk_t>* output_MQ) {
    tool::Logging(my_name_.c_str(), "the main thread is running.\n");

    struct timeval stime;
    struct timeval etime;
    double total_running_time = 0;

    gettimeofday(&stime, NULL);

    FeatureChunk_t tmp_data;
    while (true) {
        if (input_MQ->_done && input_MQ->IsEmpty()) {
            tool::Logging(my_name_.c_str(), "no chunk in the MQ, all jobs are done.\n");
            break;
        }

        if (input_MQ->Pop(tmp_data.chunk)) {
#ifdef EDR_BREAKDOWN
            gettimeofday(&_plain_feature_stime, NULL);
#endif

            switch (tmp_data.chunk.type) {
                case NORMAL_CHUNK: {
                    extractor_->ExtractFeature(tmp_data.chunk.raw_chunk.data,
                        tmp_data.chunk.raw_chunk.size, tmp_data.features);
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
            gettimeofday(&_plain_feature_etime, NULL);
            _total_plain_feature_time += tool::GetTimeDiff(
                _plain_feature_stime, _plain_feature_etime);
            if (tmp_data.chunk.type != RECIPE_CHUNK) {
                _total_plain_feature_size += tmp_data.chunk.raw_chunk.size;
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
