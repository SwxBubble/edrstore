/**
 * @file plain_similar_thd.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief  define the thread to compute the plaintext chunk features
 * @version 0.1
 * @date 2022-06-10
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef PLAIN_SIMILAR_THD_H
#define PLAIN_SIMILAR_THD_H

#include "../chunker/odess_subfeature.h"
#include "../message_queue/mq_factory.h"
#include "../data_structure.h"
#include "../configure.h"

extern Configure config;

class PlainSimilarThd {
    private:
        string my_name_ = "PlainSimilarThd";

        OdessSubfeatureExtractor* extractor_;

    public:
#ifdef EDR_BREAKDOWN
        struct timeval _plain_feature_stime;
        struct timeval _plain_feature_etime;
        double _total_plain_feature_time = 0;
        uint64_t _total_plain_feature_size = 0;
#endif

        PlainSimilarThd();
        ~PlainSimilarThd();

        void Run(AbsMQ<Chunk_t>* input_MQ, AbsMQ<FeatureChunk_t>* output_MQ);
};

#endif
