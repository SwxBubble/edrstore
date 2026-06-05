/**
 * @file similar_policy.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the interfaces of SimilarPolicy
 * @version 0.1
 * @date 2022-08-03
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef EDRSTORE_SIMILAR_POLICY
#define EDRSTORE_SIMILAR_POLICY

#include "../database/db_factory.h"
#include "../data_structure.h"

class SimilarPolicy {
    private:
        string my_name_ = "SimilarPolicy";
        struct CDFEPosting {
            string base_fp;
            uint64_t base_order;
            uint16_t subblock_rank;
            float norm_pos;
        };
        unordered_map<uint64_t, vector<CDFEPosting>> cdfe_index_;
        unordered_map<string, uint32_t> cdfe_base_subblock_count_;
        unordered_map<string, uint64_t> cdfe_base_order_;
        uint64_t next_cdfe_base_order_ = 0;
        uint32_t cdfe_hot_posting_limit_ = 64;
        uint32_t cdfe_min_matched_subblocks_ = 0;
        uint32_t cdfe_min_aligned_subblocks_ = 0;
        float cdfe_min_jaccard_proxy_ = 0.15;
        float cdfe_pos_tolerance_ = 0.15;

        bool FindBaseChunkByCDFE(ChunkInfo_t* info);
        void UpdateCDFEIndex(CDFEFeature_t* cdfe_features,
            uint32_t cdfe_feature_num, string& base_fp);

    public:
        /**
         * @brief Construct a new SimilarPolicy object
         * 
         */
        SimilarPolicy();

        /**
         * @brief Destroy the SimilarPolicy object
         * 
         */
        ~SimilarPolicy();

        /**
         * @brief find the base chunk
         * 
         * @param feature_2_fp_db feature to base fp index
         * @param info chunk info
         */
        void FindBaseChunk(AbsDatabase* feature_2_fp_db,
            ChunkInfo_t* info);

        /**
         * @brief find the base chunk
         * 
         * @param feature_2_fp_db feature to base fp index
         * @param info chunk info
         */
        void FindBaseChunk(unordered_map<uint64_t, string>& feature_2_fp_db,
            ChunkInfo_t* info);

        /**
         * @brief update the feature index 
         * 
         * @param feature_2_fp_db feature to base fp index
         * @param features chunk feature
         * @param base_fp base chunk fp
         */
        void UpdateFeatureIndex(AbsDatabase* feature_2_fp_db,
            uint64_t* features, uint8_t* base_fp);
        void UpdateFeatureIndex(AbsDatabase* feature_2_fp_db,
            ChunkInfo_t* info);

        /**
         * @brief update the feature index
         * 
         * @param feature_2_fp_db feature to base fp index
         * @param features chunk feature
         * @param base_fp base chunk fp
         */
        void UpdateFeatureIndex(unordered_map<uint64_t, string>& feature_2_fp_db,
            uint64_t* features, string& base_fp);
        void UpdateFeatureIndex(unordered_map<uint64_t, string>& feature_2_fp_db,
            ChunkInfo_t* info);
};

#endif
