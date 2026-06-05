/**
 * @file similar_policy.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interfaces of SimilarPolicy
 * @version 0.1
 * @date 2022-08-03
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../../include/reduction/similar_policy.h"

bool CmpPair(pair<string, uint32_t>& a, 
    pair<string, uint32_t>& b) {
    return a.second > b.second;
}

struct CDFECandidateScore {
    string base_fp;
    uint64_t base_order = UINT64_MAX;
    unordered_set<uint16_t> matched_query_subblocks;
    unordered_set<uint16_t> matched_base_subblocks;
    unordered_set<uint16_t> aligned_query_subblocks;
    float jaccard_proxy = 0;
};

bool CmpCDFECandidate(const CDFECandidateScore& a,
    const CDFECandidateScore& b) {
    if (a.jaccard_proxy != b.jaccard_proxy) {
        return a.jaccard_proxy > b.jaccard_proxy;
    }
    return a.base_order < b.base_order;
}

/**
 * @brief Construct a new SimilarPolicy object
 * 
 */
SimilarPolicy::SimilarPolicy() {

}

/**
 * @brief Destroy the SimilarPolicy object
 * 
 */
SimilarPolicy::~SimilarPolicy() {

}

bool SimilarPolicy::FindBaseChunkByCDFE(ChunkInfo_t* info) {
    if (info->cdfe_feature_num == 0) {
        return false;
    }

    unordered_map<string, CDFECandidateScore> candidate_map;
    uint32_t query_subblock_count = info->cdfe_feature_num;
    for (uint32_t i = 0; i < info->cdfe_feature_num; i++) {
        query_subblock_count = max(query_subblock_count,
            static_cast<uint32_t>(info->cdfe_features[i].subblock_rank) + 1);
    }

    for (uint32_t i = 0; i < info->cdfe_feature_num; i++) {
        CDFEFeature_t& qf = info->cdfe_features[i];
        auto posting_ret = cdfe_index_.find(qf.value);
        if (posting_ret == cdfe_index_.end() ||
            posting_ret->second.size() > cdfe_hot_posting_limit_) {
            continue;
        }

        for (auto& posting : posting_ret->second) {
            auto& score = candidate_map[posting.base_fp];
            if (score.base_fp.empty()) {
                score.base_fp = posting.base_fp;
                score.base_order = posting.base_order;
            }
            score.matched_query_subblocks.insert(qf.subblock_rank);
            score.matched_base_subblocks.insert(posting.subblock_rank);
            if (fabs(posting.norm_pos - qf.norm_pos) <= cdfe_pos_tolerance_) {
                score.aligned_query_subblocks.insert(qf.subblock_rank);
            }
        }
    }

    vector<CDFECandidateScore> candidates;
    for (auto& it : candidate_map) {
        CDFECandidateScore& score = it.second;
        uint32_t matched_query_subblocks =
            static_cast<uint32_t>(score.matched_query_subblocks.size());
        uint32_t matched_base_subblocks =
            static_cast<uint32_t>(score.matched_base_subblocks.size());
        uint32_t aligned_subblocks =
            static_cast<uint32_t>(score.aligned_query_subblocks.size());
        uint32_t base_subblock_count = query_subblock_count;
        auto cnt_ret = cdfe_base_subblock_count_.find(score.base_fp);
        if (cnt_ret != cdfe_base_subblock_count_.end()) {
            base_subblock_count = cnt_ret->second;
        }

        uint32_t intersection_proxy = min(matched_query_subblocks,
            matched_base_subblocks);
        uint32_t union_proxy = query_subblock_count + base_subblock_count -
            intersection_proxy;
        score.jaccard_proxy = union_proxy == 0 ? 0 :
            static_cast<float>(intersection_proxy) /
            static_cast<float>(union_proxy);

        if (matched_query_subblocks >= cdfe_min_matched_subblocks_ &&
            aligned_subblocks >= cdfe_min_aligned_subblocks_ &&
            score.jaccard_proxy >= cdfe_min_jaccard_proxy_) {
            candidates.push_back(score);
        }
    }

    if (candidates.empty()) {
        return false;
    }

    sort(candidates.begin(), candidates.end(), CmpCDFECandidate);
    info->cdfe_candidate_num = min<uint32_t>(candidates.size(),
        CDFE_TOPK_BASE_CANDIDATES);
    for (uint32_t i = 0; i < info->cdfe_candidate_num; i++) {
        memcpy(info->cdfe_candidate_base_fp[i], candidates[i].base_fp.c_str(),
            CHUNK_HASH_SIZE);
    }
    memcpy(info->addr.base_fp, candidates[0].base_fp.c_str(),
        CHUNK_HASH_SIZE);
    return true;
}

/**
 * @brief find the base chunk
 * 
 * @param feature_2_fp_db feature to base fp index
 * @param info chunk info
 */
void SimilarPolicy::FindBaseChunk(AbsDatabase* feature_2_fp_db,
    ChunkInfo_t* info) {
    info->cdfe_candidate_num = 0;
    if (FindBaseChunkByCDFE(info)) {
        info->stat = SIMILAR_CHUNK;
        return ;
    }

    // query the feature index to get the base chunk hash
    unordered_map<string, uint32_t> feature_freq_map;
    bool is_similar = false;
    bool is_first_match = true;
    uint8_t first_match_base_fp[CHUNK_HASH_SIZE];
    string tmp_base_fp;
    for (size_t i = 0; i < SUPER_FEATURE_PER_CHUNK; i++) {
        // count the freq of each base key
        if (feature_2_fp_db->QueryBuffer((char*)&info->features[i],
            sizeof(uint64_t), tmp_base_fp)) {
            if (is_first_match) {
                memcpy(first_match_base_fp, tmp_base_fp.c_str(),
                    CHUNK_HASH_SIZE);
                is_first_match = false;
            }

            if (feature_freq_map.find(tmp_base_fp) != feature_freq_map.end()) {
                feature_freq_map[tmp_base_fp]++;
            } else {
                feature_freq_map[tmp_base_fp] = 1;
            }
            is_similar = true;
        }
    }

    if (is_similar) {
        // similar chunk
        // find the most similar base chunk
        vector<pair<string, uint32_t>> tmp_freq_vec;
        for (auto it : feature_freq_map) {
            tmp_freq_vec.push_back(it);
        }
        sort(tmp_freq_vec.begin(), tmp_freq_vec.end(), CmpPair);
        if (tmp_freq_vec[0].second == 1) {
            memcpy(info->addr.base_fp, first_match_base_fp, CHUNK_HASH_SIZE);
        } else {
            memcpy(info->addr.base_fp, tmp_freq_vec[0].first.c_str(),
                CHUNK_HASH_SIZE);
        }
        info->stat = SIMILAR_CHUNK;
    } else {
        info->stat = NON_SIMILAR_CHUNK;
    }
    
    return ;
}

/**
 * @brief find the base chunk
 * 
 * @param feature_2_fp_db feature to base fp index
 * @param info chunk info
 */
void SimilarPolicy::FindBaseChunk(
    unordered_map<uint64_t, string>& feature_2_fp_db,
    ChunkInfo_t* info) {
    info->cdfe_candidate_num = 0;
    if (FindBaseChunkByCDFE(info)) {
        info->stat = SIMILAR_CHUNK;
        return ;
    }

    // query the feature index to get the base chunk hash
    unordered_map<string, uint32_t> feature_freq_map;
    bool is_similar = false;
    bool is_first_match = true;
    uint8_t first_match_base_fp[CHUNK_HASH_SIZE];
    for (size_t i = 0; i < SUPER_FEATURE_PER_CHUNK; i++) {
        // count the freq of each base key
        auto find_base_ret = feature_2_fp_db.find(info->features[i]);
        if (find_base_ret != feature_2_fp_db.end()) {
            if (is_first_match) {
                memcpy(first_match_base_fp, find_base_ret->second.c_str(),
                    CHUNK_HASH_SIZE);
                is_first_match = false;
            }
            auto find_freq_ret = feature_freq_map.find(find_base_ret->second);
            if (find_freq_ret != feature_freq_map.end()) {
                find_freq_ret->second++;
            } else {
                feature_freq_map[find_base_ret->second] = 1;
            }
            is_similar = true;
        }
    }

    if (is_similar) {
        // similar chunk
        // find the most similar base chunk
        vector<pair<string, uint32_t>> tmp_freq_vec;
        for (auto it : feature_freq_map) {
            tmp_freq_vec.push_back(it);
        }
        sort(tmp_freq_vec.begin(), tmp_freq_vec.end(), CmpPair);
        if (tmp_freq_vec[0].second == 1) {
            memcpy(info->addr.base_fp, first_match_base_fp, CHUNK_HASH_SIZE);
        } else {
            memcpy(info->addr.base_fp, tmp_freq_vec[0].first.c_str(),
                CHUNK_HASH_SIZE);
        }
        info->stat = SIMILAR_CHUNK;
    } else {
        info->stat = NON_SIMILAR_CHUNK;
    }
    
    return ;
}

/**
 * @brief update the feature index 
 * 
 * @param feature_2_fp_db feature to base fp index
 * @param features chunk feature
 * @param base_fp base chunk fp
 */
void SimilarPolicy::UpdateFeatureIndex(AbsDatabase* feature_2_fp_db,
    uint64_t* features, uint8_t* base_fp) {
    // non-similar chunk, update the feature index
    for (size_t i = 0; i < SUPER_FEATURE_PER_CHUNK; i++) {
        feature_2_fp_db->InsertBothBuffer((char*)&features[i],
            sizeof(uint64_t), (char*)base_fp, CHUNK_HASH_SIZE);
    }
    return ;
}

void SimilarPolicy::UpdateCDFEIndex(CDFEFeature_t* cdfe_features,
    uint32_t cdfe_feature_num, string& base_fp) {
    uint32_t subblock_count = cdfe_feature_num;
    uint64_t base_order = next_cdfe_base_order_;
    auto order_ret = cdfe_base_order_.find(base_fp);
    if (order_ret != cdfe_base_order_.end()) {
        base_order = order_ret->second;
    } else {
        cdfe_base_order_[base_fp] = base_order;
        next_cdfe_base_order_++;
    }
    for (uint32_t i = 0; i < cdfe_feature_num; i++) {
        subblock_count = max(subblock_count,
            static_cast<uint32_t>(cdfe_features[i].subblock_rank) + 1);
        auto& posting_list = cdfe_index_[cdfe_features[i].value];
        posting_list.push_back({base_fp, base_order,
            cdfe_features[i].subblock_rank, cdfe_features[i].norm_pos});
        if (posting_list.size() > cdfe_hot_posting_limit_) {
            posting_list.erase(posting_list.begin(),
                posting_list.begin() + (posting_list.size() -
                    cdfe_hot_posting_limit_));
        }
    }
    cdfe_base_subblock_count_[base_fp] = subblock_count;
}

void SimilarPolicy::UpdateFeatureIndex(AbsDatabase* feature_2_fp_db,
    ChunkInfo_t* info) {
    UpdateFeatureIndex(feature_2_fp_db, info->features, info->fp);
    if (info->cdfe_feature_num > 0) {
        string base_fp;
        base_fp.assign((char*)info->fp, CHUNK_HASH_SIZE);
        UpdateCDFEIndex(info->cdfe_features, info->cdfe_feature_num, base_fp);
    }
    return ;
}

/**
 * @brief update the feature index
 * 
 * @param feature_2_fp_db feature to base fp index
 * @param features chunk feature
 * @param base_fp base chunk fp
 */
void SimilarPolicy::UpdateFeatureIndex(
    unordered_map<uint64_t, string>& feature_2_fp_db,
    uint64_t* features, string& base_fp) {
    // non-similar chunk, update the feature index
    for (size_t i = 0; i < SUPER_FEATURE_PER_CHUNK; i++) {
        feature_2_fp_db[features[i]] = base_fp;
    }
    return ;
}

void SimilarPolicy::UpdateFeatureIndex(
    unordered_map<uint64_t, string>& feature_2_fp_db,
    ChunkInfo_t* info) {
    string base_fp;
    base_fp.assign((char*)info->fp, CHUNK_HASH_SIZE);
    UpdateFeatureIndex(feature_2_fp_db, info->features, base_fp);
    if (info->cdfe_feature_num > 0) {
        UpdateCDFEIndex(info->cdfe_features, info->cdfe_feature_num, base_fp);
    }
    return ;
}
