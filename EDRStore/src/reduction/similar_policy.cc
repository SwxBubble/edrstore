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

float SimilarPolicy::ComputeCDFEOrderConsistency(
    const vector<pair<uint16_t, uint16_t>>& matched_ranks) {
    if (matched_ranks.empty()) {
        return 0.0;
    }

    auto pairs = matched_ranks;
    sort(pairs.begin(), pairs.end(),
        [](const auto& a, const auto& b) {
            if (a.first != b.first) {
                return a.first < b.first;
            }
            return a.second < b.second;
        });

    vector<uint16_t> tails;
    for (auto it : pairs) {
        auto pos = lower_bound(tails.begin(), tails.end(), it.second);
        if (pos == tails.end()) {
            tails.push_back(it.second);
        } else {
            *pos = it.second;
        }
    }

    return static_cast<float>(tails.size()) /
        static_cast<float>(pairs.size());
}

void SimilarPolicy::FindBaseChunkByCDFE(ChunkInfo_t* info) {
    info->cdfe_candidate_num = 0;
    unordered_map<string, CDFECandidateStat> stats;

    uint32_t query_subblock_count = info->cdfe_feature_num;
    for (uint32_t i = 0; i < info->cdfe_feature_num; i++) {
        query_subblock_count = max(query_subblock_count,
            static_cast<uint32_t>(info->cdfe_features[i].subblock_rank) + 1);
    }

    for (uint32_t i = 0; i < info->cdfe_feature_num; i++) {
        CDFEFeature_t& qf = info->cdfe_features[i];
        auto find_ret = cdfe_index_.find(qf.value);
        if (find_ret == cdfe_index_.end()) {
            continue;
        }

        const auto& posting_list = find_ret->second;
        if (posting_list.size() > cdfe_hot_posting_limit_) {
            continue;
        }

        for (const auto& posting : posting_list) {
            auto& stat = stats[posting.base_fp];
            stat.matched_query_subblocks.insert(qf.subblock_rank);
            stat.matched_base_subblocks.insert(posting.subblock_rank);

            if (fabs(qf.norm_pos - posting.norm_pos) <= cdfe_pos_tolerance_) {
                stat.aligned_query_subblocks.insert(qf.subblock_rank);
            }
            if (stat.matched_ranks.size() < 64) {
                stat.matched_ranks.push_back(
                    {qf.subblock_rank, posting.subblock_rank});
            }
        }
    }

    struct CDFEScoredCandidate {
        string base_fp;
        float score;
    };

    vector<CDFEScoredCandidate> scored_candidates;

    for (auto& it : stats) {
        const string& base_fp = it.first;
        auto& stat = it.second;

        const uint32_t matched_query =
            static_cast<uint32_t>(stat.matched_query_subblocks.size());
        const uint32_t matched_base =
            static_cast<uint32_t>(stat.matched_base_subblocks.size());
        const uint32_t aligned =
            static_cast<uint32_t>(stat.aligned_query_subblocks.size());

        auto count_it = cdfe_base_subblock_count_.find(base_fp);
        const uint32_t base_subblock_count =
            count_it == cdfe_base_subblock_count_.end() ?
            matched_base : count_it->second;

        const uint32_t intersection_proxy = min(matched_query, matched_base);
        const uint32_t union_proxy =
            query_subblock_count + base_subblock_count - intersection_proxy;
        const float jaccard_proxy = union_proxy > 0 ?
            static_cast<float>(intersection_proxy) /
                static_cast<float>(union_proxy) :
            0.0;

        if (matched_query < cdfe_min_matched_subblocks_) {
            continue;
        }
        if (aligned < cdfe_min_aligned_subblocks_) {
            continue;
        }
        if (jaccard_proxy < cdfe_min_jaccard_proxy_) {
            continue;
        }

        const float order = ComputeCDFEOrderConsistency(stat.matched_ranks);
        const float score = jaccard_proxy + 0.01f * order;

        scored_candidates.push_back({base_fp, score});
    }

    sort(scored_candidates.begin(), scored_candidates.end(),
        [](const auto& a, const auto& b) {
            return a.score > b.score;
        });

    const uint32_t candidate_num = min<uint32_t>(
        CDFE_TOPK_BASE_CANDIDATES,
        static_cast<uint32_t>(scored_candidates.size()));
    for (uint32_t i = 0; i < candidate_num; i++) {
        memcpy(info->cdfe_candidate_base_fp[i],
            scored_candidates[i].base_fp.c_str(), CHUNK_HASH_SIZE);
    }
    info->cdfe_candidate_num = candidate_num;

    if (candidate_num > 0) {
        memcpy(info->addr.base_fp, info->cdfe_candidate_base_fp[0],
            CHUNK_HASH_SIZE);
        info->stat = SIMILAR_CHUNK;
    } else {
        info->stat = NON_SIMILAR_CHUNK;
    }
}

void SimilarPolicy::UpdateCDFEIndex(CDFEFeature_t* cdfe_features,
    uint32_t cdfe_feature_num, string& base_fp) {
    uint32_t subblock_count = cdfe_feature_num;
    for (uint32_t i = 0; i < cdfe_feature_num; i++) {
        subblock_count = max(subblock_count,
            static_cast<uint32_t>(cdfe_features[i].subblock_rank) + 1);

        auto& posting_list = cdfe_index_[cdfe_features[i].value];
        posting_list.push_back({base_fp, cdfe_features[i].subblock_rank,
            cdfe_features[i].norm_pos});
        if (posting_list.size() > cdfe_hot_posting_limit_) {
            posting_list.erase(posting_list.begin(),
                posting_list.begin() +
                    (posting_list.size() - cdfe_hot_posting_limit_));
        }
    }
    cdfe_base_subblock_count_[base_fp] = subblock_count;
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

/**
 * @brief find the base chunk
 * 
 * @param feature_2_fp_db feature to base fp index
 * @param info chunk info
 */
void SimilarPolicy::FindBaseChunk(AbsDatabase* feature_2_fp_db,
    ChunkInfo_t* info) {
    info->cdfe_candidate_num = 0;
    if (info->cdfe_feature_num > 0) {
        FindBaseChunkByCDFE(info);
        return;
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
    if (info->cdfe_feature_num > 0) {
        FindBaseChunkByCDFE(info);
        return;
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

void SimilarPolicy::UpdateFeatureIndex(AbsDatabase* feature_2_fp_db,
    ChunkInfo_t* info) {
    string base_fp;
    base_fp.assign((char*)info->fp, CHUNK_HASH_SIZE);

    if (info->cdfe_feature_num > 0) {
        UpdateCDFEIndex(info->cdfe_features, info->cdfe_feature_num, base_fp);
    }

    this->UpdateFeatureIndex(feature_2_fp_db, info->features, info->fp);
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
    ChunkInfo_t* info, string& base_fp) {
    if (info->cdfe_feature_num > 0) {
        UpdateCDFEIndex(info->cdfe_features, info->cdfe_feature_num, base_fp);
    }

    this->UpdateFeatureIndex(feature_2_fp_db, info->features, base_fp);
    return ;
}
