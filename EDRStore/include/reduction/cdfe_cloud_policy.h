#ifndef EDRSTORE_CDFE_CLOUD_POLICY_H
#define EDRSTORE_CDFE_CLOUD_POLICY_H

#include "../data_structure.h"

#include <cmath>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct CDFEPosting {
    std::string base_fp;
    uint16_t subblock_rank;
    float norm_pos;
};

struct CDFEBaseMeta {
    int subblock_count;
};

struct CDFECandidateStat {
    std::unordered_set<uint16_t> matched_query_subblocks;
    std::unordered_set<uint16_t> matched_base_subblocks;
    std::unordered_set<uint16_t> aligned_query_subblocks;
};

class CDFECloudPolicy {
private:
    std::string my_name_ = "CDFECloudPolicy";

    std::unordered_map<uint64_t, std::vector<CDFEPosting>> inverted_;
    std::unordered_map<std::string, CDFEBaseMeta> base_meta_;

    int hot_posting_limit_ = 64;
    int min_matched_subblocks_ = 2;
    float min_jaccard_proxy_ = 0.15f;
    float pos_tolerance_ = 0.15f;

public:
    uint64_t _total_query = 0;
    uint64_t _total_raw_candidates = 0;
    uint64_t _total_matched = 0;
    uint64_t _total_indexed_base = 0;
    uint64_t _total_indexed_features = 0;
    double _total_best_jaccard = 0.0;

    // phase-1 CDFE query stats
    double _total_query_time = 0.0;
    uint64_t _total_query_feature_num = 0;
    uint64_t _total_posting_scanned = 0;
    uint64_t _total_feature_not_found = 0;
    uint64_t _total_hot_feature_skipped = 0;

    CDFECloudPolicy();
    ~CDFECloudPolicy();

    void FindBaseChunk(ChunkInfo_t* info);
    void UpdateIndex(ChunkInfo_t* info);

    void PrintStats() const;
};

#endif