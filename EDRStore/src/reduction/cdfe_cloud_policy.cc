#include "../../include/reduction/cdfe_cloud_policy.h"

#include <chrono>
#include <cstring>
#include <iostream>
#include <unordered_set>

CDFECloudPolicy::CDFECloudPolicy() {}

CDFECloudPolicy::~CDFECloudPolicy() {
    PrintStats();
}

void CDFECloudPolicy::FindBaseChunk(ChunkInfo_t* info) {
    auto query_start = std::chrono::steady_clock::now();

    auto finish_query_timer = [&]() {
        auto query_end = std::chrono::steady_clock::now();
        _total_query_time +=
            std::chrono::duration<double>(query_end - query_start).count();
    };

    _total_query++;

    if (info == nullptr || info->cdfe_feature_num == 0) {
        if (info != nullptr) {
            info->stat = NON_SIMILAR_CHUNK;
        }
        finish_query_timer();
        return;
    }

    _total_query_raw_feature_num += info->cdfe_feature_num;

    std::unordered_set<uint64_t> query_feature_set;
    query_feature_set.reserve(info->cdfe_feature_num * 2);

    for (uint32_t i = 0; i < info->cdfe_feature_num; ++i) {
        query_feature_set.insert(info->cdfe_features[i].value);
    }

    _total_query_feature_num += query_feature_set.size();

    std::unordered_map<std::string, CDFECandidateStat> stats;

    for (const auto& q_value : query_feature_set) {
        auto it = inverted_.find(q_value);
        if (it == inverted_.end()) {
            _total_feature_not_found++;
            continue;
        }

        const auto& plist = it->second;

        if (static_cast<int>(plist.size()) > hot_posting_limit_) {
            _total_hot_feature_skipped++;
            continue;
        }

        _total_posting_scanned += plist.size();

        for (const auto& posting : plist) {
            auto& st = stats[posting.base_fp];
            st.matched_feature_count++;
        }
    }

    _total_raw_candidates += stats.size();

    std::string best_fp;
    float best_score = 0.0f;

    const int query_feature_count =
        static_cast<int>(query_feature_set.size());

    for (auto& kv : stats) {
        const std::string& fp = kv.first;
        CDFECandidateStat& st = kv.second;

        auto meta_it = base_meta_.find(fp);
        if (meta_it == base_meta_.end()) {
            continue;
        }

        const int base_feature_count = meta_it->second.feature_count;
        const int intersection = st.matched_feature_count;
        const int union_count =
            query_feature_count + base_feature_count - intersection;

        const float jaccard =
            union_count > 0
                ? static_cast<float>(intersection) /
                      static_cast<float>(union_count)
                : 0.0f;

        if (intersection < min_matched_features_) {
            continue;
        }

        if (jaccard < min_jaccard_proxy_) {
            continue;
        }

        if (jaccard > best_score) {
            best_score = jaccard;
            best_fp = fp;
        }
    }

    if (!best_fp.empty()) {
        memcpy(info->addr.base_fp, best_fp.data(), CHUNK_HASH_SIZE);
        info->stat = SIMILAR_CHUNK;

        _total_matched++;
        _total_best_jaccard += best_score;
    } else {
        info->stat = NON_SIMILAR_CHUNK;
    }

    finish_query_timer();
}


void CDFECloudPolicy::UpdateIndex(ChunkInfo_t* info) {
    if (info == nullptr || info->cdfe_feature_num == 0) {
        return;
    }

    std::string fp_key(reinterpret_cast<const char*>(info->fp), CHUNK_HASH_SIZE);

    std::unordered_set<uint64_t> base_feature_set;
    base_feature_set.reserve(info->cdfe_feature_num * 2);

    for (uint32_t i = 0; i < info->cdfe_feature_num; ++i) {
        base_feature_set.insert(info->cdfe_features[i].value);
    }

    if (base_meta_.find(fp_key) == base_meta_.end()) {
        _total_indexed_base++;
    }

    base_meta_[fp_key] = CDFEBaseMeta{
        static_cast<int>(base_feature_set.size())
    };

    for (const auto& value : base_feature_set) {
        auto& plist = inverted_[value];

        plist.push_back(CDFEPosting{
            fp_key
        });

        _total_indexed_features++;

        if (static_cast<int>(plist.size()) > hot_posting_limit_) {
            plist.erase(
                plist.begin(),
                plist.begin() + (plist.size() - hot_posting_limit_)
            );
        }
    }
}

void CDFECloudPolicy::PrintStats() const {
    std::cerr << "\n========== CDFECloudPolicy Stats ==========\n";
    std::cerr << "total query: " << _total_query << "\n";
    std::cerr << "total matched: " << _total_matched << "\n";
    std::cerr << "total raw candidates: " << _total_raw_candidates << "\n";
    std::cerr << "total indexed base: " << _total_indexed_base << "\n";
    std::cerr << "total indexed features: " << _total_indexed_features << "\n";

    std::cerr << "total query raw feature num: "
              << _total_query_raw_feature_num << "\n";
    std::cerr << "total query feature num: "
              << _total_query_feature_num << "\n";
    std::cerr << "total posting scanned: "
              << _total_posting_scanned << "\n";
    std::cerr << "total feature not found: "
              << _total_feature_not_found << "\n";
    std::cerr << "total hot feature skipped: "
              << _total_hot_feature_skipped << "\n";

    std::cerr << "total query time: "
              << _total_query_time << " s\n";

    if (_total_query > 0) {
        std::cerr << "avg raw candidates/query: "
                  << static_cast<double>(_total_raw_candidates) /
                         static_cast<double>(_total_query)
                  << "\n";
        std::cerr << "avg raw CDFE features/query: "
                    << static_cast<double>(_total_query_raw_feature_num) /
                        static_cast<double>(_total_query)
                    << "\n";

        std::cerr << "avg query features/query: "
                  << static_cast<double>(_total_query_feature_num) /
                         static_cast<double>(_total_query)
                  << "\n";

        std::cerr << "avg postings scanned/query: "
                  << static_cast<double>(_total_posting_scanned) /
                         static_cast<double>(_total_query)
                  << "\n";

        std::cerr << "avg query time: "
                  << (_total_query_time /
                      static_cast<double>(_total_query)) * 1000000.0
                  << " us\n";
    }

    if (_total_query_time > 0) {
        std::cerr << "query throughput: "
                  << static_cast<double>(_total_query) /
                         _total_query_time
                  << " queries/s\n";
    }

    if (_total_matched > 0) {
        std::cerr << "avg best jaccard: "
                  << _total_best_jaccard /
                         static_cast<double>(_total_matched)
                  << "\n";
    }

    std::cerr << "===========================================\n";
}
