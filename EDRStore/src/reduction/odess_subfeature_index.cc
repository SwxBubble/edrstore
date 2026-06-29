#include "../../include/reduction/odess_subfeature_index.h"

OdessSubfeatureIndex::OdessSubfeatureIndex(uint32_t min_match, uint32_t top_k)
    : min_match_(min_match), top_k_(top_k) {
}

std::vector<std::string> OdessSubfeatureIndex::QueryTopK(const uint64_t* features) {
    std::unordered_map<std::string, uint32_t> match_count;
    for (uint32_t i = 0; i < SUB_FEATURE_PER_CHUNK; i++) {
        auto it = tables_[i].find(features[i]);
        if (it == tables_[i].end()) {
            continue;
        }
        for (const std::string& base_fp : it->second) {
            match_count[base_fp]++;
        }
    }

    std::vector<std::pair<std::string, uint32_t>> ranked;
    ranked.reserve(match_count.size());
    for (auto& kv : match_count) {
        if (kv.second >= min_match_) {
            ranked.emplace_back(std::move(kv.first), kv.second);
        }
    }
    std::sort(ranked.begin(), ranked.end(),
        [](const std::pair<std::string, uint32_t>& a,
           const std::pair<std::string, uint32_t>& b) {
            return a.second > b.second;
        });

    std::vector<std::string> out;
    const size_t keep = std::min<size_t>(ranked.size(), top_k_);
    out.reserve(keep);
    for (size_t i = 0; i < keep; i++) {
        out.emplace_back(std::move(ranked[i].first));
    }
    return out;
}

void OdessSubfeatureIndex::Insert(const uint64_t* features,
    const std::string& base_fp) {
    for (uint32_t i = 0; i < SUB_FEATURE_PER_CHUNK; i++) {
        tables_[i][features[i]].push_back(base_fp);
    }
}

std::string OdessSubfeatureIndex::PopOneOccurrence(uint64_t feature) {
    for (uint32_t i = 0; i < SUB_FEATURE_PER_CHUNK; i++) {
        auto it = tables_[i].find(feature);
        if (it == tables_[i].end()) {
            continue;
        }
        auto& list = it->second;
        if (list.empty()) {
            tables_[i].erase(it);
            continue;
        }
        std::string popped = std::move(list.back());
        list.pop_back();
        if (list.empty()) {
            tables_[i].erase(it);
        }
        return popped;
    }
    return std::string();
}

uint64_t OdessSubfeatureIndex::TotalEntries() const {
    uint64_t total = 0;
    for (uint32_t i = 0; i < SUB_FEATURE_PER_CHUNK; i++) {
        for (const auto& kv : tables_[i]) {
            total += kv.second.size();
        }
    }
    return total;
}

void OdessSubfeatureIndex::InsertEdge(uint32_t slot, uint64_t feature,
    const std::string& base_fp) {
    if (slot < SUB_FEATURE_PER_CHUNK) {
        tables_[slot][feature].push_back(base_fp);
    }
}
