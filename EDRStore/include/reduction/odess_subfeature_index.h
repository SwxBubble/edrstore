#ifndef EDRSTORE_ODESS_SUBFEATURE_INDEX_H
#define EDRSTORE_ODESS_SUBFEATURE_INDEX_H

#include "../const_var.h"
#include "../define.h"

// 12-table inverted index for odess sub-features.
//
// Each of the SUB_FEATURE_PER_CHUNK slots owns its own map
//   sub_feature (uint64_t) -> list of base_fp values (strings).
// QueryTopK scans all 12 tables, counts hits per base_fp, filters
// match_count >= MIN_MATCH_FOR_SIMILAR, sorts descending by count,
// and returns the top TOP_K_CANDIDATES.
//
// base_fp is opaque to the index; callers use a chunk SHA256 (32 bytes)
// for the storage-server side, and a derived key_seed (also 32 bytes) for
// the key-server side.
class OdessSubfeatureIndex {
    private:
        std::array<std::unordered_map<uint64_t, std::vector<std::string>>,
            SUB_FEATURE_PER_CHUNK> tables_;
        uint32_t min_match_;
        uint32_t top_k_;

    public:
        explicit OdessSubfeatureIndex(uint32_t min_match = MIN_MATCH_FOR_SIMILAR,
            uint32_t top_k = TOP_K_CANDIDATES);
        ~OdessSubfeatureIndex() = default;

        // Returns up to top_k_ base_fp candidates whose match count >= min_match_,
        // sorted by descending count. Empty vector => no similar candidate.
        std::vector<std::string> QueryTopK(const uint64_t* features);

        // Inserts base_fp into all 12 per-slot inverted lists keyed by features[i].
        // No de-duplication: callers must avoid inserting the same base_fp twice
        // for the same chunk (i.e. call Insert at most once per (chunk, base_fp)).
        void Insert(const uint64_t* features, const std::string& base_fp);

        // Finds `feature` across the 12 slots, pops one base_fp from the first
        // matching list, and returns it. Empty string if not found.
        //
        // Cache eviction matches the original (approximate) semantics: the
        // client sends back evicted feature values without per-base context, so
        // each feature decrements one reference of an arbitrary base that held
        // it. With odess transforms the feature value is effectively unique to
        // its slot, so the scan finds at most one match.
        std::string PopOneOccurrence(uint64_t feature);

        // Total entry count summed across all 12 tables; for logging only.
        uint64_t TotalEntries() const;

        // Direct insert into a specific slot's list. Used by deserialization to
        // reconstruct the table without re-inserting all 12 slots like Insert().
        void InsertEdge(uint32_t slot, uint64_t feature, const std::string& base_fp);

        // Iterate every (slot, feature, base_fp) edge in the index. Used to
        // serialize the index without exposing internal storage.
        template <typename F>
        void ForEachEdge(F emit) const {
            for (uint32_t i = 0; i < SUB_FEATURE_PER_CHUNK; i++) {
                for (const auto& kv : tables_[i]) {
                    for (const std::string& base_fp : kv.second) {
                        emit(i, kv.first, base_fp);
                    }
                }
            }
        }
};

#endif
