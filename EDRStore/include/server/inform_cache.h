/**
 * @file inform_cache.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the interfaces
 * @version 0.1
 * @date 2022-08-02
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef EDRSTORE_INFORM_CACHE_H
#define EDRSTORE_INFORM_CACHE_H

#include "../configure.h"
#include "../data_structure.h"
#include "../database/db_factory.h"
#include "../reduction/odess_subfeature_index.h"
#include "../reduction/delta_comp.h"

extern Configure config;

class InformCache {
    private:
        string my_name_ = "InformCache";
        uint32_t client_id_;
        string cache_root_path_;

        // base_fp -> base chunk bytes; persists to disk (RocksDB).
        AbsDatabase* base_2_data_db_;

        // base_fp -> (ref_count, chunk_size). ref_count is incremented by
        // SUB_FEATURE_PER_CHUNK on insert and decremented per evicted feature.
        unordered_map<string, pair<uint32_t, uint32_t>> base_2_cnt_idx_;

        // Inverted index over the 12 sub-feature slots.
        OdessSubfeatureIndex* feature_index_;

        // For top-K best-delta trial.
        DeltaComp* delta_comp_;
        string cache_base_chunk_str_;

        void LoadCntIdx();
        void StoreCntIdx();

    public:
        InformCache(uint32_t client_id);
        ~InformCache();

        // Top-K trial: find up to TOP_K_CANDIDATES bases, delta-encode against
        // each, keep the smallest. Returns true and fills output_chunk on a
        // similar hit; returns false otherwise (caller treats as unique).
        bool ProcessNormalChunk(WrappedChunk_t* input_chunk,
            WrappedChunk_t* output_chunk);

        void InsertCachedChunk(WrappedChunk_t* cache_chunk);

        void EvictCacheChunk(WrappedChunk_t* evict_chunk);

        uint64_t DeleteEvictChunk();

        uint32_t FetchBaseChunk(uint8_t* base_fp, uint8_t* output_base);

        bool IsBaseChunkExist(uint8_t* base_fp);

        uint64_t GetCacheSize();
};

#endif
