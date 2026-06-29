/**
 * @file inform_cache.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interface of InformCache
 * @version 0.1
 * @date 2022-08-02
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "../../include/server/inform_cache.h"

InformCache::InformCache(uint32_t client_id) {
    client_id_ = client_id;
    cache_root_path_ = config.GetCacheRootPath();
    feature_index_ = new OdessSubfeatureIndex();
    this->LoadCntIdx();

    DatabaseFactory db_factory;
    string db_path = cache_root_path_ + to_string(client_id_) + "_db";
    base_2_data_db_ = db_factory.CreateDatabase(ROCKSDB_DB, db_path);

    delta_comp_ = new DeltaComp();
    cache_base_chunk_str_.reserve(ENC_MAX_CHUNK_SIZE);
}

InformCache::~InformCache() {
    this->StoreCntIdx();
    delete base_2_data_db_;
    delete delta_comp_;
    delete feature_index_;
}

void InformCache::InsertCachedChunk(WrappedChunk_t* cache_chunk) {
    string base_fp_str((char*)cache_chunk->info.fp, CHUNK_HASH_SIZE);

    feature_index_->Insert(cache_chunk->info.features, base_fp_str);

    auto it = base_2_cnt_idx_.find(base_fp_str);
    if (it != base_2_cnt_idx_.end()) {
        it->second.first += SUB_FEATURE_PER_CHUNK;
    } else {
        base_2_cnt_idx_[base_fp_str] = {SUB_FEATURE_PER_CHUNK, cache_chunk->info.size};
        cache_base_chunk_str_.assign((char*)cache_chunk->data,
            cache_chunk->info.size);
        base_2_data_db_->Insert(base_fp_str, cache_base_chunk_str_);
    }
}

bool InformCache::ProcessNormalChunk(WrappedChunk_t* input_chunk,
    WrappedChunk_t* output_chunk) {
    std::vector<std::string> candidates =
        feature_index_->QueryTopK(input_chunk->info.features);
    if (candidates.empty()) {
        input_chunk->info.stat = NON_SIMILAR_CHUNK;
        return false;
    }

    // Trial-encode against each candidate; keep the smallest delta. Decoder
    // can recover only if it has the chosen base_fp, so we copy it back.
    uint32_t best_size = UINT32_MAX;
    std::string best_base_fp;
    std::string trial_base;
    trial_base.reserve(ENC_MAX_CHUNK_SIZE);

    std::vector<uint8_t> trial_delta_buf(ENC_MAX_CHUNK_SIZE);

    for (const std::string& cand : candidates) {
        if (!base_2_data_db_->QueryBuffer(
                const_cast<char*>(cand.c_str()), CHUNK_HASH_SIZE, trial_base)) {
            // Race / stale index entry: base evicted but feature edge survived.
            // Skip; the next candidate may succeed.
            continue;
        }
        uint32_t trial_size = delta_comp_->DeltaEncode(
            (uint8_t*)trial_base.data(), trial_base.size(),
            input_chunk->data, input_chunk->info.size,
            trial_delta_buf.data());
        if (trial_size < best_size) {
            best_size = trial_size;
            best_base_fp = cand;
            memcpy(output_chunk->data, trial_delta_buf.data(), trial_size);
        }
    }

    if (best_base_fp.empty()) {
        // All candidates were stale.
        input_chunk->info.stat = NON_SIMILAR_CHUNK;
        return false;
    }

    // Quality gate: voting alone (>=4/12) admits weak matches whose delta is
    // barely smaller than the input. Reject when best_delta / input >
    // NUMER/DENOM so downstream stores the chunk as a fresh base instead of
    // paying delta+base overhead for no real saving.
    if ((uint64_t)best_size * DELTA_REJECT_DENOM >
            (uint64_t)input_chunk->info.size * DELTA_REJECT_NUMER) {
        input_chunk->info.stat = NON_SIMILAR_CHUNK;
        return false;
    }

    output_chunk->info.size = best_size;
    memcpy(output_chunk->info.addr.base_fp, best_base_fp.data(), CHUNK_HASH_SIZE);
    memcpy(output_chunk->info.fp, input_chunk->info.fp, CHUNK_HASH_SIZE);
    output_chunk->info.stat = CACHE_DELTA_CHUNK;
    input_chunk->info.stat = SIMILAR_CHUNK;
    return true;
}

void InformCache::LoadCntIdx() {
    string cnt_idx_path = cache_root_path_ + to_string(client_id_) + "_cnt";
    ifstream cache_cnt_hdl;
    if (tool::FileExist(cnt_idx_path)) {
        cache_cnt_hdl.open(cnt_idx_path, ios_base::in | ios_base::binary);
        if (!cache_cnt_hdl.is_open()) {
            tool::Logging(my_name_.c_str(), "cannot open the cache cnt.\n");
            exit(EXIT_FAILURE);
        }
        cache_cnt_hdl.seekg(0, ios_base::end);
        size_t file_size = cache_cnt_hdl.tellg();
        if (file_size == 0) {
            cache_cnt_hdl.close();
            return;
        }
        cache_cnt_hdl.seekg(0, ios_base::beg);

        size_t idx_item_num = 0;
        cache_cnt_hdl.read((char*)&idx_item_num, sizeof(size_t));
        string base_fp_str;
        base_fp_str.resize(CHUNK_HASH_SIZE, 0);
        uint32_t cnt;
        uint32_t chunk_size;
        for (size_t i = 0; i < idx_item_num; i++) {
            cache_cnt_hdl.read((char*)&base_fp_str[0], CHUNK_HASH_SIZE);
            cache_cnt_hdl.read((char*)&cnt, sizeof(uint32_t));
            cache_cnt_hdl.read((char*)&chunk_size, sizeof(uint32_t));
            base_2_cnt_idx_[base_fp_str] = {cnt, chunk_size};
        }
        cache_cnt_hdl.close();
    }

    // Restore the inverted index: file is a flat list of (slot, feature, base_fp).
    string feature_idx_path = cache_root_path_ + to_string(client_id_) + "_idx";
    ifstream feature_idx_hdl;
    if (tool::FileExist(feature_idx_path)) {
        feature_idx_hdl.open(feature_idx_path, ios_base::in | ios_base::binary);
        if (!feature_idx_hdl.is_open()) {
            tool::Logging(my_name_.c_str(),
                "cannot open the cache feature index.\n");
            exit(EXIT_FAILURE);
        }
        feature_idx_hdl.seekg(0, ios_base::end);
        size_t file_size = feature_idx_hdl.tellg();
        if (file_size == 0) {
            feature_idx_hdl.close();
            return;
        }
        feature_idx_hdl.seekg(0, ios_base::beg);

        size_t edge_num = 0;
        feature_idx_hdl.read((char*)&edge_num, sizeof(size_t));

        string tmp_base_fp;
        tmp_base_fp.resize(CHUNK_HASH_SIZE, 0);
        uint32_t slot;
        uint64_t feature;
        for (size_t i = 0; i < edge_num; i++) {
            feature_idx_hdl.read((char*)&slot, sizeof(uint32_t));
            feature_idx_hdl.read((char*)&feature, sizeof(uint64_t));
            feature_idx_hdl.read(&tmp_base_fp[0], CHUNK_HASH_SIZE);
            feature_index_->InsertEdge(slot, feature, tmp_base_fp);
        }
        feature_idx_hdl.close();
    }
}

void InformCache::StoreCntIdx() {
    string cnt_idx_path = cache_root_path_ + to_string(client_id_) + "_cnt";
    ofstream cache_cnt_hdl;
    cache_cnt_hdl.open(cnt_idx_path, ios_base::trunc | ios_base::binary);
    if (!cache_cnt_hdl.is_open()) {
        tool::Logging(my_name_.c_str(), "cannot init the cache cnt idx.\n");
        exit(EXIT_FAILURE);
    }
    size_t idx_item_num = base_2_cnt_idx_.size();
    cache_cnt_hdl.write((char*)&idx_item_num, sizeof(size_t));
    for (auto& it : base_2_cnt_idx_) {
        cache_cnt_hdl.write(it.first.c_str(), CHUNK_HASH_SIZE);
        cache_cnt_hdl.write((char*)&it.second.first, sizeof(uint32_t));
        cache_cnt_hdl.write((char*)&it.second.second, sizeof(uint32_t));
    }
    cache_cnt_hdl.close();

    string feature_idx_path = cache_root_path_ + to_string(client_id_) + "_idx";
    ofstream feature_idx_hdl;
    feature_idx_hdl.open(feature_idx_path, ios_base::trunc | ios_base::binary);
    if (!feature_idx_hdl.is_open()) {
        tool::Logging(my_name_.c_str(),
            "cannot init the cache feature index.\n");
        exit(EXIT_FAILURE);
    }
    size_t edge_num = feature_index_->TotalEntries();
    feature_idx_hdl.write((char*)&edge_num, sizeof(size_t));
    feature_index_->ForEachEdge(
        [&feature_idx_hdl](uint32_t slot, uint64_t feature, const std::string& base_fp) {
            feature_idx_hdl.write((char*)&slot, sizeof(uint32_t));
            feature_idx_hdl.write((char*)&feature, sizeof(uint64_t));
            feature_idx_hdl.write(base_fp.c_str(), CHUNK_HASH_SIZE);
        });
    feature_idx_hdl.close();
}

void InformCache::EvictCacheChunk(WrappedChunk_t* evict_chunk) {
    // Client tells us "these feature values are no longer in my LRU window."
    // For each feature, we pop one (feature, base_fp) edge from the index and
    // decrement that base's reference count. When a count hits zero,
    // DeleteEvictChunk will reap the base from RocksDB.
    uint32_t feature_num = evict_chunk->info.size;
    uint64_t* feature_ptr;

    for (size_t i = 0; i < feature_num; i++) {
        feature_ptr = (uint64_t*)(evict_chunk->data + i * sizeof(uint64_t));
        std::string base_fp = feature_index_->PopOneOccurrence(*feature_ptr);
        if (base_fp.empty()) {
            continue;
        }
        auto cnt_it = base_2_cnt_idx_.find(base_fp);
        if (cnt_it == base_2_cnt_idx_.end()) {
            continue;
        }
        if (cnt_it->second.first > 0) {
            cnt_it->second.first--;
        }
    }
}

uint64_t InformCache::DeleteEvictChunk() {
    uint64_t total_cache_size = 0;
    auto it = base_2_cnt_idx_.begin();
    while (it != base_2_cnt_idx_.end()) {
        if (it->second.first == 0) {
            base_2_data_db_->Delete(it->first);
            it = base_2_cnt_idx_.erase(it);
        } else {
            total_cache_size += it->second.second;
            it++;
        }
    }
    return total_cache_size;
}

bool InformCache::IsBaseChunkExist(uint8_t* base_fp) {
    string base_fp_str((char*)base_fp, CHUNK_HASH_SIZE);
    return base_2_cnt_idx_.find(base_fp_str) != base_2_cnt_idx_.end();
}

uint32_t InformCache::FetchBaseChunk(uint8_t* base_fp, uint8_t* output_base) {
    string base_fp_str((char*)base_fp, CHUNK_HASH_SIZE);
    if (!base_2_data_db_->Query(base_fp_str, cache_base_chunk_str_)) {
        tool::Logging(my_name_.c_str(),
            "cannot find the base chunk in the cache.\n");
        exit(EXIT_FAILURE);
    }
    uint32_t base_chunk_size = cache_base_chunk_str_.size();
    memcpy(output_base, cache_base_chunk_str_.c_str(), base_chunk_size);
    return base_chunk_size;
}

uint64_t InformCache::GetCacheSize() {
    return feature_index_->TotalEntries();
}
