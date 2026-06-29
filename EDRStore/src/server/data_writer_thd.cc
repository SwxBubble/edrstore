/**
 * @file data_writer_thd.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement the interfaces of DataWriterThd
 * @version 0.1
 * @date 2022-07-22
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "../../include/server/data_writer_thd.h"

DataWriterThd::DataWriterThd(AbsDatabase* fp_2_addr_db,
    OdessSubfeatureIndex* feature_index, StorageCore* storage_core) {
    fp_2_addr_db_ = fp_2_addr_db;
    feature_index_ = feature_index;
    storage_core_ = storage_core;
    delta_comp_ = new DeltaComp();
}

DataWriterThd::~DataWriterThd() {
    delete delta_comp_;
}

void DataWriterThd::Run(ClientVar* cur_client) {
    tool::Logging(my_name_.c_str(), "the main thread is running.\n");
    AbsMQ<WrappedChunk_t>* input_MQ = cur_client->_comp_2_writer_mq;

    struct timeval stime;
    struct timeval etime;
    double total_running_time = 0;

    struct timeval proc_stime;
    struct timeval proc_etime;
    double total_proc_time = 0;

    gettimeofday(&stime, NULL);

    WrappedChunk_t tmp_data;
    while (true) {
        if (input_MQ->_done && input_MQ->IsEmpty()) {
            tool::Logging(my_name_.c_str(), "no chunk in the MQ, all jobs are done.\n");
            break;
        }

        if (input_MQ->Pop(tmp_data)) {
            gettimeofday(&proc_stime, NULL);
            switch (tmp_data.info.stat) {
                case CACHE_DELTA_CHUNK: {
                    this->ProcCacheDeltaChunk(&tmp_data, cur_client);
                    break;
                }
                case UNIQUE_CHUNK: {
                    // Global top-1 lookup: we use the highest-vote candidate.
                    // We stay top-1 here (not top-K like InformCache) because
                    // the global index resolves to disk-backed containers via
                    // StorageCore::ReadChunk, where extra trial reads would
                    // amplify I/O. InformCache (per-client RocksDB) is where
                    // best-of-K trial happens cheaply.
                    std::vector<std::string> candidates =
                        feature_index_->QueryTopK(tmp_data.info.features);
                    bool wrote_as_base = false;
                    if (!candidates.empty()) {
                        memcpy(tmp_data.info.addr.base_fp,
                            candidates[0].data(), CHUNK_HASH_SIZE);
                        tmp_data.info.stat = SIMILAR_CHUNK;
                        bool encoded = this->ProcSimilarChunk(&tmp_data, cur_client);
                        if (encoded) {
                            _total_similar_chunk_num++;
                            _total_similar_data_size += tmp_data.info.size;
                        } else {
                            // Delta didn't fit; ProcSimilarChunk already wrote
                            // the chunk as a fresh base. Fall through to index
                            // it like a NON_SIMILAR_CHUNK.
                            wrote_as_base = true;
                        }
                    }
                    if (candidates.empty() || wrote_as_base) {
                        if (candidates.empty()) {
                            tmp_data.info.stat = NON_SIMILAR_CHUNK;
                            this->ProcNonSimilarChunk(&tmp_data, cur_client);
                        }
                        std::string base_fp_str(
                            (char*)tmp_data.info.fp, CHUNK_HASH_SIZE);
                        feature_index_->Insert(tmp_data.info.features,
                            base_fp_str);
                    }
                    break;
                }
                default: {
                    tool::Logging(my_name_.c_str(),
                        "wrong chunk type after cache.\n");
                    exit(EXIT_FAILURE);
                }
            }

            // update the fp index
            fp_2_addr_db_->InsertBothBuffer((char*)tmp_data.info.fp, CHUNK_HASH_SIZE,
                (char*)&tmp_data.info.addr, sizeof(KeyForChunkHashDB_t));

            gettimeofday(&proc_etime, NULL);
            total_proc_time += tool::GetTimeDiff(proc_stime, proc_etime);
        }
    }

    // check the tail container
    if (cur_client->_cur_container.cur_size != 0) {
        storage_core_->SaveContainer(&cur_client->_cur_container);
    }

    gettimeofday(&etime, NULL);
    total_running_time += tool::GetTimeDiff(stime, etime);

    tool::Logging(my_name_.c_str(), "thread exits, total proc time: %lf, "
        "total running time: %lf\n", total_proc_time, total_running_time);
}

bool DataWriterThd::ProcSimilarChunk(WrappedChunk_t* input_chunk,
    ClientVar* cur_client) {
    uint8_t base_chunk[ENC_MAX_CHUNK_SIZE];
    uint32_t base_chunk_size = 0;
    uint8_t delta_chunk[ENC_MAX_CHUNK_SIZE];
    uint32_t delta_chunk_size = 0;

    base_chunk_size = this->FetchBaseChunk(input_chunk->info.addr.base_fp,
        base_chunk, cur_client);

    if (base_chunk_size == 0) {
        // base unreadable (e.g. stale index entry); fall back to writing as new
        storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
            input_chunk->info.size, cur_client);
        input_chunk->info.addr.stat = COMP_BASE_CHUNK;
        return false;
    }

#ifdef EDR_BREAKDOWN
    gettimeofday(&_comp_delta_stime, NULL);
#endif

    delta_chunk_size = delta_comp_->DeltaEncode(base_chunk, base_chunk_size,
        input_chunk->data, input_chunk->info.size, delta_chunk);

    bool reject = (delta_chunk_size == UINT32_MAX) ||
        ((uint64_t)delta_chunk_size * DELTA_REJECT_DENOM >
            (uint64_t)input_chunk->info.size * DELTA_REJECT_NUMER);
    if (reject) {
        // Either xdelta overflowed ENC_MAX_CHUNK_SIZE, or the delta isn't
        // small enough to be worth the indirection. Write the chunk as a
        // fresh base instead.
        storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
            input_chunk->info.size, cur_client);
        input_chunk->info.addr.stat = COMP_BASE_CHUNK;
#ifdef EDR_BREAKDOWN
        gettimeofday(&_comp_delta_etime, NULL);
        _total_comp_delta_time += tool::GetTimeDiff(_comp_delta_stime,
            _comp_delta_etime);
#endif
        return false;
    }

    storage_core_->WriteChunk(&input_chunk->info.addr, delta_chunk,
        delta_chunk_size, cur_client);
    input_chunk->info.addr.stat = COMP_DELTA_CHUNK;

    _total_delta_size += delta_chunk_size;

#ifdef EDR_BREAKDOWN
    gettimeofday(&_comp_delta_etime, NULL);
    _total_comp_delta_time += tool::GetTimeDiff(_comp_delta_stime,
        _comp_delta_etime);
    _total_comp_delta_data_size += input_chunk->info.size;
#endif
    return true;
}

void DataWriterThd::ProcNonSimilarChunk(WrappedChunk_t* input_chunk,
    ClientVar* cur_client) {
    storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
        input_chunk->info.size, cur_client);
    input_chunk->info.addr.stat = COMP_BASE_CHUNK;
}

void DataWriterThd::ProcCacheDeltaChunk(WrappedChunk_t* input_chunk,
    ClientVar* cur_client) {
    storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
        input_chunk->info.size, cur_client);
    input_chunk->info.addr.stat = CACHE_DELTA_CHUNK;
}

uint32_t DataWriterThd::FetchBaseChunk(uint8_t* base_fp, uint8_t* base_data,
    ClientVar* cur_client) {
    string base_addr_str;

    if (!fp_2_addr_db_->QueryBuffer((char*)base_fp, CHUNK_HASH_SIZE, base_addr_str)) {
        tool::Logging(my_name_.c_str(), "req base chunk not exits.\n");
        return 0;
    }

    KeyForChunkHashDB_t* base_addr = (KeyForChunkHashDB_t*)&base_addr_str[0];
    bool read = storage_core_->ReadChunk(base_addr, base_data, cur_client);

    if (read == false) {
        return 0;
    }

    return base_addr->len;
}
