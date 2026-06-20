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

namespace {

string FingerprintPrefix(const uint8_t* fp) {
    static const char hex[] = "0123456789abcdef";
    string out;
    out.reserve(16);
    for (uint32_t i = 0; i < 8; i++) {
        out.push_back(hex[(fp[i] >> 4) & 0xf]);
        out.push_back(hex[fp[i] & 0xf]);
    }
    return out;
}

}

/**
 * @brief Construct a new DataWriterThd object
 * 
 * @param fp_2_addr_db fp to chunk addr index
 * @param feature_2_fp_db feature to fp index
 * @param storage_core storage core
 */
DataWriterThd::DataWriterThd(AbsDatabase* fp_2_addr_db,
    AbsDatabase* feature_2_fp_db, StorageCore* storage_core) {
    fp_2_addr_db_ = fp_2_addr_db;
    feature_2_fp_db_ = feature_2_fp_db;
    storage_core_ = storage_core;
    delta_comp_ = new DeltaComp();
    similar_policy_ = new SimilarPolicy();
}

/**
 * @brief Destroy the DataWriterThd object
 * 
 */
DataWriterThd::~DataWriterThd() {
    delete delta_comp_;
    delete similar_policy_;
}

/**
 * @brief the main process
 * 
 * @param cur_client current client var
 */
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
    // -------- main process --------
    WrappedChunk_t tmp_data;
    while (true) {
        // extract a chunk from the MQ
        if (input_MQ->_done && input_MQ->IsEmpty()) {
            tool::Logging(my_name_.c_str(), "no chunk in the MQ, all jobs are done.\n");
            break;
        }

        if (input_MQ->Pop(tmp_data)) {
            // check the base chunk
            gettimeofday(&proc_stime, NULL);
            switch (tmp_data.info.stat) {
                case CACHE_DELTA_CHUNK: {
                    this->ProcCacheDeltaChunk(&tmp_data, cur_client);
                    break;
                }
                case UNIQUE_CHUNK: {
                    similar_policy_->FindBaseChunk(feature_2_fp_db_,
                        &tmp_data.info);
                    switch (tmp_data.info.stat) {
                        case SIMILAR_CHUNK: {
                            _total_similar_chunk_num++;
                            _total_similar_data_size += tmp_data.info.size;
                            this->ProcSimilarChunk(&tmp_data, cur_client);
                            break;
                        }
                        case NON_SIMILAR_CHUNK: {
                            this->ProcNonSimilarChunk(&tmp_data, cur_client);
                            similar_policy_->UpdateFeatureIndex(
                                feature_2_fp_db_, &tmp_data.info);
                            break;
                        }
                        default: {
                            tool::Logging(my_name_.c_str(),
                                "wrong unique chunk type.\n");
                            exit(EXIT_FAILURE);
                        }
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

    return ;
}

/**
 * @brief process a similar chunk
 * 
 * @param input_chunk input chunk
 * @param cur_client current client
 */
void DataWriterThd::ProcSimilarChunk(WrappedChunk_t* input_chunk,
    ClientVar* cur_client) {
    uint8_t base_chunk[ENC_MAX_CHUNK_SIZE];
    uint32_t base_chunk_size = 0;
    uint8_t delta_chunk[ENC_MAX_CHUNK_SIZE];
    uint32_t delta_chunk_size = 0;
    uint8_t best_delta_chunk[ENC_MAX_CHUNK_SIZE];
    uint32_t best_delta_chunk_size = UINT32_MAX;
    uint8_t best_base_fp[CHUNK_HASH_SIZE];
    bool found_good_delta = false;
    uint32_t best_rank = UINT32_MAX;
    vector<pair<string, uint32_t>> candidate_delta_debug;

#ifdef EDR_BREAKDOWN
    gettimeofday(&_comp_delta_stime, NULL);
#endif

    uint32_t candidate_num = input_chunk->info.cdfe_candidate_num;
    if (candidate_num == 0) {
        candidate_num = 1;
        memcpy(input_chunk->info.cdfe_candidate_base_fp[0],
            input_chunk->info.addr.base_fp, CHUNK_HASH_SIZE);
    }

    candidate_num = min<uint32_t>(candidate_num, CDFE_TOPK_BASE_CANDIDATES);
    for (uint32_t i = 0; i < candidate_num; i++) {
        base_chunk_size = this->FetchBaseChunk(
            input_chunk->info.cdfe_candidate_base_fp[i], base_chunk,
            cur_client);
        if (base_chunk_size == 0) {
            continue;
        }

        if (!delta_comp_->TryDeltaEncode(base_chunk, base_chunk_size,
            input_chunk->data, input_chunk->info.size, delta_chunk,
            &delta_chunk_size)) {
            candidate_delta_debug.push_back({
                FingerprintPrefix(input_chunk->info.cdfe_candidate_base_fp[i]),
                UINT32_MAX
            });
            continue;
        }
        candidate_delta_debug.push_back({
            FingerprintPrefix(input_chunk->info.cdfe_candidate_base_fp[i]),
            delta_chunk_size
        });

        if (delta_chunk_size < best_delta_chunk_size) {
            best_delta_chunk_size = delta_chunk_size;
            best_rank = i;
            memcpy(best_delta_chunk, delta_chunk, delta_chunk_size);
            memcpy(best_base_fp, input_chunk->info.cdfe_candidate_base_fp[i],
                CHUNK_HASH_SIZE);
        }
    }

    if (best_delta_chunk_size < input_chunk->info.size * 0.2) {
        found_good_delta = true;
    }

    static ofstream cdfe_delta_debug_log("edr_cdfe_delta_debug.log",
        ios_base::out);
    if (cdfe_delta_debug_log.is_open()) {
        cdfe_delta_debug_log << "[EDR CDFE delta debug]"
            << " chunk_len=" << input_chunk->info.size
            << " candidate_count=" << candidate_num
            << " best_rank=";
        if (best_rank == UINT32_MAX) {
            cdfe_delta_debug_log << -1;
        } else {
            cdfe_delta_debug_log << best_rank;
        }
        cdfe_delta_debug_log << " best_delta_size=";
        if (best_delta_chunk_size == UINT32_MAX) {
            cdfe_delta_debug_log << "INVALID";
        } else {
            cdfe_delta_debug_log << best_delta_chunk_size
                << " best_delta_ratio="
                << static_cast<double>(best_delta_chunk_size) /
                    static_cast<double>(input_chunk->info.size);
        }
        cdfe_delta_debug_log << " fallback_to_base="
            << (found_good_delta ? 0 : 1) << " | ";
        for (uint32_t i = 0; i < candidate_delta_debug.size(); i++) {
            cdfe_delta_debug_log << "rank" << i
                << "(base_fp=" << candidate_delta_debug[i].first
                << ", delta_size=";
            if (candidate_delta_debug[i].second == UINT32_MAX) {
                cdfe_delta_debug_log << "INVALID";
            } else {
                cdfe_delta_debug_log << candidate_delta_debug[i].second;
            }
            cdfe_delta_debug_log << ") ";
        }
        cdfe_delta_debug_log << endl;
    }

    if (!found_good_delta) {
        storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
            input_chunk->info.size, cur_client);
        input_chunk->info.addr.stat = COMP_BASE_CHUNK;
        similar_policy_->UpdateFeatureIndex(feature_2_fp_db_,
            &input_chunk->info);
        if (_total_similar_chunk_num > 0) {
            _total_similar_chunk_num--;
        }
        if (_total_similar_data_size >= input_chunk->info.size) {
            _total_similar_data_size -= input_chunk->info.size;
        }
        return ;
    }

    memcpy(input_chunk->info.addr.base_fp, best_base_fp, CHUNK_HASH_SIZE);
    storage_core_->WriteChunk(&input_chunk->info.addr, best_delta_chunk,
        best_delta_chunk_size, cur_client);
    input_chunk->info.addr.stat = COMP_DELTA_CHUNK;

    // update stat
    _total_delta_size += best_delta_chunk_size;

#ifdef EDR_BREAKDOWN
    gettimeofday(&_comp_delta_etime, NULL);
    _total_comp_delta_time += tool::GetTimeDiff(_comp_delta_stime,
        _comp_delta_etime);
    _total_comp_delta_data_size += input_chunk->info.size;
#endif

    return ;
}

/**
 * @brief process a non-similar chunk 
 * 
 * @param input_chunk input chunk
 * @param cur_client current client
 */
void DataWriterThd::ProcNonSimilarChunk(WrappedChunk_t* input_chunk,
    ClientVar* cur_client) {
    storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
        input_chunk->info.size, cur_client);
    input_chunk->info.addr.stat = COMP_BASE_CHUNK;
    return ;
}

/**
 * @brief process a cache delta chunk
 * 
 * @param input_chunk input chunk
 * @param cur_client current client
 */
void DataWriterThd::ProcCacheDeltaChunk(WrappedChunk_t* input_chunk,
    ClientVar* cur_client) {
    storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
        input_chunk->info.size, cur_client);
    input_chunk->info.addr.stat = CACHE_DELTA_CHUNK;
    return ;
}

/**
 * @brief fetch the base chunk
 * 
 * @param base_fp base chunk fp
 * @param base_data base chunk data
 * @param cur_client current client
 * @return uint32_t base chunk size
 */
uint32_t DataWriterThd::FetchBaseChunk(uint8_t* base_fp, uint8_t* base_data,
    ClientVar* cur_client) {
    string base_addr_str;

    // step-1: query the fp index to get the base chunk address
    if (!fp_2_addr_db_->QueryBuffer((char*)base_fp, CHUNK_HASH_SIZE, base_addr_str)) {
        return 0;
    }

    // step-2: read base chunk from the disk
    KeyForChunkHashDB_t* base_addr = (KeyForChunkHashDB_t*)&base_addr_str[0];
    bool read = storage_core_->ReadChunk(base_addr, base_data, cur_client);
    
    if(read == false){
        return 0;
    }

    return base_addr->len;
}
