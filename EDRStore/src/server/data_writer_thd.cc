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
#include "../../include/crypto/aate_object.h"

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
                            AATEObjectView target_view;
                            if (!ParseAATEObject(tmp_data.data,
                                tmp_data.info.size, target_view)) {
                                tool::Logging(my_name_.c_str(),
                                    "invalid AATE similar object.\n");
                                exit(EXIT_FAILURE);
                            }
                            _total_similar_data_size += target_view.payload_size;
                            this->ProcSimilarChunk(&tmp_data, cur_client);
                            break;
                        }
                        case NON_SIMILAR_CHUNK: {
                            this->ProcNonSimilarChunk(&tmp_data, cur_client);
                            similar_policy_->UpdateFeatureIndex(
                                feature_2_fp_db_,
                                tmp_data.info.features,
                                tmp_data.info.fp
                            );
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
    uint8_t base_chunk[STORAGE_MAX_CHUNK_SIZE];
    uint32_t base_chunk_size = 0;
    uint8_t delta_chunk[ENC_MAX_CHUNK_SIZE];
    uint32_t delta_chunk_size = 0;

    base_chunk_size = this->FetchBaseChunk(input_chunk->info.addr.base_fp,
        base_chunk, cur_client);

    if(base_chunk_size == 0){
        // avoid delta, directly write
        storage_core_->WriteChunk(&input_chunk->info.addr, input_chunk->data,
            input_chunk->info.size, cur_client);
        input_chunk->info.addr.stat = COMP_BASE_CHUNK;
        AATEObjectView target_view;
        if (ParseAATEObject(input_chunk->data, input_chunk->info.size,
            target_view)) {
            _total_similar_chunk_num--;
            _total_similar_data_size -= target_view.payload_size;
        }
        similar_policy_->UpdateFeatureIndex(feature_2_fp_db_,
            input_chunk->info.features, input_chunk->info.fp);
        return;
    }

#ifdef EDR_BREAKDOWN
    gettimeofday(&_comp_delta_stime, NULL);
#endif

    AATEObjectView base_view;
    AATEObjectView target_view;
    if (!ParseAATEObject(base_chunk, base_chunk_size, base_view) ||
        !ParseAATEObject(input_chunk->data, input_chunk->info.size, target_view)) {
        tool::Logging(my_name_.c_str(), "cannot parse AATE global delta objects.\n");
        exit(EXIT_FAILURE);
    }
    delta_chunk_size = delta_comp_->DeltaEncode(
        const_cast<uint8_t*>(base_view.payload), base_view.payload_size,
        const_cast<uint8_t*>(target_view.payload), target_view.payload_size,
        delta_chunk);

    uint8_t stored_record[STORAGE_MAX_CHUNK_SIZE];
    uint32_t stored_record_size = 0;
    if (!BuildAATEDelta(target_view, delta_chunk, delta_chunk_size,
        stored_record, sizeof(stored_record), stored_record_size)) {
        tool::Logging(my_name_.c_str(), "cannot build AATE global delta record.\n");
        exit(EXIT_FAILURE);
    }
    storage_core_->WriteChunk(&input_chunk->info.addr, stored_record,
        stored_record_size, cur_client);
    input_chunk->info.addr.stat = COMP_DELTA_CHUNK;

    // update stat
    _total_delta_size += delta_chunk_size;
    _total_delta_record_overhead_size +=
        stored_record_size - delta_chunk_size;

#ifdef EDR_BREAKDOWN
    gettimeofday(&_comp_delta_etime, NULL);
    _total_comp_delta_time += tool::GetTimeDiff(_comp_delta_stime,
        _comp_delta_etime);
    _total_comp_delta_data_size += target_view.payload_size;
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
        tool::Logging(my_name_.c_str(), "req base chunk not exits.\n");
        exit(EXIT_FAILURE);
    }

    // step-2: read base chunk from the disk
    KeyForChunkHashDB_t* base_addr = (KeyForChunkHashDB_t*)&base_addr_str[0];
    bool read = storage_core_->ReadChunk(base_addr, base_data, cur_client);
    
    if(read == false){
        return 0;
    }

    return base_addr->len;
}
