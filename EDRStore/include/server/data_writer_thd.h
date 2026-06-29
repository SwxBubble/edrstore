/**
 * @file data_writer_thd.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the interface of
 * @version 0.1
 * @date 2022-07-20
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef DATA_WRITER_THD_H
#define DATA_WRITER_THD_H

#include "../configure.h"
#include "../database/db_factory.h"
#include "../reduction/delta_comp.h"
#include "../reduction/odess_subfeature_index.h"
#include "../compression/compress_util.h"
#include "client_var.h"
#include "storage_core.h"

class DataWriterThd {
    private:
        string my_name_ = "DataWriterThd";

        // storage core
        StorageCore* storage_core_;

        // for delta compression
        DeltaComp* delta_comp_;

        // Global similarity index over cipher sub-features (shared across
        // clients; populated as new unique chunks land).
        OdessSubfeatureIndex* feature_index_;

        // for fp to chunk addr index
        AbsDatabase* fp_2_addr_db_;

        // Returns true if a delta was actually written; false if we fell back
        // to storing the chunk as a fresh base (delta wouldn't fit or base was
        // unreadable). Caller can then update statistics + index accordingly.
        bool ProcSimilarChunk(WrappedChunk_t* input_chunk, ClientVar* cur_client);
        void ProcNonSimilarChunk(WrappedChunk_t* input_chunk, ClientVar* cur_client);
        void ProcCacheDeltaChunk(WrappedChunk_t* input_chunk, ClientVar* cur_client);
        uint32_t FetchBaseChunk(uint8_t* base_fp, uint8_t* base_data,
            ClientVar* cur_client);

    public:
        // for delta compression
        uint64_t _total_similar_chunk_num = 0;
        uint64_t _total_similar_data_size = 0;
        uint64_t _total_delta_size = 0;

#ifdef EDR_BREAKDOWN
        struct timeval _comp_delta_stime;
        struct timeval _comp_delta_etime;
        double _total_comp_delta_time = 0;
        uint64_t _total_comp_delta_data_size = 0;
#endif

        // feature_index is owned by ServerOptThd; shared across clients.
        DataWriterThd(AbsDatabase* fp_2_addr_db,
            OdessSubfeatureIndex* feature_index,
            StorageCore* storage_core);

        ~DataWriterThd();

        void Run(ClientVar* cur_client);
};

#endif
