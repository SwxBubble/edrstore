/**
 * @file fastcdc_chunker.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief define the interface of 
 * @version 0.1
 * @date 2022-06-03
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef MY_CODEBASE_FASTCDC_CHUNKER_H
#define MY_CODEBASE_FASTCDC_CHUNKER_H

#include "abs_chunker.h"
#include "gear_table.h"

class FastCDC : public AbsChunker {
    protected:
        string my_name_ = "FastCDC";

        uint64_t stop_mask_;

        /**
         * @brief To get the offset of chunks for a given buffer  
         * 
         * @param src the input buffer  
         * @param len the length of this buffer
         * @return uint32_t length of this chunk.
         */
        uint32_t CutPoint(const uint8_t* src, const uint32_t len);
    
    public:
        /**
         * @brief Construct a new FastCDC object
         * 
         */
        FastCDC();

        /**
         * @brief Destroy the FastCDC object
         * 
         */
        ~FastCDC();

        /**
         * @brief load the data from the file
         * 
         * @param input_file the input file handler
         * @return uint32_t the read size
         */
        uint32_t LoadDataFromFile(ifstream& input_file);

        /**
         * @brief generate a chunk
         * 
         * @param data the buffer to store the chunk data
         * @return uint32_t the chunk size
         */
        uint32_t GenerateOneChunk(uint8_t* data);
};

#endif
