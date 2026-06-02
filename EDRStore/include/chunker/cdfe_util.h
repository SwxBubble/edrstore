/**
 * @file cdfe_util.h
 * @brief CDFE set-order feature extractor for EDRStore.
 */

#ifndef EDRSTORE_CDFE_UTIL_H
#define EDRSTORE_CDFE_UTIL_H

#include "../data_structure.h"

class CDFEUtil {
    private:
        int min_subblock_size_ = 256;
        int avg_subblock_size_ = 512;
        int max_subblock_size_ = 1024;
        uint64_t boundary_mask_ = 0x1ff;
        int feature_window_size_ = 24;

        uint64_t ExtractOneLocalFeature(const uint8_t* data, int size) const;

    public:
        CDFEUtil();
        ~CDFEUtil();

        void ExtractFeature(uint8_t* data, uint32_t size,
            uint64_t* compact_features, uint32_t* cdfe_feature_num,
            CDFEFeature_t* cdfe_features);
};

#endif
