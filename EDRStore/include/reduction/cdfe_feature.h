#ifndef EDRSTORE_CDFE_FEATURE_H
#define EDRSTORE_CDFE_FEATURE_H

#include "../data_structure.h"
#include <cstdint>
#include <vector>

struct CDFEParams {
    int min_subblock_size = 256;
    int avg_subblock_size = 512;
    int max_subblock_size = 1024;

    uint64_t boundary_mask = 511;

    int split_window_size = 48;
    int feature_window_size = 24;
};

struct CDFESubblockSpan {
    int start;
    int len;
    int rank;
};

class CDFEFeatureExtractor {
private:
    CDFEParams params_;

    uint64_t Mix64(uint64_t x) const;
    uint64_t GearUpdate(uint64_t fp, uint8_t byte) const;
    bool IsBoundary(uint64_t fp) const;

    uint64_t HashBytes(const uint8_t* data, int len) const;
    uint64_t HashWindow(const uint8_t* data, int len) const;
    uint64_t ExtractOneLocalFeature(const uint8_t* data, int len) const;

    std::vector<CDFESubblockSpan> SplitIntoSubblocks(
        const uint8_t* buf,
        int chunk_len
    ) const;

public:
    CDFEFeatureExtractor();
    explicit CDFEFeatureExtractor(const CDFEParams& params);

    void Extract(const uint8_t* buf, int len, ChunkInfo_t* info) const;
};

#endif