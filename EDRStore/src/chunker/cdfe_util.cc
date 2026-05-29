/**
 * @file cdfe_util.cc
 * @brief CDFE set-order feature extractor for EDRStore.
 */

#include "../../include/chunker/cdfe_util.h"
#include "../../include/chunker/fastcdc_chunker.h"
#include "../../include/chunker/xxhash64.h"

#include <algorithm>
#include <cmath>
#include <vector>

namespace {

static inline uint64_t GearValue(uint8_t byte) {
    return static_cast<uint64_t>(GEAR[byte]);
}

static inline uint64_t Mix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static inline uint64_t GearUpdate(uint64_t fp, uint8_t byte) {
    return (fp << 1) + GearValue(byte);
}

static inline bool IsBoundary(uint64_t fp, uint64_t mask) {
    if (mask == 0) {
        return false;
    }
    return (Mix64(fp) & mask) == 0;
}

static inline uint64_t HashBytes(const uint8_t* data, int len) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

static inline uint64_t GearWindowInit(const uint8_t* data, int window_size) {
    uint64_t h = 0;
    for (int i = 0; i < window_size; ++i) {
        h = (h << 1) + GearValue(data[i]);
    }
    return h;
}

static inline uint64_t GearWindowRoll(uint64_t prev, uint8_t out_byte,
    uint8_t in_byte, int window_size) {
    const uint64_t out_contrib = GearValue(out_byte) << (window_size - 1);
    uint64_t h = prev - out_contrib;
    h = (h << 1) + GearValue(in_byte);
    return h;
}

}

CDFEUtil::CDFEUtil() {
}

CDFEUtil::~CDFEUtil() {
}

uint64_t CDFEUtil::ExtractOneLocalFeature(const uint8_t* data, int size) const {
    if (size <= 0) {
        return 0;
    }

    int window_size = feature_window_size_;
    if (window_size <= 0) {
        return Mix64(HashBytes(data, size));
    }
    if (window_size >= 64) {
        window_size = 63;
    }
    if (size < window_size) {
        return Mix64(HashBytes(data, size));
    }

    const int window_count = size - window_size + 1;
    uint64_t fp = GearWindowInit(data, window_size);
    uint64_t min_hash = Mix64(fp);

    for (int off = 1; off < window_count; ++off) {
        fp = GearWindowRoll(fp, data[off - 1],
            data[off + window_size - 1], window_size);
        const uint64_t h = Mix64(fp);
        if (h < min_hash) {
            min_hash = h;
        }
    }

    return min_hash;
}

void CDFEUtil::ExtractFeature(uint8_t* data, uint32_t size,
    uint64_t* compact_features, uint32_t* cdfe_feature_num,
    CDFEFeature_t* cdfe_features) {
    for (uint32_t i = 0; i < SUPER_FEATURE_PER_CHUNK; ++i) {
        compact_features[i] = 0;
    }
    *cdfe_feature_num = 0;

    if (data == nullptr || size == 0) {
        return;
    }

    uint32_t out_num = 0;
    uint32_t start = 0;
    uint16_t rank = 0;

    while (start < size && out_num < CDFE_MAX_FEATURE_PER_CHUNK) {
        const uint32_t remain = size - start;
        uint32_t cut = size;

        if (remain > static_cast<uint32_t>(max_subblock_size_)) {
            const uint32_t min_pos = std::min<uint32_t>(
                start + min_subblock_size_, size);
            const uint32_t avg_pos = std::min<uint32_t>(
                start + avg_subblock_size_, size);
            const uint32_t max_pos = std::min<uint32_t>(
                start + max_subblock_size_, size);

            std::vector<uint64_t> fps(max_pos - min_pos + 1);
            uint64_t fp = 0;
            for (uint32_t pos = start; pos < min_pos; ++pos) {
                fp = GearUpdate(fp, data[pos]);
            }
            fps[0] = fp;

            for (uint32_t pos = min_pos + 1; pos <= max_pos; ++pos) {
                fp = GearUpdate(fp, data[pos - 1]);
                fps[pos - min_pos] = fp;
            }

            int found_cut = -1;
            int left = static_cast<int>(avg_pos);
            int right = static_cast<int>(avg_pos) + 1;
            while (left >= static_cast<int>(min_pos) ||
                right <= static_cast<int>(max_pos)) {
                if (left >= static_cast<int>(min_pos) &&
                    IsBoundary(fps[left - min_pos], boundary_mask_)) {
                    found_cut = left;
                    break;
                }
                if (right <= static_cast<int>(max_pos) &&
                    IsBoundary(fps[right - min_pos], boundary_mask_)) {
                    found_cut = right;
                    break;
                }
                --left;
                ++right;
            }

            cut = found_cut > 0 ? static_cast<uint32_t>(found_cut) : max_pos;
        }

        if (cut <= start) {
            cut = std::min<uint32_t>(start + max_subblock_size_, size);
        }

        const uint32_t subblock_len = cut - start;
        cdfe_features[out_num].value =
            ExtractOneLocalFeature(data + start, subblock_len);
        cdfe_features[out_num].subblock_rank = rank;
        cdfe_features[out_num].norm_pos =
            static_cast<float>(start + subblock_len * 0.5f) /
            static_cast<float>(size);

        ++out_num;
        ++rank;
        start = cut;
    }

    *cdfe_feature_num = out_num;

    for (uint32_t group = 0; group < SUPER_FEATURE_PER_CHUNK; ++group) {
        std::vector<uint64_t> vals;
        for (uint32_t i = group; i < out_num; i += SUPER_FEATURE_PER_CHUNK) {
            vals.push_back(cdfe_features[i].value);
        }
        if (!vals.empty()) {
            compact_features[group] = XXHash64::hash(
                reinterpret_cast<uint8_t*>(vals.data()),
                vals.size() * sizeof(uint64_t), 0);
        }
    }
}
