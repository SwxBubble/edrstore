#include "../../include/reduction/cdfe_feature.h"
#include "../../include/reduction/gear_table.h"

#include <algorithm>
#include <limits>

CDFEFeatureExtractor::CDFEFeatureExtractor() {}

CDFEFeatureExtractor::CDFEFeatureExtractor(const CDFEParams& params) {
    params_ = params;
}

uint64_t CDFEFeatureExtractor::Mix64(uint64_t x) const {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

uint64_t CDFEFeatureExtractor::GearUpdate(uint64_t fp, uint8_t byte) const {
    return (fp << 1) + GEAR_TABLE[byte];
}

bool CDFEFeatureExtractor::IsBoundary(uint64_t fp) const {
    if (params_.boundary_mask == 0) {
        return false;
    }
    return (Mix64(fp) & params_.boundary_mask) == 0;
}

uint64_t CDFEFeatureExtractor::HashBytes(const uint8_t* data, int len) const {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t CDFEFeatureExtractor::HashWindow(const uint8_t* data, int len) const {
    uint64_t h = 0;
    for (int i = 0; i < len; ++i) {
        h = (h << 1) + GEAR_TABLE[data[i]];
    }
    return h;
}

uint64_t CDFEFeatureExtractor::ExtractOneLocalFeature(
    const uint8_t* data,
    int len
) const {
    if (len <= 0) {
        return 0;
    }

    if (len < params_.feature_window_size) {
        return Mix64(HashBytes(data, len));
    }

    const int window_num = len - params_.feature_window_size + 1;
    uint64_t min_h = std::numeric_limits<uint64_t>::max();

    for (int off = 0; off < window_num; ++off) {
        uint64_t h = HashWindow(data + off, params_.feature_window_size);
        h = Mix64(h);
        if (h < min_h) {
            min_h = h;
        }
    }

    if (min_h == std::numeric_limits<uint64_t>::max()) {
        min_h = Mix64(HashBytes(data, len));
    }

    return min_h;
}

std::vector<CDFESubblockSpan> CDFEFeatureExtractor::SplitIntoSubblocks(
    const uint8_t* buf,
    int chunk_len
) const {
    std::vector<CDFESubblockSpan> res;

    if (buf == nullptr || chunk_len <= 0) {
        return res;
    }

    int start = 0;
    int rank = 0;

    while (start < chunk_len) {
        const int remain = chunk_len - start;

        if (remain <= params_.max_subblock_size) {
            res.push_back({start, remain, rank});
            break;
        }

        const int min_pos = std::min(start + params_.min_subblock_size, chunk_len);
        const int avg_pos = std::min(start + params_.avg_subblock_size, chunk_len);
        const int max_pos = std::min(start + params_.max_subblock_size, chunk_len);

        int cut = -1;

        std::vector<uint64_t> fps(max_pos - min_pos + 1);

        uint64_t fp = 0;
        for (int pos = start; pos < min_pos; ++pos) {
            fp = GearUpdate(fp, buf[pos]);
        }
        fps[0] = fp;

        for (int pos = min_pos + 1; pos <= max_pos; ++pos) {
            fp = GearUpdate(fp, buf[pos - 1]);
            fps[pos - min_pos] = fp;
        }

        auto boundary_at = [&](int pos) -> bool {
            if (pos < min_pos || pos > max_pos) {
                return false;
            }
            return IsBoundary(fps[pos - min_pos]);
        };

        int left = avg_pos;
        int right = avg_pos + 1;

        while (left >= min_pos || right <= max_pos) {
            if (left >= min_pos && boundary_at(left)) {
                cut = left;
                break;
            }

            if (right <= max_pos && boundary_at(right)) {
                cut = right;
                break;
            }

            --left;
            ++right;
        }

        if (cut == -1) {
            cut = max_pos;
        }

        if (cut <= start) {
            cut = std::min(start + params_.max_subblock_size, chunk_len);
        }

        res.push_back({start, cut - start, rank});

        start = cut;
        rank++;

        if (static_cast<int>(res.size()) >= MAX_CDFE_FEATURES) {
            break;
        }
    }

    return res;
}

void CDFEFeatureExtractor::Extract(
    const uint8_t* buf,
    int len,
    ChunkInfo_t* info
) const {
    if (info == nullptr) {
        return;
    }

    info->cdfe_feature_num = 0;

    if (buf == nullptr || len <= 0) {
        return;
    }

    auto subblocks = SplitIntoSubblocks(buf, len);

    for (const auto& sb : subblocks) {
        if (info->cdfe_feature_num >= MAX_CDFE_FEATURES) {
            break;
        }

        const uint8_t* sbuf = buf + sb.start;
        const int slen = sb.len;

        uint64_t one_feature = ExtractOneLocalFeature(sbuf, slen);

        float norm_pos = 0.0f;
        if (len > 0) {
            norm_pos = static_cast<float>(sb.start + sb.len * 0.5f) /
                       static_cast<float>(len);
        }

        auto& dst = info->cdfe_features[info->cdfe_feature_num++];
        dst.value = one_feature;
        dst.subblock_rank = static_cast<uint16_t>(sb.rank);
        dst.norm_pos = norm_pos;
    }
}