#ifndef EDRSTORE_AATE_MODE_SELECTOR_H
#define EDRSTORE_AATE_MODE_SELECTOR_H

#include "../data_structure.h"

#include <algorithm>
#include <cstdint>
#include <vector>

struct AATEShiftEvidence {
    uint32_t matched_landmarks = 0;
    uint32_t shifted_inliers = 0;
    int32_t displacement = 0;
};

inline AATEShiftEvidence DetectAATEContentShift(
    const PositionSketch_t& current, const PositionSketch_t& reference) {
    AATEShiftEvidence evidence;
    std::vector<int32_t> shifted_displacements;
    const uint32_t current_count = std::min<uint32_t>(current.valid_count,
        AATE_POSITION_SKETCH_SIZE);
    const uint32_t reference_count = std::min<uint32_t>(reference.valid_count,
        AATE_POSITION_SKETCH_SIZE);
    for (uint32_t i = 0; i < current_count; ++i) {
        for (uint32_t j = 0; j < reference_count; ++j) {
            if (current.hashes[i] != reference.hashes[j]) {
                continue;
            }
            evidence.matched_landmarks++;
            const int32_t displacement = static_cast<int32_t>(
                current.offsets[i]) - static_cast<int32_t>(reference.offsets[j]);
            if (displacement != 0) {
                shifted_displacements.push_back(displacement);
            }
            break;
        }
    }
    if (evidence.matched_landmarks < 4 || shifted_displacements.size() < 3) {
        return evidence;
    }

    std::sort(shifted_displacements.begin(), shifted_displacements.end());
    uint32_t best_begin = 0;
    uint32_t best_count = 0;
    uint32_t begin = 0;
    for (uint32_t end = 0; end < shifted_displacements.size(); ++end) {
        while (shifted_displacements[end] - shifted_displacements[begin] > 2) {
            begin++;
        }
        const uint32_t count = end - begin + 1;
        if (count > best_count) {
            best_begin = begin;
            best_count = count;
        }
    }
    // Require a conservative, coherent shift: at least three landmarks and
    // at least one third of all matched landmarks must support it.
    if (best_count >= 3 && best_count * 3 >= evidence.matched_landmarks) {
        evidence.shifted_inliers = best_count;
        evidence.displacement = shifted_displacements[
            best_begin + best_count / 2];
    }
    return evidence;
}

inline bool ShouldUseAnchorAlignedMode(const PositionSketch_t& current,
    const PositionSketch_t& reference) {
    return DetectAATEContentShift(current, reference).shifted_inliers != 0;
}

#endif
