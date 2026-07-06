#include "chunker/finesse_util.h"
#include "crypto/aate_mode_selector.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

Configure config("config.json");

namespace {

PositionSketch_t Sketch(FinesseUtil& finesse, RabinCtx_t& ctx,
    std::vector<uint8_t>& data) {
    PositionSketch_t sketch{};
    finesse.ExtractPositionSketch(ctx, data.data(), data.size(), sketch);
    return sketch;
}

} // namespace

int main() {
    FinesseUtil finesse(SUPER_FEATURE_PER_CHUNK, FEATURE_PER_CHUNK,
        FEATURE_PER_SUPER_FEATURE);
    RabinFPUtil rabin(config.GetSimilarSlidingWinSize());
    RabinCtx_t ctx;
    rabin.NewCtx(ctx);

    std::mt19937 rng(0x51f7);
    std::vector<uint8_t> base(8192);
    for (uint8_t& byte : base) {
        byte = static_cast<uint8_t>(rng());
    }
    PositionSketch_t base_sketch = Sketch(finesse, ctx, base);
    assert(base_sketch.valid_count == AATE_POSITION_SKETCH_SIZE);

    std::vector<uint8_t> replacement = base;
    for (uint32_t i = 3000; i < 3020; ++i) {
        replacement[i] ^= 0x5a;
    }
    PositionSketch_t replacement_sketch = Sketch(finesse, ctx, replacement);
    assert(!ShouldUseAnchorAlignedMode(replacement_sketch, base_sketch));

    std::vector<uint8_t> inserted = base;
    const std::vector<uint8_t> insertion = {0x91, 0x22, 0x37, 0x48, 0x59,
        0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1};
    inserted.insert(inserted.begin() + 100, insertion.begin(), insertion.end());
    PositionSketch_t inserted_sketch = Sketch(finesse, ctx, inserted);
    AATEShiftEvidence evidence = DetectAATEContentShift(inserted_sketch,
        base_sketch);
    assert(evidence.matched_landmarks >= 4);
    assert(evidence.shifted_inliers >= 3);
    assert(evidence.displacement == static_cast<int32_t>(insertion.size()));

    std::vector<uint8_t> deleted = base;
    deleted.erase(deleted.begin() + 100, deleted.begin() + 113);
    PositionSketch_t deleted_sketch = Sketch(finesse, ctx, deleted);
    evidence = DetectAATEContentShift(deleted_sketch, base_sketch);
    assert(evidence.shifted_inliers >= 3);
    assert(evidence.displacement == -13);

    rabin.FreeCtx(ctx);
    std::cout << "Position sketch tests passed\n";
    return 0;
}
