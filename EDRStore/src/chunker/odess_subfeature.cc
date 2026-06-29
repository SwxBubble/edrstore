#include "../../include/chunker/odess_subfeature.h"
#include "../../include/chunker/gear_table.h"

namespace {

// 12 (M, A) coefficient pairs from Muti-delta-methods/feature/features.cpp:45-53.
// They define the parallel linear transforms used to sketch the rolling Gear hash
// into 12 independent sub-feature slots.
constexpr uint32_t kOdessM[SUB_FEATURE_PER_CHUNK] = {
    0x5b49898a, 0xe4f94e27, 0x95f658b2, 0x8f9c99fc,
    0xeba8d4d8, 0xba2c8e92, 0xa868aeb4, 0xd767df82,
    0x843606a4, 0xc1e70129, 0x32d9d1b0, 0xeb91e53c,
};

constexpr uint32_t kOdessA[SUB_FEATURE_PER_CHUNK] = {
    0x0ff4be8c, 0x6f485986, 0x012843ff, 0x5b47dc4d,
    0x7faa9b8a, 0xd547b8ba, 0xf9979921, 0x4f5400da,
    0x725f79a9, 0x3c9321ac, 0x0032716d, 0x3f5adf5d,
};

}  // namespace

void OdessSubfeatureExtractor::ExtractFeature(const uint8_t* data,
    uint32_t size, uint64_t* features) {
    for (uint32_t j = 0; j < SUB_FEATURE_PER_CHUNK; j++) {
        features[j] = 0;
    }

    // Upstream truncates Gear fingerprint and transform to uint32_t; we preserve
    // that for byte-for-byte parity with Muti-delta-methods/feature/features.cpp.
    uint32_t finger_print = 0;
    for (uint32_t i = 0; i < size; i++) {
        finger_print = (finger_print << 1) +
            static_cast<uint32_t>(GEAR_TABLE[data[i]]);
        if ((finger_print & ODESS_SAMPLE_MASK) == 0) {
            for (uint32_t j = 0; j < SUB_FEATURE_PER_CHUNK; j++) {
                const uint32_t transform = kOdessM[j] * finger_print + kOdessA[j];
                const uint64_t transform64 = static_cast<uint64_t>(transform);
                if (features[j] == 0 || features[j] >= transform64) {
                    features[j] = transform64;
                }
            }
        }
    }
}
