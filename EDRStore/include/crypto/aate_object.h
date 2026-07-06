#ifndef EDRSTORE_AATE_OBJECT_H
#define EDRSTORE_AATE_OBJECT_H

#include "../const_var.h"

#include <cstdint>
#include <cstring>

enum class AATEObjectMode : uint8_t {
    GLOBAL = 0,
    ANCHOR_ALIGNED = 1,
};

struct AATEObjectView {
    const uint8_t* metadata = nullptr;
    uint32_t metadata_size = 0;
    const uint8_t* payload = nullptr;
    uint32_t payload_size = 0;
    AATEObjectMode mode = AATEObjectMode::GLOBAL;
};

struct AATEDeltaView {
    const uint8_t* metadata = nullptr;
    uint32_t metadata_size = 0;
    const uint8_t* delta = nullptr;
    uint32_t delta_size = 0;
    uint32_t payload_size = 0;
    AATEObjectMode mode = AATEObjectMode::ANCHOR_ALIGNED;
};

inline uint32_t AATEReadU32(const uint8_t* in) {
    return (static_cast<uint32_t>(in[0]) << 24) |
        (static_cast<uint32_t>(in[1]) << 16) |
        (static_cast<uint32_t>(in[2]) << 8) |
        static_cast<uint32_t>(in[3]);
}

inline void AATEWriteU32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>(value >> 24);
    out[1] = static_cast<uint8_t>(value >> 16);
    out[2] = static_cast<uint8_t>(value >> 8);
    out[3] = static_cast<uint8_t>(value);
}

inline bool ParseAATEObject(const uint8_t* object, uint32_t object_size,
    AATEObjectView& view) {
    static constexpr uint8_t kAATEMagic[4] = {'A', 'A', 'T', 'E'};
    static constexpr uint8_t kGlobalMagic[4] = {'A', 'A', 'T', 'G'};
    if (object == nullptr || object_size <= AATE_GLOBAL_HEADER_SIZE ||
        object[4] != 1) {
        return false;
    }
    if (std::memcmp(object, kGlobalMagic, sizeof(kGlobalMagic)) == 0) {
        const uint32_t payload_size = object_size - AATE_GLOBAL_HEADER_SIZE;
        if (payload_size > AATE_MAX_PLAIN_SIZE) {
            return false;
        }
        view.metadata = object;
        view.metadata_size = AATE_GLOBAL_HEADER_SIZE;
        view.payload = object + AATE_GLOBAL_HEADER_SIZE;
        view.payload_size = payload_size;
        view.mode = AATEObjectMode::GLOBAL;
        return true;
    }
    if (object_size < AATE_ENVELOPE_HEADER_SIZE ||
        std::memcmp(object, kAATEMagic, sizeof(kAATEMagic)) != 0) {
        return false;
    }
    const uint32_t payload_size = AATEReadU32(object + 5);
    const uint32_t recipe_size = AATEReadU32(object + 9);
    const uint32_t metadata_size = AATE_ENVELOPE_HEADER_SIZE + recipe_size;
    if (payload_size == 0 || payload_size > AATE_MAX_PLAIN_SIZE ||
        recipe_size == 0 || recipe_size > AATE_MAX_RECIPE_SIZE ||
        metadata_size > object_size || object_size - metadata_size != payload_size) {
        return false;
    }
    view.metadata = object;
    view.metadata_size = metadata_size;
    view.payload = object + metadata_size;
    view.payload_size = payload_size;
    view.mode = AATEObjectMode::ANCHOR_ALIGNED;
    return true;
}

inline void AATEDomainSeparateFeatures(const AATEObjectView& view,
    uint64_t* features, uint32_t feature_count) {
    const uint64_t domain = view.mode == AATEObjectMode::GLOBAL
        ? 0x474c4f42414c7631ULL  // "GLOBALv1"
        : 0x414e43484f527631ULL; // "ANCHORv1"
    for (uint32_t i = 0; i < feature_count; ++i) {
        features[i] ^= domain;
    }
}

inline bool ParseAATEDelta(const uint8_t* record, uint32_t record_size,
    AATEDeltaView& view) {
    static constexpr uint8_t kMagic[4] = {'A', 'A', 'D', 'L'};
    static constexpr uint8_t kGlobalDeltaMagic[4] = {'G', 'D', 'L', 'T'};
    static constexpr uint8_t kAATEMagic[4] = {'A', 'A', 'T', 'E'};
    static constexpr uint8_t kGlobalMagic[4] = {'A', 'A', 'T', 'G'};
    if (record == nullptr || record_size <= AATE_GLOBAL_DELTA_HEADER_SIZE) {
        return false;
    }
    if (std::memcmp(record, kGlobalDeltaMagic,
            sizeof(kGlobalDeltaMagic)) == 0 && record[4] == 1) {
        view.metadata = nullptr;
        view.metadata_size = 0;
        view.delta = record + AATE_GLOBAL_DELTA_HEADER_SIZE;
        view.delta_size = record_size - AATE_GLOBAL_DELTA_HEADER_SIZE;
        view.payload_size = 0; // learned from xdelta decode
        view.mode = AATEObjectMode::GLOBAL;
        return view.delta_size <= ENC_MAX_CHUNK_SIZE;
    }
    if (record_size < AATE_DELTA_HEADER_SIZE ||
        std::memcmp(record, kMagic, sizeof(kMagic)) != 0 || record[4] != 1) {
        return false;
    }
    const uint32_t metadata_size = AATEReadU32(record + 5);
    const uint32_t payload_size = AATEReadU32(record + 9);
    const uint32_t delta_size = AATEReadU32(record + 13);
    if (metadata_size < AATE_GLOBAL_HEADER_SIZE ||
        metadata_size > AATE_ENVELOPE_HEADER_SIZE + AATE_MAX_RECIPE_SIZE ||
        payload_size == 0 || payload_size > AATE_MAX_PLAIN_SIZE ||
        delta_size > ENC_MAX_CHUNK_SIZE ||
        record_size != AATE_DELTA_HEADER_SIZE + metadata_size + delta_size) {
        return false;
    }
    const uint8_t* metadata = record + AATE_DELTA_HEADER_SIZE;
    const bool global_metadata = metadata_size == AATE_GLOBAL_HEADER_SIZE &&
        std::memcmp(metadata, kGlobalMagic, sizeof(kGlobalMagic)) == 0 &&
        metadata[4] == 1;
    const bool aate_metadata = metadata_size >= AATE_ENVELOPE_HEADER_SIZE &&
        std::memcmp(metadata, kAATEMagic, sizeof(kAATEMagic)) == 0 &&
        metadata[4] == 1 && AATEReadU32(metadata + 5) == payload_size &&
        AATE_ENVELOPE_HEADER_SIZE + AATEReadU32(metadata + 9) == metadata_size;
    if (!global_metadata && !aate_metadata) {
        return false;
    }
    view.metadata = metadata;
    view.metadata_size = metadata_size;
    view.delta = view.metadata + metadata_size;
    view.delta_size = delta_size;
    view.payload_size = payload_size;
    view.mode = global_metadata ? AATEObjectMode::GLOBAL
                                : AATEObjectMode::ANCHOR_ALIGNED;
    return true;
}

inline bool BuildAATEDelta(const AATEObjectView& target, const uint8_t* delta,
    uint32_t delta_size, uint8_t* output, uint32_t output_capacity,
    uint32_t& output_size) {
    if (target.mode == AATEObjectMode::GLOBAL) {
        const uint32_t required = AATE_GLOBAL_DELTA_HEADER_SIZE + delta_size;
        if (delta == nullptr || output == nullptr || delta_size == 0 ||
            delta_size > ENC_MAX_CHUNK_SIZE || required > output_capacity) {
            return false;
        }
        static constexpr uint8_t kGlobalDeltaMagic[4] = {'G', 'D', 'L', 'T'};
        std::memcpy(output, kGlobalDeltaMagic, sizeof(kGlobalDeltaMagic));
        output[4] = 1;
        std::memcpy(output + AATE_GLOBAL_DELTA_HEADER_SIZE, delta, delta_size);
        output_size = required;
        return true;
    }
    const uint32_t required = AATE_DELTA_HEADER_SIZE + target.metadata_size +
        delta_size;
    if (delta == nullptr || output == nullptr || delta_size > ENC_MAX_CHUNK_SIZE ||
        required > output_capacity) {
        return false;
    }
    static constexpr uint8_t kMagic[4] = {'A', 'A', 'D', 'L'};
    std::memcpy(output, kMagic, sizeof(kMagic));
    output[4] = 1;
    AATEWriteU32(output + 5, target.metadata_size);
    AATEWriteU32(output + 9, target.payload_size);
    AATEWriteU32(output + 13, delta_size);
    std::memcpy(output + AATE_DELTA_HEADER_SIZE, target.metadata,
        target.metadata_size);
    std::memcpy(output + AATE_DELTA_HEADER_SIZE + target.metadata_size, delta,
        delta_size);
    output_size = required;
    return true;
}

inline bool BuildAATEObject(const AATEDeltaView& delta_view,
    const uint8_t* payload, uint32_t payload_size, uint8_t* output,
    uint32_t output_capacity, uint32_t& output_size) {
    if (delta_view.mode == AATEObjectMode::GLOBAL) {
        const uint32_t required = AATE_GLOBAL_HEADER_SIZE + payload_size;
        if (payload == nullptr || output == nullptr || payload_size == 0 ||
            payload_size > AATE_MAX_PLAIN_SIZE || required > output_capacity) {
            return false;
        }
        static constexpr uint8_t kGlobalMagic[4] = {'A', 'A', 'T', 'G'};
        std::memcpy(output, kGlobalMagic, sizeof(kGlobalMagic));
        output[4] = 1;
        std::memcpy(output + AATE_GLOBAL_HEADER_SIZE, payload, payload_size);
        output_size = required;
        return true;
    }
    const uint32_t required = delta_view.metadata_size + payload_size;
    if (payload == nullptr || output == nullptr ||
        payload_size != delta_view.payload_size || required > output_capacity) {
        return false;
    }
    std::memcpy(output, delta_view.metadata, delta_view.metadata_size);
    std::memcpy(output + delta_view.metadata_size, payload, payload_size);
    output_size = required;
    return true;
}

#endif
