#include "client/two_phase_enc.h"
#include "chunker/rabin_poly.h"
#include "crypto/aate_object.h"
#include "crypto/aate_mode_selector.h"
#include "../third/xdelta/xdelta3.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

namespace {

uint32_t ReadU32(const uint8_t* in) {
    return (static_cast<uint32_t>(in[0]) << 24) |
        (static_cast<uint32_t>(in[1]) << 16) |
        (static_cast<uint32_t>(in[2]) << 8) |
        static_cast<uint32_t>(in[3]);
}

uint32_t PayloadOffset(const std::vector<uint8_t>& envelope) {
    assert(envelope.size() >= AATE_ENVELOPE_HEADER_SIZE);
    return AATE_ENVELOPE_HEADER_SIZE + ReadU32(envelope.data() + 9);
}

std::vector<uint16_t> FindBoundaries(const std::vector<uint8_t>& data) {
    RabinFPUtil rabin(48);
    RabinCtx_t ctx;
    rabin.NewCtx(ctx);
    std::vector<uint16_t> result;
    for (uint32_t i = 0; i < data.size(); ++i) {
        const uint64_t fp = rabin.SlideOneByte(ctx, data[i]);
        const uint32_t boundary = i + 1;
        if (boundary >= 48 && boundary < data.size() &&
            (fp & 0x1ff) == 0x0a5) {
            result.push_back(static_cast<uint16_t>(boundary));
        }
    }
    rabin.FreeCtx(ctx);
    return result;
}

std::vector<uint8_t> Encrypt(TwoPhaseEnc& aate, std::vector<uint8_t>& plain,
    std::vector<uint8_t>& seed) {
    std::vector<uint8_t> envelope(ENC_MAX_CHUNK_SIZE);
    const uint32_t size = aate.TwoPhaseEncChunkWithMode(plain.data(),
        plain.size(), seed.data(), envelope.data(),
        TwoPhaseEncMode::ANCHOR_ALIGNED);
    assert(size != 0);
    envelope.resize(size);
    assert(envelope.size() - PayloadOffset(envelope) == plain.size());
    return envelope;
}

std::vector<uint8_t> EncryptGlobal(TwoPhaseEnc& aate,
    std::vector<uint8_t>& plain, std::vector<uint8_t>& seed) {
    std::vector<uint8_t> object(ENC_MAX_CHUNK_SIZE);
    const uint32_t size = aate.TwoPhaseEncChunk(plain.data(), plain.size(),
        seed.data(), object.data());
    assert(size == AATE_GLOBAL_HEADER_SIZE + plain.size());
    object.resize(size);
    assert(std::memcmp(object.data(), "AATG", 4) == 0);
    AATEObjectView view;
    assert(ParseAATEObject(object.data(), object.size(), view));
    assert(view.metadata_size == AATE_GLOBAL_HEADER_SIZE);
    assert(view.payload_size == plain.size());
    return object;
}

void CheckRoundTrip(TwoPhaseEnc& aate, std::vector<uint8_t> plain,
    std::vector<uint8_t>& seed) {
    const std::vector<uint8_t> original = plain;
    std::vector<uint8_t> envelope = Encrypt(aate, plain, seed);
    std::vector<uint8_t> recovered(AATE_MAX_PLAIN_SIZE);
    const uint32_t recovered_size = aate.TwoPhaseDecChunk(envelope.data(),
        envelope.size(), seed.data(), recovered.data());
    assert(recovered_size == original.size());
    assert(std::equal(original.begin(), original.end(), recovered.begin()));

    std::vector<uint8_t> envelope_again = Encrypt(aate, plain, seed);
    assert(envelope == envelope_again);
}

} // namespace

int main() {
    PositionSketch_t reference_sketch{};
    reference_sketch.valid_count = AATE_POSITION_SKETCH_SIZE;
    for (uint32_t i = 0; i < AATE_POSITION_SKETCH_SIZE; ++i) {
        reference_sketch.hashes[i] = 0xf000000000000000ULL - i * 101;
        reference_sketch.offsets[i] = 200 + i * 500;
    }
    PositionSketch_t replacement_sketch = reference_sketch;
    assert(!ShouldUseAnchorAlignedMode(replacement_sketch, reference_sketch));

    PositionSketch_t prefix_insert_sketch = reference_sketch;
    for (uint32_t i = 0; i < AATE_POSITION_SKETCH_SIZE; ++i) {
        prefix_insert_sketch.offsets[i] += 13;
    }
    AATEShiftEvidence prefix_evidence = DetectAATEContentShift(
        prefix_insert_sketch, reference_sketch);
    assert(prefix_evidence.shifted_inliers == AATE_POSITION_SKETCH_SIZE);
    assert(prefix_evidence.displacement == 13);
    assert(ShouldUseAnchorAlignedMode(prefix_insert_sketch, reference_sketch));

    PositionSketch_t middle_insert_sketch = reference_sketch;
    for (uint32_t i = 4; i < AATE_POSITION_SKETCH_SIZE; ++i) {
        middle_insert_sketch.offsets[i] += 9;
    }
    assert(ShouldUseAnchorAlignedMode(middle_insert_sketch, reference_sketch));

    PositionSketch_t weak_evidence_sketch = reference_sketch;
    weak_evidence_sketch.valid_count = 2;
    weak_evidence_sketch.offsets[0] += 7;
    weak_evidence_sketch.offsets[1] += 7;
    assert(!ShouldUseAnchorAlignedMode(weak_evidence_sketch,
        reference_sketch));

    TwoPhaseEnc aate;
    std::vector<uint8_t> seed(CHUNK_HASH_SIZE);
    for (uint32_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i * 7 + 3);
    }

    std::mt19937 rng(0xA47E);

    // GLOBAL is the default storage-oriented mode.  It has only a five-byte
    // header, is deterministic and preserves same-offset 16-byte locality.
    std::vector<uint8_t> global_plain(1024);
    for (uint8_t& byte : global_plain) {
        byte = static_cast<uint8_t>(rng());
    }
    std::vector<uint8_t> global_object = EncryptGlobal(aate, global_plain, seed);
    std::vector<uint8_t> global_again = EncryptGlobal(aate, global_plain, seed);
    assert(global_object == global_again);
    std::vector<uint8_t> global_recovered(AATE_MAX_PLAIN_SIZE);
    assert(aate.TwoPhaseDecChunk(global_object.data(), global_object.size(),
        seed.data(), global_recovered.data()) == global_plain.size());
    assert(std::equal(global_plain.begin(), global_plain.end(),
        global_recovered.begin()));

    std::vector<uint8_t> global_changed_plain = global_plain;
    global_changed_plain[321] ^= 0x5a;
    std::vector<uint8_t> global_changed = EncryptGlobal(aate,
        global_changed_plain, seed);
    const uint32_t changed_block_start = AATE_GLOBAL_HEADER_SIZE + 320;
    assert(std::equal(global_object.begin() + AATE_GLOBAL_HEADER_SIZE,
        global_object.begin() + changed_block_start,
        global_changed.begin() + AATE_GLOBAL_HEADER_SIZE));
    assert(std::equal(global_object.begin() + changed_block_start + 16,
        global_object.end(), global_changed.begin() + changed_block_start + 16));
    assert(std::memcmp(global_object.data() + changed_block_start,
        global_changed.data() + changed_block_start, 16) != 0);

    // GLOBAL metadata also travels outside xdelta and can rebuild the object.
    AATEObjectView global_view;
    assert(ParseAATEObject(global_object.data(), global_object.size(), global_view));
    const uint8_t global_fake_delta[] = {0x31, 0x32};
    std::vector<uint8_t> global_delta(STORAGE_MAX_CHUNK_SIZE);
    uint32_t global_delta_size = 0;
    assert(BuildAATEDelta(global_view, global_fake_delta,
        sizeof(global_fake_delta), global_delta.data(), global_delta.size(),
        global_delta_size));
    assert(global_delta_size == AATE_GLOBAL_DELTA_HEADER_SIZE +
        sizeof(global_fake_delta));
    AATEDeltaView global_delta_view;
    assert(ParseAATEDelta(global_delta.data(), global_delta_size,
        global_delta_view));
    std::vector<uint8_t> global_rebuilt(ENC_MAX_CHUNK_SIZE);
    uint32_t global_rebuilt_size = 0;
    assert(BuildAATEObject(global_delta_view, global_view.payload,
        global_view.payload_size, global_rebuilt.data(), global_rebuilt.size(),
        global_rebuilt_size));
    assert(global_rebuilt_size == global_object.size());
    assert(std::equal(global_object.begin(), global_object.end(),
        global_rebuilt.begin()));

    AATEObjectView global_changed_view;
    assert(ParseAATEObject(global_changed.data(), global_changed.size(),
        global_changed_view));
    std::vector<uint8_t> global_payload_delta(ENC_MAX_CHUNK_SIZE);
    uint64_t global_payload_delta_size = 0;
    assert(xd3_encode_memory(global_changed_view.payload,
        global_changed_view.payload_size, global_view.payload,
        global_view.payload_size, global_payload_delta.data(),
        &global_payload_delta_size, global_payload_delta.size(),
        XD3_NOCOMPRESS) == 0);
    assert(BuildAATEDelta(global_changed_view, global_payload_delta.data(),
        global_payload_delta_size, global_delta.data(), global_delta.size(),
        global_delta_size));
    assert(ParseAATEDelta(global_delta.data(), global_delta_size,
        global_delta_view));
    std::vector<uint8_t> global_restored_payload(AATE_MAX_PLAIN_SIZE);
    uint64_t global_restored_payload_size = 0;
    assert(xd3_decode_memory(global_delta_view.delta,
        global_delta_view.delta_size, global_view.payload,
        global_view.payload_size, global_restored_payload.data(),
        &global_restored_payload_size, global_restored_payload.size(),
        XD3_NOCOMPRESS) == 0);
    assert(BuildAATEObject(global_delta_view, global_restored_payload.data(),
        global_restored_payload_size, global_rebuilt.data(),
        global_rebuilt.size(), global_rebuilt_size));
    assert(global_rebuilt_size == global_changed.size());
    assert(std::equal(global_changed.begin(), global_changed.end(),
        global_rebuilt.begin()));
    assert(aate.TwoPhaseDecChunk(global_rebuilt.data(), global_rebuilt_size,
        seed.data(), global_recovered.data()) == global_changed_plain.size());
    assert(std::equal(global_changed_plain.begin(), global_changed_plain.end(),
        global_recovered.begin()));

    for (uint32_t size : {1U, 15U, 16U, 17U, 47U, 48U, 49U, 1024U,
        8192U, static_cast<uint32_t>(MAX_CHUNK_SIZE),
        static_cast<uint32_t>(AATE_MAX_PLAIN_SIZE)}) {
        std::vector<uint8_t> plain(size);
        for (uint8_t& byte : plain) {
            byte = static_cast<uint8_t>(rng());
        }
        CheckRoundTrip(aate, plain, seed);
    }

    // A repeated-byte window is low entropy and must not create anchors.
    const uint64_t accepted_before_dense = aate.GetStats().accepted_anchor_count;
    std::vector<uint8_t> dense(MAX_CHUNK_SIZE, 0);
    CheckRoundTrip(aate, dense, seed);
    std::vector<uint8_t> dense_envelope = Encrypt(aate, dense, seed);
    AATEObjectView dense_view;
    assert(ParseAATEObject(dense_envelope.data(), dense_envelope.size(),
        dense_view));
    assert(dense_view.metadata_size == AATE_ENVELOPE_HEADER_SIZE + 3);
    assert(aate.GetStats().accepted_anchor_count == accepted_before_dense);

    const uint64_t accepted_before_repeated =
        aate.GetStats().accepted_anchor_count;
    std::vector<uint8_t> repeated(MAX_CHUNK_SIZE, 0x5a);
    std::vector<uint8_t> repeated_envelope = Encrypt(aate, repeated, seed);
    AATEObjectView repeated_view;
    assert(ParseAATEObject(repeated_envelope.data(), repeated_envelope.size(),
        repeated_view));
    assert(repeated_view.metadata_size == AATE_ENVELOPE_HEADER_SIZE + 3);
    assert(aate.GetStats().accepted_anchor_count == accepted_before_repeated);

    // A payload delta record carries target metadata separately; rebuilding
    // an object must preserve that metadata byte-for-byte.
    AATEObjectView object_view;
    assert(ParseAATEObject(dense_envelope.data(), dense_envelope.size(),
        object_view));
    const uint8_t fake_delta[] = {0x11, 0x22, 0x33};
    std::vector<uint8_t> delta_record(STORAGE_MAX_CHUNK_SIZE);
    uint32_t delta_record_size = 0;
    assert(BuildAATEDelta(object_view, fake_delta, sizeof(fake_delta),
        delta_record.data(), delta_record.size(), delta_record_size));
    AATEDeltaView delta_view;
    assert(ParseAATEDelta(delta_record.data(), delta_record_size, delta_view));
    std::vector<uint8_t> rebuilt(ENC_MAX_CHUNK_SIZE);
    uint32_t rebuilt_size = 0;
    assert(BuildAATEObject(delta_view, object_view.payload,
        object_view.payload_size, rebuilt.data(), rebuilt.size(), rebuilt_size));
    assert(rebuilt_size == dense_envelope.size());
    assert(std::equal(dense_envelope.begin(), dense_envelope.end(),
        rebuilt.begin()));

    // A prefix insertion must not perturb ciphertext after the first stable
    // anchor. Compare one complete aligned region in both payloads.
    std::vector<uint8_t> base(8000);
    for (uint8_t& byte : base) {
        byte = static_cast<uint8_t>(rng());
    }
    const uint32_t insert_at = 100;
    std::vector<uint8_t> inserted = base;
    const std::vector<uint8_t> prefix = {0x91, 0x22, 0x37, 0x48, 0x59,
        0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1};
    inserted.insert(inserted.begin() + insert_at, prefix.begin(), prefix.end());
    const auto base_boundaries = FindBoundaries(base);
    const auto inserted_boundaries = FindBoundaries(inserted);
    auto first = std::find_if(base_boundaries.begin(), base_boundaries.end(),
        [insert_at](uint16_t boundary) { return boundary > insert_at + 48; });
    assert(first != base_boundaries.end() && std::next(first) != base_boundaries.end());
    const uint16_t begin_a = *first;
    const uint16_t end_a = *std::next(first);
    const uint16_t begin_b = begin_a + prefix.size();
    const uint16_t end_b = end_a + prefix.size();
    assert(std::find(inserted_boundaries.begin(), inserted_boundaries.end(), begin_b) !=
        inserted_boundaries.end());
    assert(std::find(inserted_boundaries.begin(), inserted_boundaries.end(), end_b) !=
        inserted_boundaries.end());

    std::vector<uint8_t> base_envelope = Encrypt(aate, base, seed);
    std::vector<uint8_t> inserted_envelope = Encrypt(aate, inserted, seed);
    const uint8_t* payload_a = base_envelope.data() + PayloadOffset(base_envelope);
    const uint8_t* payload_b = inserted_envelope.data() + PayloadOffset(inserted_envelope);
    assert(end_a - begin_a == end_b - begin_b);
    assert(std::memcmp(payload_a + begin_a, payload_b + begin_b,
        end_a - begin_a) == 0);

    // End-to-end payload-only xdelta: metadata is excluded from xdelta,
    // stored with the target, and attached again before AATE decryption.
    AATEObjectView base_view;
    AATEObjectView inserted_view;
    assert(ParseAATEObject(base_envelope.data(), base_envelope.size(), base_view));
    assert(ParseAATEObject(inserted_envelope.data(), inserted_envelope.size(),
        inserted_view));
    std::vector<uint8_t> payload_delta(ENC_MAX_CHUNK_SIZE);
    uint64_t payload_delta_size = 0;
    assert(xd3_encode_memory(inserted_view.payload, inserted_view.payload_size,
        base_view.payload, base_view.payload_size, payload_delta.data(),
        &payload_delta_size, payload_delta.size(), XD3_NOCOMPRESS) == 0);
    std::vector<uint8_t> stored_delta(STORAGE_MAX_CHUNK_SIZE);
    uint32_t stored_delta_size = 0;
    assert(BuildAATEDelta(inserted_view, payload_delta.data(),
        payload_delta_size, stored_delta.data(), stored_delta.size(),
        stored_delta_size));
    AATEDeltaView stored_delta_view;
    assert(ParseAATEDelta(stored_delta.data(), stored_delta_size,
        stored_delta_view));
    std::vector<uint8_t> restored_payload(AATE_MAX_PLAIN_SIZE);
    uint64_t restored_payload_size = 0;
    assert(xd3_decode_memory(stored_delta_view.delta,
        stored_delta_view.delta_size, base_view.payload, base_view.payload_size,
        restored_payload.data(), &restored_payload_size,
        restored_payload.size(), XD3_NOCOMPRESS) == 0);
    std::vector<uint8_t> restored_object(ENC_MAX_CHUNK_SIZE);
    uint32_t restored_object_size = 0;
    assert(BuildAATEObject(stored_delta_view, restored_payload.data(),
        restored_payload_size, restored_object.data(), restored_object.size(),
        restored_object_size));
    assert(restored_object_size == inserted_envelope.size());
    assert(std::equal(inserted_envelope.begin(), inserted_envelope.end(),
        restored_object.begin()));
    std::vector<uint8_t> restored_plain(AATE_MAX_PLAIN_SIZE);
    assert(aate.TwoPhaseDecChunk(restored_object.data(), restored_object_size,
        seed.data(), restored_plain.data()) == inserted.size());
    assert(std::equal(inserted.begin(), inserted.end(), restored_plain.begin()));

    // Deletion has the same re-synchronization property in the other
    // direction.
    const uint32_t delete_size = 13;
    std::vector<uint8_t> deleted = base;
    deleted.erase(deleted.begin() + insert_at,
        deleted.begin() + insert_at + delete_size);
    const auto deleted_boundaries = FindBoundaries(deleted);
    auto delete_first = std::find_if(base_boundaries.begin(), base_boundaries.end(),
        [insert_at, delete_size](uint16_t boundary) {
            return boundary > insert_at + delete_size + 48;
        });
    assert(delete_first != base_boundaries.end() &&
        std::next(delete_first) != base_boundaries.end());
    const uint16_t delete_begin_a = *delete_first;
    const uint16_t delete_end_a = *std::next(delete_first);
    const uint16_t delete_begin_b = delete_begin_a - delete_size;
    const uint16_t delete_end_b = delete_end_a - delete_size;
    assert(std::find(deleted_boundaries.begin(), deleted_boundaries.end(),
        delete_begin_b) != deleted_boundaries.end());
    assert(std::find(deleted_boundaries.begin(), deleted_boundaries.end(),
        delete_end_b) != deleted_boundaries.end());
    std::vector<uint8_t> deleted_envelope = Encrypt(aate, deleted, seed);
    const uint8_t* payload_deleted = deleted_envelope.data() +
        PayloadOffset(deleted_envelope);
    assert(std::memcmp(payload_a + delete_begin_a,
        payload_deleted + delete_begin_b, delete_end_a - delete_begin_a) == 0);

    // Recipe authentication and group-key binding.
    std::vector<uint8_t> tampered = base_envelope;
    tampered[25] ^= 1;
    std::vector<uint8_t> recovered(AATE_MAX_PLAIN_SIZE);
    assert(aate.TwoPhaseDecChunk(tampered.data(), tampered.size(), seed.data(),
        recovered.data()) == 0);
    std::vector<uint8_t> wrong_seed = seed;
    wrong_seed[0] ^= 1;
    assert(aate.TwoPhaseDecChunk(base_envelope.data(), base_envelope.size(),
        wrong_seed.data(), recovered.data()) == 0);

    std::cout << "AATE tests passed\n";
    return 0;
}
