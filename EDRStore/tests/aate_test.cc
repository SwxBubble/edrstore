#include "client/two_phase_enc.h"
#include "chunker/rabin_poly.h"

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
        if (boundary >= 48 && boundary < data.size() && (fp & 0x3ff) == 0) {
            result.push_back(static_cast<uint16_t>(boundary));
        }
    }
    rabin.FreeCtx(ctx);
    return result;
}

std::vector<uint8_t> Encrypt(TwoPhaseEnc& aate, std::vector<uint8_t>& plain,
    std::vector<uint8_t>& seed) {
    std::vector<uint8_t> envelope(ENC_MAX_CHUNK_SIZE);
    const uint32_t size = aate.TwoPhaseEncChunk(plain.data(), plain.size(),
        seed.data(), envelope.data());
    assert(size != 0);
    envelope.resize(size);
    assert(envelope.size() - PayloadOffset(envelope) == plain.size());
    return envelope;
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
    TwoPhaseEnc aate;
    std::vector<uint8_t> seed(CHUNK_HASH_SIZE);
    for (uint32_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i * 7 + 3);
    }

    std::mt19937 rng(0xA47E);
    for (uint32_t size : {1U, 15U, 16U, 17U, 47U, 48U, 49U, 1024U,
        8192U, static_cast<uint32_t>(MAX_CHUNK_SIZE),
        static_cast<uint32_t>(AATE_MAX_PLAIN_SIZE)}) {
        std::vector<uint8_t> plain(size);
        for (uint8_t& byte : plain) {
            byte = static_cast<uint8_t>(rng());
        }
        CheckRoundTrip(aate, plain, seed);
    }

    // Worst-case dense anchors (all-zero Rabin windows) must select bitmap
    // metadata, stay within ENC_MAX_CHUNK_SIZE, and remain reversible.
    std::vector<uint8_t> dense(MAX_CHUNK_SIZE, 0);
    CheckRoundTrip(aate, dense, seed);

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
