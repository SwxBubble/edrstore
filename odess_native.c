/* odess_native.c - Native sub-feature extraction for the validation script.
 * Compiled to libodess_native.so by delta_domain_compare.py on first import.
 *
 * Mirrors EDRStore/src/chunker/odess_subfeature.cc bit-for-bit.
 *
 * Build:
 *   gcc -O3 -shared -fPIC -o libodess_native.so odess_native.c
 */
#include <stdint.h>
#include <string.h>

#include "EDRStore/include/chunker/gear_table.h"

static const uint32_t M[12] = {
    0x5b49898a, 0xe4f94e27, 0x95f658b2, 0x8f9c99fc,
    0xeba8d4d8, 0xba2c8e92, 0xa868aeb4, 0xd767df82,
    0x843606a4, 0xc1e70129, 0x32d9d1b0, 0xeb91e53c,
};

static const uint32_t A[12] = {
    0x0ff4be8c, 0x6f485986, 0x012843ff, 0x5b47dc4d,
    0x7faa9b8a, 0xd547b8ba, 0xf9979921, 0x4f5400da,
    0x725f79a9, 0x3c9321ac, 0x0032716d, 0x3f5adf5d,
};

/* features must point to uint64_t[12]; will be zeroed and filled. */
extern "C" void odess_extract(const uint8_t* data, uint32_t size, uint64_t* features) {
    for (uint32_t j = 0; j < 12; j++) features[j] = 0;
    uint32_t fp = 0;
    for (uint32_t i = 0; i < size; i++) {
        fp = (fp << 1) + (uint32_t)GEAR_TABLE[data[i]];
        if ((fp & 0x7FULL) == 0) {
            for (uint32_t j = 0; j < 12; j++) {
                uint32_t t = M[j] * fp + A[j];
                uint64_t t64 = (uint64_t)t;
                if (features[j] == 0 || features[j] >= t64) {
                    features[j] = t64;
                }
            }
        }
    }
}
