#ifndef EDRSTORE_ODESS_SUBFEATURE_H
#define EDRSTORE_ODESS_SUBFEATURE_H

#include "../const_var.h"
#include "../define.h"

class OdessSubfeatureExtractor {
    public:
        OdessSubfeatureExtractor() = default;
        ~OdessSubfeatureExtractor() = default;

        // Fills features[SUB_FEATURE_PER_CHUNK] with the 12 odess sub-features
        // of the input buffer. Stateless; safe to call concurrently.
        void ExtractFeature(const uint8_t* data, uint32_t size, uint64_t* features);
};

#endif
