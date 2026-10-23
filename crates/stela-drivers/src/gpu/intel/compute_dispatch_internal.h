/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_COMPUTE_DISPATCH_INTERNAL_H
#define STELA_INTEL_COMPUTE_DISPATCH_INTERNAL_H
#include "compute_dispatch.h"

struct stela_intel_compute_encoder {
    size_t words;
    void (*pack)(uint32_t *, const struct stela_intel_compute_dispatch *);
};
extern const struct stela_intel_compute_encoder stela_intel_compute_encoder_125;
extern const struct stela_intel_compute_encoder stela_intel_compute_encoder_200;
extern const struct stela_intel_compute_encoder stela_intel_compute_encoder_300;
extern const struct stela_intel_compute_encoder stela_intel_compute_encoder_350;
#endif
