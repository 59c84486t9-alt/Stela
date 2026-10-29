/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_DISPATCH_INTERNAL_H
#define STELA_INTEL_DISPATCH_INTERNAL_H
#include "dispatch.h"

struct stela_intel_gpgpu_encoder {
    size_t words;
    void (*pack)(uint32_t *, const struct stela_intel_gpgpu_dispatch *);
};

extern const struct stela_intel_gpgpu_encoder stela_intel_gpgpu_encoder_70;
extern const struct stela_intel_gpgpu_encoder stela_intel_gpgpu_encoder_75;
extern const struct stela_intel_gpgpu_encoder stela_intel_gpgpu_encoder_80;
extern const struct stela_intel_gpgpu_encoder stela_intel_gpgpu_encoder_90;
extern const struct stela_intel_gpgpu_encoder stela_intel_gpgpu_encoder_110;
extern const struct stela_intel_gpgpu_encoder stela_intel_gpgpu_encoder_120;

#endif
