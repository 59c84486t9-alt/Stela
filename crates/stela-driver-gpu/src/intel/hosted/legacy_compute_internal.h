/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_LEGACY_COMPUTE_INTERNAL_H
#define STELA_INTEL_HOSTED_LEGACY_COMPUTE_INTERNAL_H
#include "legacy_compute.h"

/* Internal computed policy only; never a caller-supplied driver policy API. */
struct stela_intel_legacy_state {
    uint64_t kernel_offset;
    uint32_t max_threads, scratch_encoding, curbe_regs;
    uint32_t per_thread_regs, cross_thread_regs;
    uint32_t slm_encoding;
    bool uses_barrier;
};
#define DECLARE_LEGACY_PACK(ver) \
    void stela_intel_legacy_pack_##ver(const struct stela_intel_legacy_state *, \
        const struct stela_intel_legacy_placement *, struct stela_intel_legacy_plan *)
DECLARE_LEGACY_PACK(70);
DECLARE_LEGACY_PACK(75);
DECLARE_LEGACY_PACK(80);
DECLARE_LEGACY_PACK(90);
DECLARE_LEGACY_PACK(110);
DECLARE_LEGACY_PACK(120);
#undef DECLARE_LEGACY_PACK
#endif
