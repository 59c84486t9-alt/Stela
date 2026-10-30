/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_DISPATCH_H
#define STELA_INTEL_DISPATCH_H

#include "commands.h"

/* Values come from the actual compiled shader's intel_cs_dispatch_info and the
 * Metal workgroup/grid specialization. The engine/pipeline owner verifies the
 * selected compiler binary, SIMD mode, device limits and actual local group
 * shape, installs matching interface descriptor 0, CURBE/per-thread subgroup
 * push data, state bases, binding tables, scratch/SLM, cache policy, context and
 * required workarounds, and pins all referenced resources. None of those
 * prerequisites is implied or substituted by these packet encoders.
 */
struct stela_intel_gpgpu_dispatch {
    uint32_t gfx_verx10; /* 70,75,80,90,110,120; not a PCI support declaration */
    uint32_t group_size; /* Exact compiled local invocation count */
    uint32_t simd_size; /* 8,16,32; a variant actually compiled for this shader */
    uint32_t threads;
    uint32_t right_mask;
    uint32_t groups[3]; /* Direct, unpredicated dispatch from grid origin 0 */
};

/* Append original generated GPGPU_WALKER + MEDIA_STATE_FLUSH as used by Iris.
 * Checks all packet fields before changing output. No resource addresses are
 * invented and no submission/completion or context/pipeline setup is performed.
 * Other generations/indirect/predicated dispatch require their real paths;
 * this helper must not be used as a fallback for COMPUTE_WALKER generations.
 * Errors match commands.h; unsupported gfx_verx10 returns -95.
 */
int stela_intel_gpgpu_dispatch(struct stela_intel_commands *,
                              const struct stela_intel_gpgpu_dispatch *);

#endif
