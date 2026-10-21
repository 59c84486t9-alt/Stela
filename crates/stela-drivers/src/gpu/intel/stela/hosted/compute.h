/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_COMPUTE_H
#define STELA_INTEL_HOSTED_COMPUTE_H

#include "../compute_dispatch.h"
#include "intel/compiler/brw/brw_compiler.h"
#include "intel/isl/isl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Trusted hosted resource owner's actual placements, relative to the already
 * installed instruction/surface bases. Spans start at the given offsets and
 * must remain mapped/pinned for execution. No process pointers cross the
 * physical boundary. This describes ownership prerequisites, not proof of GPU
 * residency or a substitute for the native owner's resource validation.
 */
struct stela_intel_compute_placement {
    uint64_t code_offset;
    uint64_t code_span;
    uint32_t binding_table_offset;
    uint32_t binding_table_entries;
    uint64_t binding_table_span;
};

struct stela_intel_compute_requirements {
    uint32_t scratch_bytes_per_thread;
    uint32_t slm_bytes_per_group;
    uint32_t cfe_max_threads;
    uint32_t binding_table_entries;
    uint32_t apply_async_thread_limits;
    uint32_t pixel_async_thread_limit;
    uint32_t z_pass_async_thread_limit;
    uint32_t np_z_async_throttle;
};

struct stela_intel_compute_plan {
    struct stela_intel_compute_dispatch dispatch;
    struct stela_intel_compute_requirements requirements;
};

/* Hosted buffer-only, fixed-workgroup BRW producer. compiler->devinfo and
 * isl->info must be the same actual initialized device object, with valid
 * topology/cache configuration. program must be the actual matching compiled
 * compute result; uploaded code must include its relocations/constant data and
 * preserve the caller's binary/source provenance. All pointer lifetimes stay
 * in this process. Only the scalar plan and owned native resource references
 * may cross the execution boundary.
 *
 * SIMD/offset/mask/push, SLM, thread-group/register allocation and MOCS come
 * from original Intel helpers. Caller supplies grid, optional variable SLM and
 * real resource placements, never encoded driver policy. Table/sampler prefetch
 * stays disabled following Iris defaults. Sampler/ray-stack/push-bearing and
 * variable-workgroup programs require their own resource/payload paths and
 * fail explicitly; Gen35's existing qualification hold remains in force.
 *
 * The native owner must apply returned CFE/scratch/SLM/async requirements and
 * actual device cache/L3/workaround/VRT policy before dispatch, retain all
 * resources, and validate the native descriptor. No state is applied here.
 * Returns 0, -22 invalid metadata/placement, or -95 unsupported path. Errors
 * leave the entire output plan unchanged. This API is not an untrusted Mesa
 * object deserializer or a device-support/Metal-family declaration.
 */
int stela_intel_compute_plan(const struct brw_compiler *, const struct isl_device *,
                             const struct brw_cs_prog_data *,
                             const struct stela_intel_compute_placement *,
                             const uint32_t groups[3], uint32_t variable_slm_bytes,
                             struct stela_intel_compute_plan *);

#ifdef __cplusplus
}
#endif
#endif
