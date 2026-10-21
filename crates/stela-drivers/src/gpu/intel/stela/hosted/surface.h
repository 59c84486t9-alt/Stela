/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_SURFACE_H
#define STELA_INTEL_HOSTED_SURFACE_H

#include "intel/isl/isl.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hosted Mesa component: compile for the user-space frontend/compiler process.
 * This header and its ISL implementation do not belong in the freestanding
 * physical backend. Only validated state bytes plus owned resource references
 * may cross that boundary; these native process pointers must never cross it.
 */
enum stela_intel_buffer_access {
    STELA_INTEL_BUFFER_READ = 1,
    STELA_INTEL_BUFFER_WRITE = 2,
    STELA_INTEL_BUFFER_READ_WRITE = 3,
};

struct stela_intel_raw_view {
    uint64_t gpu_base; /* Actual allocation mapping, in the selected GPU VM */
    uint64_t mapped_bytes; /* Pinned/reachable span, including required padding */
    uint64_t buffer_bytes; /* Logical allocation length, excluding padding */
    uint64_t offset;
    uint64_t bytes; /* Exact Metal view length, not rounded hardware size */
    uint32_t address_bits; /* Real VM width supplied by the mapping owner */
    uint32_t alignment; /* Shader/view alignment; at least a dword here */
    uint32_t access;
    uint32_t available_access;
    bool external; /* Select original ISL external/internal MOCS policy */
};

/* The owner supplies an actual initialized ISL device, valid cache/PAT/MOCS
 * configuration, aux/workaround resources and the real GPU mapping/lifetimes.
 * View accesses must fit both the logical allocation and the physically mapped
 * padded surface range. Keep mappings pinned until completion; a descriptor
 * itself is not memory protection and cannot enforce read-only rights.
 *
 * The current indexed-SSBO ABI queries a 32-bit exact byte length. Zero length,
 * >UINT32_MAX, unknown rights/VM widths, insufficient padding, noncanonical VA,
 * unsupported address fields and ISL-clamped sizes fail explicitly. Protected,
 * compressed, scratch and typed/image surfaces require their real paths.
 *
 * Return encoded state bytes (>0), -22 invalid input/configuration, -28 output
 * too small or -95 unavailable ISL generation. Errors leave output unchanged.
 * CPU output must be u32 aligned; its eventual GPU placement must satisfy
 * dev->ss.align, checked by the resource/state owner at upload time.
 */
int stela_intel_raw_buffer_state(const struct isl_device *,
                                 const struct stela_intel_raw_view *,
                                 void *state, size_t capacity);

struct stela_intel_raw_limits {
    uint64_t max_view_bytes;
    uint32_t state_bytes;
    uint32_t gpu_state_alignment;
    uint32_t surface_address_bits; /* Packet field width, not the VM width */
};

/* Encoder ceilings from original ISL plus the implemented exact-size SSBO ABI.
 * Actual allocation/mapping/device/shader limits can reduce them further. */
int stela_intel_query_raw_limits(const struct isl_device *, struct stela_intel_raw_limits *);

/* Hardware format properties from original ISL, not a Metal feature/family
 * declaration. Frontend advertisement must intersect these with implemented
 * resource/shader/command paths and actual runtime device limits. The current
 * adapter implements only RAW buffer-state encoding; image/typed operations
 * listed here are hardware facts awaiting their own resource implementations.
 */
struct stela_intel_format_support {
    bool rendering, blending, sampling, filtering, vertex_fetch;
    bool typed_read, typed_write, typed_atomic;
    bool raw_buffer_encoder;
    isl_sample_count_mask_t sample_counts;
};

int stela_intel_query_format(const struct isl_device *, enum isl_format,
                             struct stela_intel_format_support *);

#ifdef __cplusplus
}
#endif
#endif
