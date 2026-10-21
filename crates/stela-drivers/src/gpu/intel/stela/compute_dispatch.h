/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_COMPUTE_DISPATCH_H
#define STELA_INTEL_COMPUTE_DISPATCH_H

#include "commands.h"

/* A direct, unpredicated COMPUTE_WALKER from grid origin zero. Values must
 * belong to the selected compiled shader and actual device, not merely a
 * matching PCI generation. Offsets are relative to the owner's real installed
 * instruction/dynamic/surface state bases, never host pointers or GPU VAs.
 * Encoded policy fields come from the original hosted Intel helpers (including
 * SLM preference, thread-group dispatch size and ptl_register_blocks).
 */
struct stela_intel_compute_dispatch {
    uint32_t gfx_verx10; /* 125,200,300,350; packet form, not qualification */
    uint32_t local_size[3];
    uint32_t simd_size;
    uint32_t threads;
    uint32_t right_mask;
    uint32_t groups[3];
    uint32_t kernel_offset; /* Actual selected SIMD binary, 64-byte alignment */
    uint32_t binding_table_offset; /* 32-byte alignment, 21-bit field */
    uint32_t binding_table_entry_count; /* Hardware prefetch hint, 0..31 */
    uint32_t sampler_offset; /* 32-byte alignment */
    uint32_t sampler_count; /* Original encoded count, 0..4 */
    uint32_t slm_encoding;
    uint32_t preferred_slm_encoding;
    uint32_t barrier_encoding;
    uint32_t thread_group_dispatch_size;
    uint32_t register_blocks; /* Original compiled VRT encoding on Gen30+ */
    uint32_t generate_local_id; /* Original compiler mask: 0 or full X/XY/XYZ
                               * prefix; nonzero requires power-of-two X/Y */
    uint32_t walk_order; /* Original INTEL_WALK_ORDER_*, 0..5 */
    uint32_t uses_sampler; /* Actual compiler property, including bindless */
    uint32_t post_sync_mocs; /* Actual owner's original ISL cache policy */
    uint32_t push_bytes; /* Actual total compiled push requirement; must be 0 */
};

/* Appends the original generated COMPUTE_WALKER, including its real interface
 * descriptor. Mandatory prerequisites remain with the physical device owner:
 * pipeline selection, CFE/thread/scratch setup, state bases and binding/sampler
 * tables, actual device limits, SLM and async throttling, cache/L3/workarounds,
 * all code/resource mappings and lifetimes, ordering, submission and faults.
 * No post-sync write, inline/indirect push data, predicate, partition, indirect
 * dispatch or completion signal is synthesized. Push-bearing shaders fail
 * explicitly. Errors are atomic and follow commands.h; unsupported paths -95.
 */
int stela_intel_compute_dispatch(struct stela_intel_commands *,
                                const struct stela_intel_compute_dispatch *);

#endif
