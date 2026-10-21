/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_LEGACY_COMPUTE_H
#define STELA_INTEL_HOSTED_LEGACY_COMPUTE_H

#include "../dispatch.h"
#include "compiler/shader_info.h"
#include "intel/compiler/brw/brw_compiler.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/isl/isl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Actual owner placements: code relative to instruction base; table relative
 * to surface base before Gen11 and installed binding-table pool base on Gen11+;
 * CURBE/descriptor relative to dynamic base; scratch GPU VA. Table entries
 * themselves still reference actual surface states relative to surface base.
 * Spans start at those offsets/addresses. All bases, mappings and resources
 * must be validated, installed and retained by the physical execution owner.
 * These are hosted objects, not proof of residency or untrusted ABI objects.
 */
struct stela_intel_legacy_placement {
    uint64_t code_offset, code_span;
    uint32_t binding_table_offset, binding_table_entries;
    uint64_t binding_table_span;
    uint32_t curbe_offset, descriptor_offset;
    uint64_t curbe_span, descriptor_span;
    uint64_t scratch_address, scratch_span;
};

#define STELA_INTEL_LEGACY_CURBE_DWORDS 512
struct stela_intel_legacy_plan {
    struct stela_intel_gpgpu_dispatch dispatch;
    uint32_t curbe_bytes;
    uint32_t curbe[STELA_INTEL_LEGACY_CURBE_DWORDS];
    uint32_t descriptor[8];
    uint32_t vfe_words, vfe[9];
    uint32_t curbe_load[4], descriptor_load[4];
    uint32_t walker_words, walker[17];
    uint32_t scratch_bytes_per_thread;
    uint64_t scratch_allocation_bytes;
    uint32_t slm_bytes_per_group;
    uint32_t binding_table_entries;
    uint32_t cs_stall_before_vfe;
    uint32_t disable_mid_thread_preemption;
};

/* Fixed-workgroup, direct-origin, buffer-only legacy compute producer. Uses
 * actual compiled BRW (Gen9/11/12) or ELK (Gen7/7.5/8) metadata and original
 * dispatch/SLM helpers, subgroup push ABI, Iris/Crocus state policy and XML
 * packers. No guessed subgroup values or shader metadata are accepted.
 * Program and initialized ISL/compiler must describe the SAME actual device.
 *
 * Output contains payload/descriptor bytes to upload at the owned placements,
 * VFE + load packets, and checked native walker bytes, not an executing batch.
 * The physical owner must install/validate state bases (including the Gen11+
 * binding-table pool) and resources, patch
 * actual code relocations/constant data, select compute pipeline, apply real
 * cache/L3/GT workarounds and preemption policy, stall before VFE, preserve load
 * ordering, publish actual DMA visibility, submit and retain resources through
 * real completion. Do not submit these arrays while ignoring those duties.
 *
 * Only no-push or the original one-dword per-thread subgroup payload is
 * implemented. Other uniforms, samplers, workgroup-count bindings, ray-stack,
 * dynamic workgroups and modern walkers fail explicitly.
 * FP32 requires explicit qualified RTE+FTZ or (Gen8+) RTE+preserve controls;
 * Gen7/7.5 preserve, other widths and unknown/conflicting modes are refused.
 * All host pointers stay in this process. Only validated byte/resource references may cross the
 * native boundary. Errors (invalid -22, unsupported -95) leave output intact.
 */
int stela_intel_legacy_brw_plan(const struct brw_compiler *, const struct isl_device *,
                              const struct brw_cs_prog_data *,
                              const struct shader_info *,
                              const struct stela_intel_legacy_placement *,
                              const uint32_t groups[3], uint32_t variable_slm_bytes,
                              struct stela_intel_legacy_plan *);
int stela_intel_legacy_elk_plan(const struct elk_compiler *, const struct isl_device *,
                              const struct elk_cs_prog_data *,
                              const struct shader_info *,
                              const struct stela_intel_legacy_placement *,
                              const uint32_t groups[3],
                              struct stela_intel_legacy_plan *);

#ifdef __cplusplus
}
#endif
#endif
