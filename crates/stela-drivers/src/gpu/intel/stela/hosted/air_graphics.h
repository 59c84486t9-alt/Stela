/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_AIR_GRAPHICS_H
#define STELA_INTEL_AIR_GRAPHICS_H
#include "../../../metal/compiler/library_assembly.h"
#include "compiler/air_to_nir.h"
#include "intel/compiler/brw/brw_compiler.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/dev/intel_debug.h"
#ifdef __cplusplus
extern "C" {
#endif

#define STELA_INTEL_GRAPHICS_ABI 1u
enum stela_intel_graphics_status {
    STELA_INTEL_GRAPHICS_OK, STELA_INTEL_GRAPHICS_INVALID,
    STELA_INTEL_GRAPHICS_UNSUPPORTED, STELA_INTEL_GRAPHICS_DEVICE,
    STELA_INTEL_GRAPHICS_LIMIT, STELA_INTEL_GRAPHICS_ALLOCATION,
    STELA_INTEL_GRAPHICS_FRONTEND, STELA_INTEL_GRAPHICS_BACKEND,
};
enum stela_intel_graphics_backend { STELA_INTEL_GRAPHICS_BRW = 1, STELA_INTEL_GRAPHICS_ELK = 2 };
struct stela_intel_graphics_error {
    enum stela_intel_graphics_status status;
    struct stela_air_error air;
    char detail[256];
};
struct stela_intel_graphics_options {
    uint32_t size, abi, max_instructions, max_code_bytes, max_varying_slots;
    /* Current explicit compile model: exactly one color region and one sample.
     * These are compilation specializations, never actual attachment/VM grants. */
    uint32_t color_regions, samples;
    enum stela_air_fp_profile vertex_fp_profile, fragment_fp_profile;
};
struct stela_intel_graphics_binding {
    struct stela_air_buffer buffer;
    uint32_t logical_slot, bti;
    bool used; /* Actual pre-BTI NIR resource use, not reflection alone. */
    bool table_entry; /* Only used buffers get a table entry and a meaningful bti. */
};
struct stela_intel_graphics_stage_binary {
    enum stela_air_stage stage;
    const void *code;
    uint32_t code_bytes, executable_bytes, binding_table_bytes;
    /* Exactly one matching stage/backend pointer is non-NULL. All original
     * fields, deep parameters, relocations and constant data remain owned. */
    const struct brw_vs_prog_data *brw_vs;
    const struct brw_fs_prog_data *brw_fs;
    const struct elk_vs_prog_data *elk_vs;
    const struct elk_fs_prog_data *elk_fs;
};
struct stela_intel_graphics_policy {
    uint64_t original_compiler_config;
    BITSET_WORD debug[BITSET_WORDS(INTEL_DEBUG_MAX)];
    uint64_t simd;
    uint32_t simd_overridden;
    int spilling_rate;
    uint32_t register_file_size, register_pressure_threshold;
    bool scalar_vertex, scalar_fragment, constant_buffer_0_is_relative;
    bool supports_shader_constants, has_negative_rhw_bug;
};
struct stela_intel_graphics_provenance {
    enum stela_intel_graphics_backend backend;
    struct intel_device_info device;
    struct stela_intel_graphics_options options;
    struct stela_intel_graphics_policy policy;
    /* Genuine independently preserved selected-stage origins. Different input
     * libraries/source builds may link; neither is rewritten as kernel kind 2. */
    const struct stela_metal_stage_view *vertex, *fragment;
};
struct stela_intel_graphics_compilation;

/* Hosted same-CPU owner only. Exactly one compiler is the actual initialized
 * matching immutable device/ISA/RA context with real callbacks. The retained
 * compiler implementation stays loaded for owned NIR services. Each original
 * VS/FS NIR option set must have NULL cb_data: opaque callback lifetime is not
 * inferred or copied. Borrowed log_data remains valid throughout the call.
 * The compiler process serializes original cached BTI/debug initialization
 * before parallel use and keeps that process policy immutable. A selected
 * original JAY stage policy is refused until its actual backend is integrated.
 *
 * vertex and fragment are distinct exclusive owning slots holding TWO distinct
 * genuine canonical selected-stage assemblies, with their actual roles. They,
 * output, error and every pointed allocation are disjoint and serialized
 * against mutation/destruction. output is initially NULL. Failure preserves
 * both input owning slots and empty output. Only complete success consumes
 * BOTH inputs (clears both slots) and publishes the uniquely owned package.
 * No allocation or other failure remains after that ownership transition.
 *
 * Logical readonly AS2 bindings retain exact reflected size/alignment and
 * shared 64-bit bounds. Their BTIs follow the Iris/Crocus table layout: the
 * fragment render target first, then the used buffers in index order.
 * Real resource binding still needs actual initialized ISL/cache policy and
 * stela_intel_raw_buffer_state/image_state with genuine views, mapped padding,
 * rights, surface/table heaps and visibility lifetimes. State does not protect
 * rights. Code/relocations/constants/push/scratch/VUE are actual requirements,
 * never a claim they are uploaded or configured. Preserve original relocation
 * helpers and actual same-VM values when a genuine owner later uploads them.
 *
 * Current stage/model/effect and Gen35 qualification holds remain explicit.
 * Wrapper OOM is typed; normal original backend fatal/OOM/cancellation remains
 * the hosted compiler process owner's responsibility. No Metal PSO, native
 * graphics-state completion, device/context/VM initialization, URB/L3 install,
 * submission or GPU execution occurs. No process pointer crosses native IPC.
 */
enum stela_intel_graphics_status stela_intel_graphics_compile(
    const struct brw_compiler *, const struct elk_compiler *, void *log_data,
    struct stela_metal_assembly **vertex, struct stela_metal_assembly **fragment,
    const struct stela_intel_graphics_options *,
    struct stela_intel_graphics_compilation **output,
    struct stela_intel_graphics_error *);
const struct stela_intel_graphics_provenance *stela_intel_graphics_provenance(
    const struct stela_intel_graphics_compilation *);
const struct stela_intel_graphics_stage_binary *stela_intel_graphics_binary(
    const struct stela_intel_graphics_compilation *, enum stela_air_stage);
const struct stela_intel_graphics_binding *stela_intel_graphics_bindings(
    const struct stela_intel_graphics_compilation *, enum stela_air_stage, uint32_t *count);
const nir_shader *stela_intel_graphics_nir(
    const struct stela_intel_graphics_compilation *, enum stela_air_stage);
void stela_intel_graphics_destroy(struct stela_intel_graphics_compilation **);
/* Whole-span ISA validation; the ELK half lives in air_validate_elk.c because
 * original ELK EU enums cannot be co-included with BRW's. */
bool stela_intel_graphics_validate_elk(const struct elk_compiler *, const void *, uint32_t,
    unsigned end_alignment);
enum stela_intel_graphics_status stela_intel_graphics_validate_brw(
    const struct intel_device_info *, void *context, const void *, uint32_t,
    unsigned end_alignment);
#ifdef __cplusplus
}
#endif
#endif
