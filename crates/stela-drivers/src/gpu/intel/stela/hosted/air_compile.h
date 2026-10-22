/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_AIR_COMPILE_H
#define STELA_INTEL_AIR_COMPILE_H
#include "../../../metal/compiler/library_assembly.h"
#include "stela/air_to_nir.h"
#include "../../../metal/compiler/threadgroup.h"
#include "intel/compiler/brw/brw_compiler.h"
#include "intel/compiler/elk/elk_compiler.h"
#include "intel/dev/intel_debug.h"
#ifdef __cplusplus
extern "C" {
#endif
#define STELA_INTEL_AIR_ABI 1u
enum stela_intel_air_status {
    STELA_INTEL_AIR_OK, STELA_INTEL_AIR_INVALID, STELA_INTEL_AIR_UNSUPPORTED,
    STELA_INTEL_AIR_DEVICE, STELA_INTEL_AIR_LIMIT, STELA_INTEL_AIR_ALLOCATION,
    STELA_INTEL_AIR_FRONTEND, STELA_INTEL_AIR_BACKEND,
};
enum stela_intel_air_backend { STELA_INTEL_AIR_BRW = 1, STELA_INTEL_AIR_ELK = 2 };
struct stela_intel_air_options {
    uint32_t size, abi, workgroup_size[3], max_instructions, max_code_bytes;
    /* Zero retains original compiler SIMD selection; fixed8/16/32 is explicit
     * specialization, not inferred from Apple CPU or a test device name. */
    uint32_t subgroup_size;
    enum stela_air_fp_profile fp_profile;
};
struct stela_intel_air_error {
    enum stela_intel_air_status status;
    struct stela_air_error air;
    char detail[256];
};
struct stela_intel_air_binding { struct stela_air_buffer buffer; uint32_t slot; };
/* Actual code-affecting compiler policy, copied without object/RA/callback
 * pointers. NIR options remain available through the owned NIR. */
struct stela_intel_air_policy {
    bool precise_trig, lower_dpas, optimistic_simd_heuristic;
    bool scalar_stage, constant_buffer_0_is_relative, supports_shader_constants, has_negative_rhw_bug;
    int spilling_rate;
    uint32_t register_file_size, register_pressure_threshold, lowered_format_count;
    const uint32_t *lowered_formats;
    BITSET_WORD debug[BITSET_WORDS(INTEL_DEBUG_MAX)];
    uint64_t simd;
    uint32_t simd_overridden;
};
/* Same-process immutable evidence, not serialized IPC or a cache wire format.
 * Compiler/source provenance is absent for an archive unless independently
 * established by its actual owner. An FP profile authenticates no input. */
struct stela_intel_air_provenance {
    struct stela_metal_input_info input;
    struct stela_metal_input_entry entry;
    uint32_t selected_entry, entry_flags, library_flags, compiler_profile;
    uint32_t request_language, request_fast_math, argument_count;
    uint64_t air_offset, air_bytes;
    uint8_t air_sha256[32], source_sha256[32];
    struct stela_msl_build_identity build;
    const char *name, *target;
    const struct stela_air_argument_info *arguments;
    struct stela_intel_air_options options;
    struct intel_device_info device;
    struct stela_intel_air_policy policy;
    struct stela_metal_threadgroup_specialization threadgroup;
};
struct stela_intel_air_binary {
    enum stela_intel_air_backend backend;
    const void *code;
    uint32_t code_bytes, executable_bytes;
    const struct brw_cs_prog_data *brw;
    const struct elk_cs_prog_data *elk;
};
struct stela_intel_air_compilation;
/* Hosted same-CPU compiler. Exactly ONE compiler must be the actual initialized
 * matching device/ISA/RA context from this retained build, with genuine debug
 * and performance callbacks. Borrowed log_data must be valid for those callbacks
 * throughout compilation (NULL only if they support it); it is never retained.
 * Actual compute NIR options must have NULL cb_data: opaque callback payload
 * ownership cannot be copied or inferred. Non-NULL is refused before allocation.
 * The retained compiler implementation must remain loaded for owned NIR
 * services/function pointers. All borrowed context policy must stay immutable
 * during this call. No device discovery/construction occurs here. The output
 * slot is uniquely owned and initially NULL; failures preserve it. The result
 * retains no compiler/assembly pointer, and owns original code/progdata,
 * relocations, constant data, ELK params, NIR/options and GLSL type lifetimes.
 *
 * Current ABI maps every declared ordinary AS1 argument (including unused
 * arguments) to a distinct contiguous SSBO slot in metadata order. Zero such
 * arguments is valid. The existing shared frontend's exact32-bit view-size
 * query and bounds lowering remain intact. The actual resource owner uses
 * stela_intel_raw_buffer_state with the exact Metal view/rights/alignment,
 * including ISL's mapped padding, then uploads real surface states/table
 * offsets and retains device/VM/mapping/cache/visibility/fence lifetimes.
 * No fixed VA, resource allocator or caller flag authenticates that ownership.
 *
 * Returned resident bytes include original constant data and unpatched
 * relocation records; executable_bytes excludes trailing constant data.
 * Apply original relocation helpers and real resource values before upload.
 * Scratch/push/SLM/barriers/SIMD are genuine requirements, not readiness.
 * Existing compute/legacy producers retain their restrictions, including
 * Gen35 original compiler/dispatch qualification hold (refused before its
 * assert-bearing path). Gen7/7.5 FP32-preserve is explicitly refused.
 * DynamicAS3 specialization and incomplete canonical global reflection remain
 * unsupported. No Metal PSO, initialization, upload or GPU work is created.
 * Wrapper OOM is typed; original compiler fatal/OOM/cancellation remains the
 * normal compiler process owner's responsibility. All views are serialized
 * against mutation/destruction; no C++/Rust/host pointers cross the native ABI. */
/* Exact dispatch-size specialization; existing compile() delegates with NULL.
 * Request arrays are borrowed only during the call and copied into provenance.
 * Backend shared totals include these rows plus static layout, never expose
 * them as Metal staticThreadgroupMemoryLength or add dynamic bytes twice.
 * stela_metal_threadgroup_matches checks values only, not resource ownership. */
enum stela_intel_air_status stela_intel_air_compile_specialized(const struct brw_compiler *,
    const struct elk_compiler *, void *log_data, const struct stela_metal_assembly *, uint32_t selected_entry,
    const struct stela_intel_air_options *, const struct stela_metal_threadgroup_request *,
    struct stela_intel_air_compilation **,
    struct stela_intel_air_error *);

enum stela_intel_air_status stela_intel_air_compile(const struct brw_compiler *,
    const struct elk_compiler *, void *log_data, const struct stela_metal_assembly *, uint32_t selected_entry,
    const struct stela_intel_air_options *, struct stela_intel_air_compilation **,
    struct stela_intel_air_error *);
const struct stela_intel_air_binary *stela_intel_air_binary(const struct stela_intel_air_compilation *);
const nir_shader *stela_intel_air_nir(const struct stela_intel_air_compilation *);
const struct stela_intel_air_provenance *stela_intel_air_provenance(const struct stela_intel_air_compilation *);
const struct stela_intel_air_binding *stela_intel_air_bindings(const struct stela_intel_air_compilation *, uint32_t *count);
void stela_intel_air_destroy(struct stela_intel_air_compilation **);
/* Internal separately compiled TU: original EU implementation headers share
 * enumerators across BRW/ELK, so retain the original ELK header in isolation. */
bool stela_intel_air_validate_elk(const struct elk_compiler *, const void *, uint32_t);
#ifdef __cplusplus
}
#endif
#endif
