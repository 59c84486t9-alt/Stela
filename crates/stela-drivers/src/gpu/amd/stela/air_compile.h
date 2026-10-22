/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_AIR_COMPILE_H
#define STELA_AMD_AIR_COMPILE_H

#include "compute.h"
#include "../../metal/compiler/library_assembly.h"
#include "stela/air_to_nir.h"
#include "../../metal/compiler/threadgroup.h"
#include "amd/common/ac_gpu_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STELA_AMD_AIR_ABI 1u
#define STELA_AMD_AIR_MAX_BUFFERS 8u

enum stela_amd_air_status {
   STELA_AMD_AIR_OK,
   STELA_AMD_AIR_INVALID,
   STELA_AMD_AIR_UNSUPPORTED,
   STELA_AMD_AIR_DEVICE_INFO_UNAVAILABLE,
   STELA_AMD_AIR_LIMIT,
   STELA_AMD_AIR_ALLOCATION,
   STELA_AMD_AIR_FRONTEND,
   STELA_AMD_AIR_BACKEND,
};

struct stela_amd_air_options {
   uint32_t size, abi;
   uint32_t wave_size, workgroup_size[3], max_instructions, max_code_bytes;
   enum stela_air_fp_profile fp_profile;
};

struct stela_amd_air_error {
   enum stela_amd_air_status status;
   struct stela_air_error air;
   char detail[256];
};

/* Ordered as the actual user SGPR pairs consumed by compute.c. Metadata keeps
 * Metal index, LLVM argument ordinal, required access and reflected alignment;
 * neither a buffer VA nor a caller-created permission boolean is compiled in.
 * At dispatch, the real resource owner must supply matching views/rights,
 * lifetime, VM, residency and cache ordering through completion. */
struct stela_amd_air_binding {
   struct stela_air_buffer buffer;
   struct ac_arg argument;
};

/* Immutable same-process facts, not an IPC/cache wire format. All strings and
 * argument reflection below are copied from the selected canonical assembly.
 * Input/module/raw offsets and hashes retain their original distinct scopes.
 * Zero archive source/build fields remain absent; an FP policy NEVER fabricates
 * source compiler provenance. The compiler/input owner must independently
 * qualify the nondefault AIR FP profile, as required by air_to_nir.h. */
struct stela_amd_air_provenance {
   struct stela_metal_input_info input;
   struct stela_metal_input_entry entry;
   uint32_t selected_entry, entry_flags, library_flags, compiler_profile;
   uint32_t request_language, request_fast_math, argument_count;
   uint64_t air_offset, air_bytes;
   uint8_t air_sha256[32], source_sha256[32];
   struct stela_msl_build_identity build;
   const char *name, *target;
   const struct stela_air_argument_info *arguments;
   struct stela_amd_air_options options;
   struct ac_compiler_info compiler_info;
   uint32_t pci_id, pci_rev_id;
   bool has_graphics;
   uint64_t aco_codegen_flags;
    struct stela_metal_threadgroup_specialization threadgroup;
};

struct stela_amd_air_compilation;

/* Normal hosted compiler process only. info MUST be the actual initialized
 * device/compiler facts from the matching retained Mesa build, not a family
 * guessed from an Apple CPU or a test topology. This routine validates facts it
 * consumes but cannot authenticate a caller-created radeon_info. Input owner,
 * options and info are borrowed through this synchronous call only. No LLVM,
 * assembly, options or device pointer survives success.
 *
 * Only ordinary AS1 buffer arguments (up to the existing eight address pairs),
 * current shared frontend bodies and ACO-supported targets are admitted. Dynamic
 * AS3 arguments require compile_specialized with exact requested byte lengths.
 * Qualified static shared storage uses original NIR/ACO lowering
 * if admitted by the canonical library owner. No function-constant overrides,
 * descriptor/sampler/image ABI or compiler fallback is invented.
 *
 * Output MUST point to an empty sole-owning slot; every failure preserves it.
 * Error is optional complete writable storage. All input/output/error storage
 * must be valid, disjoint, and serialized against destruction/mutation. This
 * wrapper reports its own allocation failures, not recovery from fatal/OOM
 * inside LLVM/Mesa/ACO; the normal compiler-process owner supplies cancellation,
 * watchdog and crash isolation. No global fault handler is installed.
 */
/* Exact dispatch-size specialization; existing compile() delegates with NULL.
 * Request arrays are borrowed only during the call and copied into provenance.
 * Backend shared totals include these rows plus static layout, never expose
 * them as Metal staticThreadgroupMemoryLength or add dynamic bytes twice.
 * stela_metal_threadgroup_matches checks values only, not resource ownership. */
enum stela_amd_air_status stela_amd_air_compile_specialized(
   const struct radeon_info *info, const struct stela_metal_assembly *library,
   uint32_t selected_entry, const struct stela_amd_air_options *options,
   const struct stela_metal_threadgroup_request *threadgroup,
   struct stela_amd_air_compilation **output, struct stela_amd_air_error *error);

enum stela_amd_air_status stela_amd_air_compile(
   const struct radeon_info *info, const struct stela_metal_assembly *library,
   uint32_t selected_entry, const struct stela_amd_air_options *options,
   struct stela_amd_air_compilation **output, struct stela_amd_air_error *error);

/* Borrowed immutable views last until the unique owner is destroyed. The code
 * view covers complete code/data; binary.executable_bytes excludes trailing
 * constants. Stable NIR/options/args/config backing makes binary usable by the
 * existing stela_amd_build_compute_pipeline, once the real code/resource owner
 * supplies the SAME initialized device/compiler facts and published allocation
 * views. That owner retains device identity/epoch: these C pointers are not a
 * replacement for its authenticated session or lifetime. Scratch/LDS
 * requirements are actual compiler results, NOT resource readiness or a Metal
 * pipeline state. No upload, relocation, allocation, submission or GPU access
 * occurs here. Symbols currently refuse, rather than escaping unresolved. */
const struct stela_amd_compute_binary *stela_amd_air_binary(
   const struct stela_amd_air_compilation *owner);
const uint8_t *stela_amd_air_code(const struct stela_amd_air_compilation *owner);
const struct stela_amd_air_binding *stela_amd_air_bindings(
   const struct stela_amd_air_compilation *owner, uint32_t *count);
const struct stela_amd_air_provenance *stela_amd_air_provenance(
   const struct stela_amd_air_compilation *owner);
void stela_amd_air_destroy(struct stela_amd_air_compilation **owner);

#ifdef __cplusplus
}
#endif
#endif
