/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_LIBRARY_ASSEMBLY_H
#define STELA_METAL_LIBRARY_ASSEMBLY_H
#include "../metal/macos/library_manifest.h"
#ifdef __cplusplus
extern "C" {
#endif
#define STELA_METAL_ASSEMBLY_ABI 1u
struct stela_metal_assembly_options {
   uint32_t size, abi, max_entries, reserved;
   uint64_t max_input_bytes, max_metadata_bytes;
};
enum stela_metal_assembly_status {
   STELA_METAL_ASSEMBLY_OK,
   STELA_METAL_ASSEMBLY_INPUT,
   STELA_METAL_ASSEMBLY_ABI_MISMATCH,
   STELA_METAL_ASSEMBLY_LIMIT,
   STELA_METAL_ASSEMBLY_ALLOCATION,
   STELA_METAL_ASSEMBLY_CONTAINER,
   STELA_METAL_ASSEMBLY_AIR,
   STELA_METAL_ASSEMBLY_IDENTITY,
   STELA_METAL_ASSEMBLY_REFLECTION,
   STELA_METAL_ASSEMBLY_SOURCE,
};
struct stela_metal_assembly_error {
   uint32_t size, abi, status, input_status, air_kind, air_instruction;
   uint64_t input_offset;
   char detail[256];
};
struct stela_metal_assembly;

/* Hosted local owner only, never a pointer IPC format. Standard libc owns the
 * copied metadata; the canonical Rust input handle owns original bytes. LLVM
 * callback views are copied before callback return. No LLVM or request/output
 * pointer, device, connection, pipeline or GPU object escapes this assembly.
 *
 * Options require exact size/ABI1 and nonzero explicit bounds. Metadata budget
 * covers all retained C owner/records/pointers/strings, excluding the separately
 * bounded Rust input and normal transient LLVM/Foundation allocations. Defaults
 * are 64MiB input, 16MiB retained metadata, 256 entries. No partial owner is
 * published: failure preserves the empty output slot; error is optional complete
 * writable storage. Input/output/error/owner storage must be disjoint, readable
 * or writable as indicated and not concurrently mutated/destroyed. */
/* Archive admission additionally requires exactly the canonical six required
 * function tags and absent/ENDT-only public/private/header metadata. Nonempty
 * unqualified extensions refuse before any reflection flags are published. */
struct stela_metal_assembly_options stela_metal_assembly_default_options(void);
enum stela_metal_assembly_status stela_metal_assemble_archive(
   const struct stela_metal_assembly_options *options,
   const void *bytes, size_t byte_count, struct stela_metal_assembly **output,
   struct stela_metal_assembly_error *error);

/* Source request/output MUST come from a successful invocation of the existing
 * qualified adapter by the trusted compiler owner. This is an integrity and
 * consistency boundary, not authentication of caller-created C structs. It
 * reuses validate_request and checks source/AIR hashes and exact metadata facts;
 * llvm.ident is never used to manufacture compiler provenance. The caller may
 * dispose source/request/output storage after success. No compiler invocation,
 * dylib loading, source option mapping or hardware call is made here. */
enum stela_metal_assembly_status stela_metal_assemble_source(
   const struct stela_metal_assembly_options *options,
   const struct stela_msl_apple_config *config,
   const struct stela_msl_request *request, const struct stela_msl_output *compiled,
   struct stela_metal_assembly **output, struct stela_metal_assembly_error *error);

/* Selected-stage compiler input, not a complete public Metal library. This
 * additive owner mode cannot be consumed through assembly_manifest (returns
 * NULL). TYPE is the actual canonical vertex0/fragment1 value, never kernel2.
 * identity has no compute reflection/ENTRY flags; reflection is the actual
 * deep-owned stage descriptor. provenance retains original input, target and
 * qualified source-request/build facts, with entries=NULL/entry_count=0 because
 * this view selects one stage rather than claiming a complete library manifest.
 * archive_index is UINT32_MAX for source; pointers are same-process immutable
 * borrows until owner destruction, never an IPC format or resource authority. */
struct stela_metal_stage_view {
   uint32_t size, abi, archive_index, reserved;
   const struct stela_metal_library_manifest *provenance;
   const struct stela_metal_function_record *identity;
   const struct stela_air_stage_entry *reflection;
};
enum stela_metal_assembly_status stela_metal_assemble_selected_stage_archive(
   const struct stela_metal_assembly_options *, const void *, size_t,
   uint32_t archive_index, enum stela_air_stage expected_stage,
   struct stela_metal_assembly **, struct stela_metal_assembly_error *);
enum stela_metal_assembly_status stela_metal_assemble_selected_stage_source(
   const struct stela_metal_assembly_options *, const struct stela_msl_apple_config *,
   const struct stela_msl_request *, const struct stela_msl_output *,
   const char *entry_name, size_t entry_name_bytes, enum stela_air_stage,
   struct stela_metal_assembly **, struct stela_metal_assembly_error *);
const struct stela_metal_stage_view *stela_metal_assembly_stage(
   const struct stela_metal_assembly *);

/* Views are immutable and valid only while this unique owner is retained. They
 * can be passed to the real same-CPU library constructor, which makes its own
 * owned snapshot. Serialize destruction with ALL borrowed accesses. No pointer
 * in these views may be serialized into IPC. NULL or selected-stage owner yields NULL compute manifest. */
const struct stela_metal_library_manifest *stela_metal_assembly_manifest(
   const struct stela_metal_assembly *owner);
enum stela_metal_assembly_status stela_metal_assembly_original(
   const struct stela_metal_assembly *owner, struct stela_metal_input_view *view,
   struct stela_metal_assembly_error *error);
void stela_metal_assembly_destroy(struct stela_metal_assembly **owner);
#ifdef __cplusplus
}
#endif
#endif
