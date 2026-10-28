/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_LIBRARY_MANIFEST_H
#define STELA_METAL_LIBRARY_MANIFEST_H
#include "../metal/input/input.h"
#include "apple_source.h"
#include "air_metadata.h"

#define STELA_METAL_LIBRARY_ABI 1u
#define STELA_METAL_ENTRY_NO_CONSTANTS 1u
#define STELA_METAL_ENTRY_PLAIN_BUFFERS 2u
#define STELA_METAL_ENTRY_COMPLETE_REFLECTION 4u
#define STELA_METAL_LIBRARY_SOURCE_COMPILED 1u

/* Same-process, same-CPU helper-result assembly only. These pointers are NOT an
 * IPC wire representation. The actual authenticated helper/transport owner must
 * produce this manifest with the canonical Rust input parser and shared LLVM23
 * inspector, cross-checking MTLB NAME/TYPE/VERS against the selected actual AIR
 * entry. Metadata flags are evidence, never inferred from app/source identity.
 * NO_CONSTANTS requires validated absence of function constants in both archive
 * metadata (when present) and AIR. PLAIN_BUFFERS
 * requires every buffer's reflected MSL type to be a supported builtin scalar/
 * vector; unknown/struct resources cannot claim absence of argument buffers.
 * COMPLETE_REFLECTION requires the shared inspector's reflection_complete,
 * including absent unsupported constants/annotations/globals (qualified internal
 * undef AS3 static storage is understood) and exact primitive
 * names/layout. The assembler must copy all borrowed inspector arrays/strings
 * during each callback. Manifest pointers must refer to live immutable owner
 * storage through constructor return; the constructor retains no such pointers.
 * used describes uses in the accepted AIR, not backend liveness.
 * LLVM/body/codegen support, device caps and runtime binding are pipeline work.
 */
struct stela_metal_function_record {
   uint32_t size, abi, flags, reserved;
   struct stela_metal_input_entry entry;
   const uint8_t *name;
   uint64_t name_bytes;
   uint64_t air_offset, air_bytes;
   uint8_t air_sha256[32];
   uint32_t argument_count, reserved_arguments;
   const struct stela_air_argument_info *arguments;
};
struct stela_metal_library_manifest {
   uint32_t size, abi, flags, compiler_profile;
   struct stela_metal_input_info input;
   uint32_t request_language, request_fast_math, entry_count, reserved;
   const uint8_t *target;
   uint64_t target_bytes;
   uint8_t source_sha256[32];
   struct stela_msl_build_identity build;
   const struct stela_metal_function_record *entries;
};

#endif
