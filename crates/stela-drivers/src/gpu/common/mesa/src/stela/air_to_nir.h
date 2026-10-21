/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_TO_NIR_H
#define STELA_AIR_TO_NIR_H

#include "compiler/nir/nir_builder.h"
#include <stddef.h>

/* User-space compiler boundary. LLVM and Mesa must be built for this process's
 * architecture and linked with their normal runtime services. No GPU access,
 * IOKit call, Metal device registration, or command submission happens here.
 */
enum stela_air_error_kind {
   STELA_AIR_OK,
   STELA_AIR_INPUT,
   STELA_AIR_LLVM_VERSION,
   STELA_AIR_BITCODE,
   STELA_AIR_VERIFY,
   STELA_AIR_TARGET,
   STELA_AIR_METADATA,
   STELA_AIR_ARGUMENT,
   STELA_AIR_CONTROL_FLOW,
   STELA_AIR_INSTRUCTION,
   STELA_AIR_TYPE,
   STELA_AIR_MEMORY,
   STELA_AIR_LIMIT,
   STELA_AIR_ALLOCATION,
};

struct stela_air_error {
   enum stela_air_error_kind kind;
   unsigned instruction; /* Zero-based instruction ordinal, not source line. */
   char detail[256];
};

enum stela_air_buffer_access {
   STELA_AIR_READ = 1,
   STELA_AIR_WRITE = 2,
   STELA_AIR_READ_WRITE = 3,
};

struct stela_air_buffer {
   unsigned argument;
   unsigned index; /* air.location_index; not an LLVM parameter byte offset. */
   unsigned address_space;
   enum stela_air_buffer_access access;
   unsigned type_size; /* Zero when the input omits this optional reflection. */
   unsigned type_alignment;
};

/* Resolve a validated Metal buffer binding to a 64-bit device virtual address.
 * The caller owns resource lifetime, size/access validation, actual allocation,
 * residency and runtime argument ABI. Returning NULL refuses compilation. This
 * callback must only build NIR; it must not submit commands or mutate resources.
 * Test callbacks may use fixed addresses; production bindings must not do so.
 */
typedef nir_def *(*stela_air_bind_buffer)(nir_builder *b,
                                        const struct stela_air_buffer *buffer,
                                        void *data);

struct stela_air_options {
   unsigned workgroup_size[3]; /* Exact nonzero pipeline specialization. */
   unsigned max_instructions; /* Nonzero caller-supplied compilation budget. */
   stela_air_bind_buffer bind_buffer;
   void *binding_data;
};

/* Input is the hash-checked raw AIR bitcode selected by the archive reader.
 * Success transfers ownership of a real NIR shader to the caller (ralloc_free).
 * Failure returns NULL, destroys partial NIR, and reports an explicit error.
 * The caller retains input bytes/digest/build ID and records the exact selected
 * target, workgroup specialization and argument mapping alongside vendor output.
 * LLVM is a native compiler library, not a hostile-input sandbox.
 */
nir_shader *stela_air_to_nir(const void *bitcode, size_t size, const char *entry,
                            const nir_shader_compiler_options *nir_options,
                            const struct stela_air_options *options,
                            struct stela_air_error *error);
#endif
