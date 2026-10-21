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

/* Alternative for a backend with indexed buffer surfaces rather than global
 * device addresses. The callback maps a Metal argument to a fixed SSBO slot.
 * Its surface must describe exactly that argument's buffer view, including its
 * offset and byte length; the shader's logical offset starts at zero. Distinct
 * arguments require distinct slots, even when their runtime views alias. A slot
 * is not an encoded or truncated GPU VA. */
typedef bool (*stela_air_bind_ssbo)(const struct stela_air_buffer *buffer,
                                   unsigned *slot, void *data);

struct stela_air_threadgroup_view {
   uint64_t size; /* Exact nonempty per-dispatch byte extent, not type_size. */
   unsigned alignment;
   enum stela_air_buffer_access available_access;
};

/* AS3 uses a separate Metal index namespace. Return the actual dispatch's
 * allocation length/rights/alignment; NIR owns the shared-memory layout, never
 * a CPU/GPU VA. The exact sizes/alignment and workgroup specialization must be
 * retained in receipts and the pipeline cache key. Changing them requires a
 * matching compiled specialization and dispatch shared-memory reservation. */
typedef bool (*stela_air_bind_threadgroup)(const struct stela_air_buffer *buffer,
                                          struct stela_air_threadgroup_view *view,
                                          void *data);

struct stela_air_ssbo_view {
   unsigned slot;
   uint64_t buffer_size;
   uint64_t offset;
   uint64_t size;
   enum stela_air_buffer_access access; /* Required by this shader argument. */
   enum stela_air_buffer_access available_access; /* Actual resource rights. */
   unsigned alignment; /* Required power-of-two byte alignment of this view. */
};

/* Command binding precondition for the 32-bit get_ssbo_size ABI: nonempty exact
 * byte views, <=UINT32_MAX bytes, wholly within the real allocation, and a slot
 * within the pipeline's explicit table extent (1..UINT8_MAX). The native driver
 * must additionally validate its GPU base VA/canonical form and base alignment,
 * lifetime and residency when constructing the original hardware surface state.
 * No physical VA is constructed by the SSBO compiler path. */
bool stela_air_ssbo_view_valid(const struct stela_air_ssbo_view *view,
                               unsigned ssbo_count);

enum stela_air_fp_profile {
   /* Ordinary LLVM environment; private AIR denorm options are not inferred. */
   STELA_AIR_FP_IEEE_DEFAULT = 0,
   /* Reverse-engineered AIR 2.9 / MSL 4.1 compiler 32023.922 profile: arithmetic
    * FP32 FTZ inputs/results and RTE, target air64_v29-apple-macosx27.2.0.
    * The caller must retain independently verified compiler/build provenance;
    * matching llvm.ident is consistency
    * metadata, not authentication. This is not a universal AIR declaration. */
   STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41 = 1,
};

struct stela_air_options {
   unsigned workgroup_size[3]; /* Exact nonzero pipeline specialization. */
   unsigned max_instructions; /* Nonzero caller-supplied compilation budget. */
   stela_air_bind_buffer bind_buffer;
   void *binding_data;
   /* Select one buffer callback, never both. Zero-initialized additions retain
    * the original global64 path. SSBO mode uses the existing NIR SSBO intrinsics
    * and size query; the backend must lower these through its actual resource
    * ABI. Full 64-bit offsets are checked before narrowing; out-of-view loads
    * return zero and stores are discarded, never wrapped into another offset.
    * Every runtime view must pass stela_air_ssbo_view_valid before dispatch. */
   stela_air_bind_ssbo bind_ssbo;
   unsigned ssbo_count;
   enum stela_air_fp_profile fp_profile;
   stela_air_bind_threadgroup bind_threadgroup;
   /* Explicit target/backend representability limit. Zero refuses shared
    * resources/barriers; NAK callers must additionally stay within UINT16_MAX
    * before its original smem_size conversion. No target limit is inferred. */
   unsigned max_threadgroup_bytes;
};

/* Input is the hash-checked raw AIR bitcode selected by the archive reader.
 * Success transfers ownership of a real NIR shader to the caller (ralloc_free).
 * Failure returns NULL, destroys partial NIR, and reports an explicit error.
 * The caller retains input bytes/digest/build ID and records the exact selected
 * target, workgroup specialization and argument mapping alongside vendor output.
 * Structured diamonds/triangles and pre-tested natural loops retain exact
 * integer/FP32 scalar/vector PHIs. Loops require one unconditional preheader,
 * one distinct unconditional latch and one header exit; iterations are uncapped.
 * One final return, <=128 blocks/header-or-merge PHIs and <=32 nested constructs.
 * Nested/multi-latch/body-exit loops, pointer PHIs and general CFGs are refused.
 * Qualified AS3 storage is returned as explicit shared32 NIR with the original
 * aligned layout in info.shared_size. Dynamic view sizes/alignment and target
 * byte limits are caller specializations, never inferred GPU capabilities.
 * Only the observed ordinary-shared collective barrier form is supported.
 * LLVM is a native compiler library, not a hostile-input sandbox.
 */
nir_shader *stela_air_to_nir(const void *bitcode, size_t size, const char *entry,
                            const nir_shader_compiler_options *nir_options,
                            const struct stela_air_options *options,
                            struct stela_air_error *error);
#endif
