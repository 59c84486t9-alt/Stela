/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_TO_NIR_H
#define STELA_AIR_TO_NIR_H

#include "compiler/nir/nir_builder.h"
#include "air_metadata.h"
#include <stddef.h>

/* User-space compiler boundary. LLVM and Mesa must be built for this process's
 * architecture and linked with their normal runtime services. No GPU access,
 * IOKit call, Metal device registration, or command submission happens here.
 */
/* Resolve a validated Metal buffer binding to a 64-bit device virtual address.
 * The caller owns resource lifetime, size/access validation, actual allocation,
 * residency and runtime argument ABI. Returning NULL refuses compilation. This
 * callback must build straight-line NIR in the entry prelude; it must not
 * introduce control flow, submit commands or mutate resources.
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

/* Additive VS/FS frontend. No runtime/Metal pipeline is constructed. resources
 * supplies the same actual AS2-readonly view/bounds and FP contract as compute;
 * workgroup_size/max_threadgroup_bytes/bind_threadgroup must be zero/NULL here.
 * AS2 and AS1 are not interchangeable permissions/address spaces. All declared
 * varying identifiers/types must match the explicit shared VS/FS map. Target
 * IO limits are real caller facts, not inferred Metal family advertisement.
 * Returned NIR owns variables/names; no descriptor/map/input pointer survives.
 * Original NIR stage IO lowering belongs to the actual vendor compiler owner.
 * Packed flat FP32 scalar/vector aggregates assembled through insertvalue may
 * cross PHIs, including loop backedges; every reachable incoming leaf must be
 * completely defined. Nested/unpacked aggregates, other leaf types and direct
 * aggregate constants remain unsupported. The source path awaits qualification.
 * As with the compute entrypoint, nir_options must outlive the returned shader;
 * the owned vendor compiler wrapper must retain a stable qualified options copy. */
struct stela_air_stage_options {
   enum stela_air_stage stage;
   struct stela_air_options resources;
   const struct stela_air_varying_slot *varyings;
   unsigned varying_count, max_varying_slots;
};
nir_shader *stela_air_stage_to_nir(const void *, size_t, const char *entry,
                                  const nir_shader_compiler_options *,
                                  const struct stela_air_stage_options *,
                                  struct stela_air_error *);

/* Input is the hash-checked raw AIR bitcode selected by the archive reader.
 * Success transfers ownership of a real NIR shader to the caller (ralloc_free).
 * Failure returns NULL, destroys partial NIR, and reports an explicit error.
 * The caller retains input bytes/digest/build ID and records the exact selected
 * target, workgroup specialization and argument mapping alongside vendor output.
 * Reachable integer/FP32 scalar/vector CFGs use the original LLVM switch
 * legalization and Mesa goto-to-if structurization, including numeric PHIs,
 * early returns, nested/multiple-latch loops and irreducible entries. Original
 * and legalized inputs share the caller's instruction budget; total switch
 * cases also obey that budget before legalization. Production has no iteration
 * cap. Pointer PHIs require a pre-emission, cycle-aware proof of one validated
 * resource root and homogeneous AS2 root/derived reflection state. The numeric
 * PHI carries only the offset/VA; its root's exact rights/resource/view metadata
 * remain static and every incoming edge must agree. Pointer eq/ne require the
 * same resource authority, ignoring only AS2 root-reflection typing state;
 * relational and cross-resource comparisons remain explicit refusals.
 * Integer division/remainder admit i8/i16/i32/i64 scalar or fixed2-4 lanes
 * through original NIR udiv/idiv/umod/irem. Only LLVM-defined inputs constrain
 * their values: zero divisors and signed MIN/-1 division/remainder are UB;
 * inexact exact-div results are poison. No result/trap behavior is promised
 * there. Direct undef/poison and freeze remain refused. Target owners must
 * run their actual Mesa division/int64 lowering; this source unit is UNRUN.
 * Cross-resource joins,
 * rootless/undef/poison/integer-derived pointers, unsupported pointer producers,
 * compute aggregate PHIs and reachable unsupported terminators are refused
 * explicitly. Unreachable blocks consume the budget but emit no
 * effects. These source paths await semantic/vendor qualification; no family
 * capability follows from accepting a control-flow shape.
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
