/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_AIR_COMPILE_H
#define STELA_NVIDIA_AIR_COMPILE_H
#include "../../compiler/library_assembly.h"
#include "compiler/air_to_nir.h"
#include "../../compiler/threadgroup.h"
#include "compute.h"
#ifdef __cplusplus
extern "C" {
#endif

#define STELA_NV_AIR_ABI 1u
#define STELA_NV_AIR_ROW_BYTES 8u
#define STELA_NV_AIR_CBUF_ALIGNMENT 64u

enum stela_nv_air_status {
    STELA_NV_AIR_OK,
    STELA_NV_AIR_INVALID,
    STELA_NV_AIR_UNSUPPORTED,
    STELA_NV_AIR_DEVICE,
    STELA_NV_AIR_LIMIT,
    STELA_NV_AIR_ALLOCATION,
    STELA_NV_AIR_FRONTEND,
    STELA_NV_AIR_BACKEND,
    STELA_NV_AIR_BINDING,
};
struct stela_nv_air_options {
    uint32_t size, abi, workgroup_size[3], max_instructions, max_code_bytes;
    uint32_t argument_cbuf, record_assembly;
    enum stela_air_fp_profile fp_profile;
};
struct stela_nv_air_error {
    enum stela_nv_air_status status;
    struct stela_air_error air;
    char detail[256];
};
struct stela_nv_air_binding {
    /* Only original LLVM-used AS1 parameters require rows; every parameter's
     * complete reflection still appears in provenance.arguments. */
    struct stela_air_buffer buffer;
    uint32_t cbuf_offset;
};
/* Immutable same-process views, never pointer IPC or a cache wire format.
 * Source/compiler provenance remains absent for an archive unless independently
 * established by its real input owner; selecting an FP policy authenticates
 * nothing. The nondefault FP profile needs air_to_nir.h's independent build
 * qualification. The actual NAK options, layouts, device facts and debug flags
 * join source/workgroup/profile/bindings in the compiled specialization key. */
struct stela_nv_air_provenance {
    struct stela_metal_input_info input;
    struct stela_metal_input_entry entry;
    uint32_t selected_entry, entry_flags, library_flags, compiler_profile;
    uint32_t request_language, request_fast_math, argument_count;
    uint64_t air_offset, air_bytes;
    uint8_t air_sha256[32], source_sha256[32];
    struct stela_msl_build_identity build;
    const char *name, *target;
    const struct stela_air_argument_info *arguments;
    struct stela_nv_air_options options;
    struct nv_device_info device;
    struct nak_constant_offset_info base_layout, graphics_layout;
    uint64_t nak_debug_flags;
    struct stela_metal_threadgroup_specialization threadgroup;
};
struct stela_nv_air_compilation;

/* Hosted same-CPU compiler only. Device and compiler MUST be the matching real
 * initialized context from the retained Mesa build, not test topology or an
 * Apple CPU profile. We use the original nak_compiler declaration to check SM
 * and warp consistency; no C++/Rust object ABI is reconstructed. All inputs are
 * borrowed through this call only. Success retains no assembly/compiler/device
 * pointers. NIR/options/GLSL types and the original nak_shader_bin have owned
 * lifetimes. Failure preserves the empty sole-owning output slot.
 *
 * This first-party compute ABI dedicates one selected QMD cbuf slot (0..7) to
 * eight-byte LE GPU addresses in metadata argument order, with an explicit
 * Metal-index/LLVM-ordinal map. The complete extent is rounded to64B, <=64KiB.
 * The dispatch owner reserves that slot for this table, uploads/publishes it
 * and retains every resource through actual completion. No VA is in shader
 * code. No other cbuf reads/printf/images/samplers are admitted in this subset;
 * expanding it requires an explicit compatible layout contract.
 *
 * Dynamic AS3 requires compile_specialized with exact requested byte lengths. Static shared
 * lowering is retained if admitted by the canonical owner. Scratch/stack/barrier
 * requirements are real compiler facts and may outlive current plan support.
 * No GPU allocation, initialization, upload, submission or Metal PSO is created.
 * Wrapper allocation failures are typed. Original LLVM/Mesa/Rust fatal/OOM and
 * cancellation remain the normal compiler process owner's responsibility. */
/* Exact dispatch-size specialization; existing compile() delegates with NULL.
 * Request arrays are borrowed only during the call and copied into provenance.
 * Backend shared totals include these rows plus static layout, never expose
 * them as Metal staticThreadgroupMemoryLength or add dynamic bytes twice.
 * stela_metal_threadgroup_matches checks values only, not resource ownership. */
enum stela_nv_air_status stela_nv_air_compile_specialized(const struct nv_device_info *,
    const struct nak_compiler *, const struct stela_metal_assembly *, uint32_t selected_entry,
    const struct stela_nv_air_options *, const struct stela_metal_threadgroup_request *,
    struct stela_nv_air_compilation **,
    struct stela_nv_air_error *);

enum stela_nv_air_status stela_nv_air_compile(const struct nv_device_info *,
    const struct nak_compiler *, const struct stela_metal_assembly *, uint32_t selected_entry,
    const struct stela_nv_air_options *, struct stela_nv_air_compilation **,
    struct stela_nv_air_error *);

/* Actual live GPU view, not an allocator or proof created by these fields.
 * Match the live device pointer supplied to pack_arguments and retain a real
 * unique mapping/resource owner through dispatch completion. No caller boolean,
 * owner cookie or PCI tuple authenticates permissions, residency or device/VM
 * epoch. The actual dispatch service establishes those preconditions. Views may
 * alias when permitted by their genuine source/runtime contract. */
struct stela_nv_air_buffer_view {
    const struct nv_device_info *device;
    const void *owner;
    uint32_t argument, index, available_access;
    uint64_t allocation_va, allocation_bytes, offset, bytes;
};
/* Atomic bounded CPU table formation only: exact map/count, view spans, rights,
 * type alignment and declared unsigned VM-width arithmetic are checked before
 * writes. Device compiler facts must match the compiled target. Output is a
 * separate writable normal CPU span, never a cast GPU VA/MMIO mapping; retain
 * actual CPU ownership/cache coherency. A successful image must be uploaded to
 * a real64B-aligned cbuf allocation of table_bytes, bound at argument_cbuf via
 * the existing stela_nv_compute_encode. It neither pins views nor supplies
 * visibility/order/fences. No allocations occur in this function. Zero-buffer
 * code has table_bytes0 and needs no cbuf/view/output. All storage is disjoint
 * and serialized against mutation/destruction; errors preserve output bytes. */
enum stela_nv_air_status stela_nv_air_pack_arguments(const struct stela_nv_air_compilation *,
    const struct nv_device_info *, unsigned va_bits, const struct stela_nv_air_buffer_view *,
    uint32_t view_count, void *output, size_t output_bytes);

const struct nak_shader_bin *stela_nv_air_binary(const struct stela_nv_air_compilation *);
const nir_shader *stela_nv_air_nir(const struct stela_nv_air_compilation *);
const struct stela_nv_air_provenance *stela_nv_air_provenance(const struct stela_nv_air_compilation *);
const struct stela_nv_air_binding *stela_nv_air_bindings(const struct stela_nv_air_compilation *,
    uint32_t *count, uint32_t *table_bytes);
void stela_nv_air_destroy(struct stela_nv_air_compilation **);
#ifdef __cplusplus
}
#endif
#endif
