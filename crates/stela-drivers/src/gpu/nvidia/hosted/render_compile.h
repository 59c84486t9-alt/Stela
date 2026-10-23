/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_RENDER_COMPILE_H
#define STELA_NVIDIA_RENDER_COMPILE_H
#include "compiler/air_to_nir.h"
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#ifdef __cplusplus
extern "C" {
#endif
#define STELA_NVIDIA_RENDER_ABI 1u
#define STELA_NVIDIA_RENDER_ROW_BYTES 16u
#define STELA_NVIDIA_RENDER_TABLE_ALIGNMENT 64u
struct stela_metal_assembly;
struct stela_metal_stage_view;
struct stela_nvidia_air_buffer_view;
struct stela_nvidia_render_compilation;
enum stela_nvidia_render_status {
    STELA_NVIDIA_RENDER_OK, STELA_NVIDIA_RENDER_INVALID, STELA_NVIDIA_RENDER_UNSUPPORTED,
    STELA_NVIDIA_RENDER_DEVICE, STELA_NVIDIA_RENDER_LIMIT, STELA_NVIDIA_RENDER_ALLOCATION,
    STELA_NVIDIA_RENDER_FRONTEND, STELA_NVIDIA_RENDER_BACKEND, STELA_NVIDIA_RENDER_BINDING,
};
struct stela_nvidia_render_error {
    enum stela_nvidia_render_status status;
    struct stela_air_error air;
    char detail[256];
};
struct stela_nvidia_render_options {
    uint32_t size, abi, max_instructions, max_code_bytes, max_constant_bytes;
    uint32_t max_varying_slots, argument_cbuf[2], constant_data_cbuf[2], record_assembly;
    enum stela_air_fp_profile fp_profile;
    /* All raster facts are known. Indices 0/1 always mean VS/FS, never TYPE or
     * stela_air_stage enum values. Original key, no private policy enum. */
    struct nak_fs_key fs_key;
    uint32_t raster_samples;
    bool sample_shading_enable, depth_stencil_feedback, conservative_underestimate;
    float min_sample_shading;
};
struct stela_nvidia_render_binding {
    struct stela_air_buffer buffer;
    uint32_t cbuf_offset;
};
struct stela_nvidia_render_upload {
    /* Immutable ordinary CPU bytes, never PA/IOVA/GPU VA. Exact original header,
     * code and padded constant data; unused prefix/gaps are deterministic zero.
     * A genuine shader-VM owner must allocate with alignment, upload/publish,
     * bind data_cbuf, and retain all resources through real retirement. */
    const void *bytes;
    uint32_t size, alignment, header_offset, header_size, code_offset;
    uint32_t data_offset, data_size, data_cbuf;
};
struct stela_nvidia_render_provenance {
    struct stela_nvidia_render_options options;
    struct nv_device_info device;
    struct nak_constant_offset_info base_layout, graphics_layout;
    uint64_t nak_debug_flags;
};
/* Hosted same-process CPU owner, no Metal PSO/GPU allocation/initialization or
 * submission. Borrow the genuine matching initialized retained NAK/device only
 * during this call. Actual nak_nir_options must exist with cb_data==NULL before
 * any wrapper allocation; owned options retain the original implementation's
 * callbacks/code, whose loaded lifetime must cover this result. SM/warps/options
 * checks do not authenticate invented caller device records or GPU readiness.
 *
 * Both distinct unique stage input owners are consumed ONLY on success. Their
 * slots and output storage must be distinct. All error/options/source/result
 * and owning-slot storage must be readable/writable as indicated, disjoint as
 * applicable, and serialized against mutation/destruction; in particular error
 * cannot alias either source, options or any slot. Success clears both input slots
 * and publishes one complete result with no allocation in that commit. Every
 * failure leaves both inputs unchanged and output empty. Canonical selected
 * VS/FS identities may come from different libraries. Output owns source bytes,
 * descriptors/provenance, options, NIR, original bins and CPU upload images;
 * temporary LLVM/compiler/device/request pointers do not survive. Destruction
 * is serialized with all immutable borrows and destroys bins/NIR before sources.
 * Standard libc supplies wrapper metadata; original compiler fatal/OOM remains
 * the host compiler-process owner's contract. */
enum stela_nvidia_render_status stela_nvidia_render_compile(const struct nv_device_info *,
    const struct nak_compiler *, struct stela_metal_assembly **vertex,
    struct stela_metal_assembly **fragment, const struct stela_nvidia_render_options *,
    struct stela_nvidia_render_compilation **, struct stela_nvidia_render_error *);

/* Exact per-stage dynamic cbuf ABI: up to 128 used readonly AS2 buffer rows,
 * metadata ordered by LLVM ordinal, each LE {VA64, exact byte length32, zero32}.
 * Any nonzero bounded view is allowed, including partial elements; reflected
 * type size is stride, not whole allocation length. Original bridge checks each
 * access at 64 bits before narrowing. No VA is compiled into the shader.
 *
 * Reuses the existing stela_nvidia_air_buffer_view record only; its owner/device
 * fields are preconditions established by a genuine dispatch/resource service,
 * not authentication. Pack checks exact map/count/rights/alignment/VA-width/spans
 * before any output write, allocates nothing, and supplies no residency/VM epoch,
 * coherency, GPU mapping or fences. Output is a disjoint ordinary CPU writable
 * span. Tables require max(original cbuf alignment,64) when actually uploaded;
 * per-stage cbuf slots are separate hardware binding groups. No compute QMD is
 * formed or reinterpreted. Zero used buffers requires no views/output/table. */
enum stela_nvidia_render_status stela_nvidia_render_pack_arguments(
    const struct stela_nvidia_render_compilation *, enum stela_air_stage,
    const struct nv_device_info *, unsigned va_bits, const struct stela_nvidia_air_buffer_view *,
    uint32_t count, void *output, size_t output_bytes);
const struct nak_shader_bin *stela_nvidia_render_binary(const struct stela_nvidia_render_compilation *, enum stela_air_stage);
const nir_shader *stela_nvidia_render_nir(const struct stela_nvidia_render_compilation *, enum stela_air_stage);
const struct stela_metal_stage_view *stela_nvidia_render_source(const struct stela_nvidia_render_compilation *, enum stela_air_stage);
const struct stela_nvidia_render_upload *stela_nvidia_render_upload(const struct stela_nvidia_render_compilation *, enum stela_air_stage);
const struct stela_nvidia_render_binding *stela_nvidia_render_bindings(const struct stela_nvidia_render_compilation *, enum stela_air_stage, uint32_t *count, uint32_t *table_bytes);
const struct stela_nvidia_render_provenance *stela_nvidia_render_provenance(const struct stela_nvidia_render_compilation *);
const nir_shader_compiler_options *stela_nvidia_render_nir_options(const struct stela_nvidia_render_compilation *);
void stela_nvidia_render_destroy(struct stela_nvidia_render_compilation **);
#ifdef __cplusplus
}
#endif
#endif
