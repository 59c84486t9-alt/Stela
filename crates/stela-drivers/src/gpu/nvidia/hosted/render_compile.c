/* SPDX-License-Identifier: MIT */
#include "render_compile.h"
#include "../../compiler/library_assembly.h"
#include "air_compile.h" /* Reuse the existing immutable resource-view record. */
#include "nouveau/compiler/nak_private.h"
#include "nouveau/headers/nvidia/classes/cla097.h"
#include "nouveau/headers/nvidia/classes/clc597.h"
#include "util/ralloc.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBUF_COUNT 8u
#define ORIGINAL_CBUF_COUNT 32u
#define CBUF_BYTES 65536u
#define MAX_CODE (64u * 1024u * 1024u)
#define MAX_VARYINGS 32u
#define MAX_BINDINGS AIR_MAX_ARGUMENTS

struct render_stage {
    struct stela_metal_assembly *source;
    nir_shader *nir;
    struct nak_shader_bin *bin;
    struct stela_nv_render_binding bindings[MAX_BINDINGS];
    uint32_t binding_count, table_bytes;
    struct stela_nv_render_upload upload;
};
struct stela_nv_render_compilation {
    struct stela_nv_render_provenance provenance;
    nir_shader_compiler_options nir_options;
    struct stela_air_varying_slot varyings[MAX_VARYINGS];
    unsigned varying_count;
    struct render_stage stage[2];
    bool type_reference;
};
struct lower_context {
    const struct render_stage *stage;
    uint32_t table_cbuf, data_cbuf;
};
static enum stela_nv_render_status report(struct stela_nv_render_error *error,
    enum stela_nv_render_status status, const char *detail)
{
    if (error) { error->status = status; snprintf(error->detail, sizeof(error->detail), "%s", detail); }
    return status;
}
static int stage_index(enum stela_air_stage stage)
{
    return stage == STELA_AIR_VERTEX ? 0 : stage == STELA_AIR_FRAGMENT ? 1 : -1;
}
static const struct render_stage *get_stage(const struct stela_nv_render_compilation *owner,
    enum stela_air_stage stage)
{
    int index = stage_index(stage);
    return owner && index >= 0 ? &owner->stage[index] : NULL;
}
void stela_nv_render_destroy(struct stela_nv_render_compilation **slot)
{
    if (!slot || !*slot) return;
    struct stela_nv_render_compilation *owner = *slot; *slot = NULL;
    for (unsigned s = 0; s < 2; ++s) {
        struct render_stage *stage = &owner->stage[s];
        if (stage->bin) nak_shader_bin_destroy(stage->bin);
        ralloc_free(stage->nir);
        free((void *)stage->upload.bytes);
    }
    if (owner->type_reference) glsl_type_singleton_decref();
    for (unsigned s = 0; s < 2; ++s) stela_metal_assembly_destroy(&owner->stage[s].source);
    free(owner);
}
static bool device_valid(const struct nv_device_info *device)
{
    /* Original sm_match admits every uint8 SM>=20; its 70+ branch has no
     * upper cap. Warps are an original uint8 field, checked against the actual
     * compiler below. Fermi's historical 80B-header/64B-alignment assertion is
     * an explicit upload-image hold; it is not a backend eligibility limit. */
    return device->sm >= 20 && device->max_warps_per_mp && device->cls_eng3d != 0;
}
static bool layout_valid(const struct nak_constant_offset_info *layout)
{
    /* Original FS lookup tables use byte locations and 16-bit pass masks for
     * at most 16 samples. The printf location is an 8-byte pointer, not data. */
    return layout->sample_info_cb < ORIGINAL_CBUF_COUNT && layout->printf_cb < ORIGINAL_CBUF_COUNT &&
        layout->sample_locations_offset <= CBUF_BYTES - 16u &&
        layout->sample_masks_offset <= CBUF_BYTES - 16u * sizeof(struct nak_sample_mask) &&
        !(layout->sample_masks_offset % sizeof(struct nak_sample_mask)) &&
        layout->printf_buffer_offset <= CBUF_BYTES - 8u && !(layout->printf_buffer_offset % 8u);
}
static bool slot_free(uint32_t slot, const struct nak_compiler *compiler)
{
    return slot < CBUF_COUNT && slot != nak_const_offsets_base.sample_info_cb &&
        slot != nak_const_offsets_base.printf_cb &&
        slot != nak_const_offsets_turing_graphics.sample_info_cb &&
        slot != nak_const_offsets_turing_graphics.printf_cb;
}
static bool same_buffer(const struct stela_air_buffer *a, const struct stela_air_buffer *b)
{
    return a->argument == b->argument && a->index == b->index &&
        a->address_space == b->address_space && a->access == b->access &&
        a->type_size == b->type_size && a->type_alignment == b->type_alignment;
}
static bool prepare_bindings(struct render_stage *stage, const struct stela_air_stage_entry *entry)
{
    for (unsigned i = 0; i < entry->input_count; ++i) {
        const struct stela_air_stage_io *input = &entry->inputs[i];
        if (input->semantic != STELA_AIR_STAGE_BUFFER || !input->used) continue;
        const struct stela_air_buffer *buffer = &input->buffer;
        if (stage->binding_count == MAX_BINDINGS || buffer->address_space != 2 ||
            buffer->access != STELA_AIR_READ || !buffer->type_size || !buffer->type_alignment ||
            (buffer->type_alignment & (buffer->type_alignment - 1))) return false;
        for (unsigned j = 0; j < stage->binding_count; ++j) {
            if (stage->bindings[j].buffer.argument == buffer->argument ||
                stage->bindings[j].buffer.index == buffer->index) return false;
        }
        const unsigned row = stage->binding_count++;
        stage->bindings[row] = (struct stela_nv_render_binding){
            .buffer = *buffer, .cbuf_offset = row * STELA_NV_RENDER_ROW_BYTES};
    }
    stage->table_bytes = align(stage->binding_count * STELA_NV_RENDER_ROW_BYTES,
                               STELA_NV_RENDER_TABLE_ALIGNMENT);
    return stage->table_bytes <= CBUF_BYTES;
}
static bool bind_buffer(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
    const struct render_stage *stage = data;
    for (unsigned i = 0; i < stage->binding_count; ++i) {
        if (!same_buffer(buffer, &stage->bindings[i].buffer)) continue;
        *slot = i; return true;
    }
    return false;
}
/* Shader constant data is uploaded behind the code and bound as its own
 * constant buffer, so each load reads that buffer at its base plus offset. */
static bool lower_constant_load(nir_builder *b, nir_intrinsic_instr *load, uint32_t cbuf)
{
    b->cursor = nir_before_instr(&load->instr);
    nir_def *offset = nir_iadd_imm(b, load->src[0].ssa, nir_intrinsic_base(load));
    nir_def *data = nir_ldc_nv(b, load->def.num_components, load->def.bit_size,
        nir_imm_int(b, (int)cbuf), offset,
        .align_mul = nir_intrinsic_align_mul(load), .align_offset = nir_intrinsic_align_offset(load));
    nir_def_replace(&load->def, data);
    return true;
}
static bool lower_resource(nir_builder *b, nir_intrinsic_instr *intrin, void *data)
{
    const struct lower_context *ctx = data;
    if (intrin->intrinsic == nir_intrinsic_load_constant)
        return lower_constant_load(b, intrin, ctx->data_cbuf);
    if (intrin->intrinsic != nir_intrinsic_load_ssbo_address &&
        intrin->intrinsic != nir_intrinsic_get_ssbo_size) return false;
    /* Checked for every occurrence before this pass. */
    unsigned slot = (unsigned)nir_src_as_uint(intrin->src[0]);
    bool address = intrin->intrinsic == nir_intrinsic_load_ssbo_address;
    b->cursor = nir_before_instr(&intrin->instr);
    nir_def *value = nir_ldc_nv(b, 1, address ? 64 : 32,
        nir_imm_int(b, (int)ctx->table_cbuf), nir_imm_int(b, 0),
        .base = ctx->stage->bindings[slot].cbuf_offset + (address ? 0u : 8u),
        .align_mul = address ? 8 : 4, .align_offset = 0);
    nir_def_rewrite_uses(&intrin->def, value);
    nir_instr_remove(&intrin->instr);
    return true;
}
static bool validate_resources(const struct render_stage *stage, bool lowered, bool final,
    const struct lower_context *ctx)
{
    nir_shader *nir = stage->nir;
    nir_foreach_function_impl(impl, nir) nir_foreach_block_unstructured(block, impl) nir_foreach_instr(instr, block) {
        if (instr->type != nir_instr_type_intrinsic) continue;
        nir_intrinsic_instr *intrin = nir_instr_as_intrinsic(instr);
        switch (intrin->intrinsic) {
        case nir_intrinsic_load_constant: {
            /* Original NIR range describes the complete byte interval starting
             * at base; 0 is unknown. Trust no made-up buffer length or folded
             * offset. Original dynamic offset semantics stay unchanged. */
            if (nir_intrinsic_base(intrin) < 0) return false;
            uint32_t base = (uint32_t)nir_intrinsic_base(intrin), range = nir_intrinsic_range(intrin);
            uint32_t access = intrin->def.num_components * intrin->def.bit_size / 8u;
            if (lowered) { if (!nir_def_is_unused(&intrin->def)) return false; break; }
            if (!range || !access || base > nir->constant_data_size ||
                range > nir->constant_data_size - base || access > range ||
                intrin->src[0].ssa->bit_size != 32) return false;
            if (nir_src_is_const(intrin->src[0]) && nir_src_as_uint(intrin->src[0]) > range - access) return false;
            break;
        }
        case nir_intrinsic_load_ssbo_address:
        case nir_intrinsic_get_ssbo_size:
            if (lowered || !nir_src_is_const(intrin->src[0]) ||
                nir_src_as_uint(intrin->src[0]) >= stage->binding_count) return false;
            if (intrin->intrinsic == nir_intrinsic_load_ssbo_address &&
                (!nir_src_is_const(intrin->src[1]) || nir_src_as_uint(intrin->src[1]) != 0)) return false;
            break;
        case nir_intrinsic_ldc_nv:
            if (!lowered || !nir_src_is_const(intrin->src[0]) || intrin->src[1].ssa->bit_size != 32) return false;
            if (nir_src_as_uint(intrin->src[0]) == ctx->table_cbuf) {
                if (nir_intrinsic_base(intrin) < 0 || !nir_src_is_const(intrin->src[1])) return false;
                uint64_t offset = (uint32_t)nir_intrinsic_base(intrin) + nir_src_as_uint(intrin->src[1]);
                uint32_t access = intrin->def.num_components * intrin->def.bit_size / 8u;
                uint32_t row_bytes = final ? STELA_NV_RENDER_ROW_BYTES : 12u;
                if (!access || offset >= stage->binding_count * STELA_NV_RENDER_ROW_BYTES ||
                    offset % STELA_NV_RENDER_ROW_BYTES >= row_bytes ||
                    access > row_bytes - offset % STELA_NV_RENDER_ROW_BYTES) return false;
                if (!final && (intrin->def.num_components != 1 || (access != 4 && access != 8) ||
                    offset % STELA_NV_RENDER_ROW_BYTES != (access == 8 ? 0u : 8u))) return false;
            } else if (nir_src_as_uint(intrin->src[0]) != ctx->data_cbuf || !nir->constant_data_size) return false;

            break;
        case nir_intrinsic_load_global:
        case nir_intrinsic_load_global_constant:
            if (!stage->binding_count || nir_src_is_const(intrin->src[0])) return false;
            break;
        case nir_intrinsic_load_ssbo: case nir_intrinsic_store_ssbo: case nir_intrinsic_store_global:
        case nir_intrinsic_load_shared: case nir_intrinsic_store_shared:
        case nir_intrinsic_load_ubo: case nir_intrinsic_load_printf_buffer_address:
        case nir_intrinsic_load_printf_buffer_size:
            return false;
        default: break;
        }
    }
    return true;
}
static enum stela_nv_render_status make_upload(struct render_stage *stage, const struct nv_device_info *device,
    uint32_t data_cbuf, uint32_t max_constant_bytes)
{
    const struct nak_shader_info *info = &stage->bin->info;
    if (device->cls_eng3d < KEPLER_A) return STELA_NV_RENDER_UNSUPPORTED;
    if (info->stage != MESA_SHADER_VERTEX && info->stage != MESA_SHADER_FRAGMENT) return STELA_NV_RENDER_BACKEND;
    /* NVK's upload layout for a vertex or fragment shader on Kepler and
     * later: the shader program header (20 words before Turing, 32 from
     * Turing) ends where the 128-byte aligned code begins. Constant buffers
     * bind at 256-byte alignment before Turing and 64-byte from Turing. */
    const bool turing = device->cls_eng3d >= TURING_A;
    const uint32_t header = turing ? 32u * 4u : 20u * 4u, code_offset = 128u;
    const uint32_t header_offset = code_offset - header, cbuf_align = turing ? 64u : 256u;
    /* Bound every addition and alignment first. */
    if (header > sizeof(info->hdr) || stage->bin->code_size > UINT32_MAX - code_offset ||
        stage->nir->constant_data_size > max_constant_bytes ||
        stage->nir->constant_data_size > CBUF_BYTES ||
        stage->nir->constant_data_size > UINT32_MAX - (cbuf_align - 1u)) return STELA_NV_RENDER_LIMIT;
    uint32_t data_size = align(stage->nir->constant_data_size, cbuf_align);
    uint32_t size = code_offset + stage->bin->code_size;
    uint32_t data_offset = 0, alignment = code_offset;
    if (data_size) {
        if (!stage->nir->constant_data) return STELA_NV_RENDER_BACKEND;
        if (data_size > max_constant_bytes || data_size > CBUF_BYTES ||
            size > UINT32_MAX - (cbuf_align - 1u)) return STELA_NV_RENDER_LIMIT;
        data_offset = align(size, cbuf_align);
        if (data_size > UINT32_MAX - data_offset) return STELA_NV_RENDER_LIMIT;
        size = data_offset + data_size; alignment = MAX2(alignment, cbuf_align);
    }
    void *bytes = calloc(1, size);
    if (!bytes) return STELA_NV_RENDER_ALLOCATION;
    memcpy((char *)bytes + header_offset, info->hdr, header);
    memcpy((char *)bytes + code_offset, stage->bin->code, stage->bin->code_size);
    if (data_size) memcpy((char *)bytes + data_offset, stage->nir->constant_data, stage->nir->constant_data_size);
    stage->upload = (struct stela_nv_render_upload){.bytes = bytes, .size = size,
        .alignment = alignment, .header_offset = header_offset, .header_size = header,
        .code_offset = code_offset, .data_offset = data_offset, .data_size = data_size, .data_cbuf = data_cbuf};
    return STELA_NV_RENDER_OK;
}
enum stela_nv_render_status stela_nv_render_compile(const struct nv_device_info *device,
    const struct nak_compiler *compiler, struct stela_metal_assembly **vertex,
    struct stela_metal_assembly **fragment, const struct stela_nv_render_options *options,
    struct stela_nv_render_compilation **output, struct stela_nv_render_error *error)
{
    if (error) memset(error, 0, sizeof(*error));
    if (!device || !compiler || !vertex || !fragment || vertex == fragment ||
        (void *)vertex == (void *)output || (void *)fragment == (void *)output ||
        !*vertex || !*fragment || *vertex == *fragment || !output || *output || !options ||
        options->size != sizeof(*options) || options->abi != STELA_NV_RENDER_ABI)
        return report(error, STELA_NV_RENDER_INVALID, "Distinct unique stage owners and empty output required");
    if (!device_valid(device) || compiler->sm != device->sm || compiler->warps_per_sm != device->max_warps_per_mp)
        return report(error, STELA_NV_RENDER_DEVICE, "Matching original initialized NAK/device context required");
    const nir_shader_compiler_options *actual_options = nak_nir_options(compiler);
    if (!actual_options || actual_options->cb_data)
        return report(error, STELA_NV_RENDER_UNSUPPORTED, "Borrowed compiler option callback data refused before allocation");
    if (device->cls_eng3d < KEPLER_A)
        return report(error, STELA_NV_RENDER_UNSUPPORTED, "Original Fermi graphics upload alignment is unsupported");
    if (!options->max_instructions || !options->max_code_bytes || options->max_code_bytes > MAX_CODE ||
        !options->max_constant_bytes || options->max_constant_bytes > CBUF_BYTES ||
        !options->max_varying_slots || options->max_varying_slots > MAX_VARYINGS)
        return report(error, STELA_NV_RENDER_LIMIT, "Explicit bounded code/constants/IO budgets required");
    if (options->record_assembly > 1 ||
        (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT && options->fp_profile != STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41) ||
        !options->raster_samples || options->raster_samples > 16 ||
        (options->raster_samples & (options->raster_samples - 1)) ||
        !isfinite(options->min_sample_shading) || options->min_sample_shading < 0 || options->min_sample_shading > 1 ||
        options->fs_key.pad || options->fs_key.force_sample_shading != options->sample_shading_enable ||
        options->fs_key.zs_self_dep != options->depth_stencil_feedback ||
        options->fs_key.uses_underestimate != options->conservative_underestimate)
        return report(error, STELA_NV_RENDER_UNSUPPORTED, "Explicit known raster/sample/original FS-key facts required");
    if (!layout_valid(&nak_const_offsets_base) || !layout_valid(&nak_const_offsets_turing_graphics))
        return report(error, STELA_NV_RENDER_UNSUPPORTED, "Original compiler constant layout not representable");
    for (unsigned s = 0; s < 2; ++s) {
        if (!slot_free(options->argument_cbuf[s], compiler) || !slot_free(options->constant_data_cbuf[s], compiler) ||
            options->argument_cbuf[s] == options->constant_data_cbuf[s])
            return report(error, STELA_NV_RENDER_UNSUPPORTED, "Per-stage argument/data slots must be disjoint from original layouts");
    }
    struct stela_metal_assembly *sources[2] = {*vertex, *fragment};
    const struct stela_metal_stage_view *views[2];
    struct stela_metal_input_view raw[2];
    for (unsigned s = 0; s < 2; ++s) {
        views[s] = stela_metal_assembly_stage(sources[s]);
        if (!views[s] || views[s]->size != sizeof(*views[s]) || views[s]->abi != STELA_METAL_ASSEMBLY_ABI ||
            views[s]->reserved || !views[s]->identity || !views[s]->reflection || !views[s]->provenance ||
            views[s]->identity->entry.kind != s || views[s]->reflection->stage != (s ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX) ||
            views[s]->provenance->entries || views[s]->provenance->entry_count)
            return report(error, STELA_NV_RENDER_INVALID, "Genuine selected canonical VS/FS owners required");
        raw[s] = (struct stela_metal_input_view){.size = sizeof(raw[s]), .abi = STELA_METAL_INPUT_ABI};
        const struct stela_metal_function_record *identity = views[s]->identity;
        if (stela_metal_assembly_original(sources[s], &raw[s], NULL) != STELA_METAL_ASSEMBLY_OK ||
            identity->air_offset > raw[s].length || identity->air_bytes > raw[s].length - identity->air_offset ||
            !identity->air_bytes || identity->air_bytes > AIR_MAX_BITCODE_BYTES)
            return report(error, STELA_NV_RENDER_INVALID, "Invalid canonical stage raw span");
    }
    struct stela_nv_render_compilation *owner = calloc(1, sizeof(*owner));
    if (!owner) return report(error, STELA_NV_RENDER_ALLOCATION, "Render owner allocation failed");
    owner->provenance = (struct stela_nv_render_provenance){.options = *options, .device = *device,
        .base_layout = nak_const_offsets_base, .graphics_layout = nak_const_offsets_turing_graphics,
        .nak_debug_flags = nak_debug_flags(compiler)};
    owner->nir_options = *actual_options;
    struct stela_air_error air_error;
    enum stela_nv_render_status status = STELA_NV_RENDER_OK;
    if (!stela_air_link_stage_io(views[0]->reflection, views[1]->reflection, options->max_varying_slots,
        owner->varyings, MAX_VARYINGS, &owner->varying_count, &air_error)) {
        if (error) error->air = air_error;
        status = report(error, STELA_NV_RENDER_FRONTEND, "Canonical stage IO does not link"); goto fail;
    }
    glsl_type_singleton_init_or_ref(); owner->type_reference = true;
    for (unsigned s = 0; s < 2; ++s) {
        struct render_stage *stage = &owner->stage[s];
        if (!prepare_bindings(stage, views[s]->reflection)) {
            status = report(error, STELA_NV_RENDER_BINDING, "Unsupported or duplicate used AS2 buffer map"); goto fail;
        }
        struct stela_air_stage_options air = {.stage = s ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX,
            .resources = {.max_instructions = options->max_instructions, .bind_ssbo = stage->binding_count ? bind_buffer : NULL,
                .binding_data = stage, .ssbo_count = stage->binding_count, .fp_profile = options->fp_profile},
            .varyings = owner->varyings, .varying_count = owner->varying_count,
            .max_varying_slots = options->max_varying_slots};
        const struct stela_metal_function_record *identity = views[s]->identity;
        stage->nir = stela_air_stage_to_nir(raw[s].bytes + identity->air_offset, (size_t)identity->air_bytes,
            views[s]->reflection->name, &owner->nir_options, &air, &air_error);
        if (!stage->nir) {
            if (error) error->air = air_error;
            status = report(error, STELA_NV_RENDER_FRONTEND, "Shared frontend refused selected stage"); goto fail;
        }
        if (stage->nir->info.shared_size) {
            status = report(error, STELA_NV_RENDER_UNSUPPORTED, "Render shared storage unsupported"); goto fail;
        }
        nak_preprocess_nir(stage->nir, compiler);
        const nir_lower_ssbo_options ssbo = {0};
        nir_lower_ssbo(stage->nir, &ssbo);
        const struct lower_context lower = {.stage = stage, .table_cbuf = options->argument_cbuf[s],
            .data_cbuf = options->constant_data_cbuf[s]};
        if (!validate_resources(stage, false, false, &lower)) {
            status = report(error, STELA_NV_RENDER_UNSUPPORTED, "Unsupported constant/resource NIR contract"); goto fail;
        }
        nir_shader_intrinsics_pass(stage->nir, lower_resource, nir_metadata_none, (void *)&lower);
        if (!validate_resources(stage, true, false, &lower)) {
            status = report(error, STELA_NV_RENDER_UNSUPPORTED, "Unexpected dynamic cbuf/resource graph"); goto fail;
        }
        nir_validate_shader(stage->nir, "owned render original resource lowering");
        stage->bin = nak_compile_shader(stage->nir, options->record_assembly != 0, compiler, 0,
            s ? &options->fs_key : NULL, false);
        if (!stage->bin || !stage->bin->code || !stage->bin->code_size ||
            stage->bin->info.stage != (s ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX) ||
            stage->bin->info.sm != device->sm) {
            status = report(error, STELA_NV_RENDER_BACKEND, "Original NAK stage output unavailable/inconsistent"); goto fail;
        }
        if (!validate_resources(stage, true, true, &lower)) {
            status = report(error, STELA_NV_RENDER_UNSUPPORTED, "Original postprocess requires an unbound resource"); goto fail;
        }
        if (stage->bin->code_size > options->max_code_bytes ||
            stage->nir->constant_data_size > options->max_constant_bytes) {
            status = report(error, STELA_NV_RENDER_LIMIT, "Original output exceeds explicit budget"); goto fail;
        }
        status = make_upload(stage, device, options->constant_data_cbuf[s], options->max_constant_bytes);
        if (status) {
            report(error, status, "Bounded original upload image unavailable"); goto fail;
        }
    }
    /* No fallible work or callbacks after the ownership commit begins. */
    owner->stage[0].source = *vertex; owner->stage[1].source = *fragment;
    *vertex = NULL; *fragment = NULL; *output = owner;
    return report(error, STELA_NV_RENDER_OK, "");
fail:
    stela_nv_render_destroy(&owner);
    return status;
}
static bool within_vm(uint64_t address, uint64_t bytes, unsigned bits)
{
    if (!address || !bytes || !bits || bits > 64) return false;
    uint64_t last = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1u;
    return address <= last && bytes - 1u <= last - address;
}
enum stela_nv_render_status stela_nv_render_pack_arguments(const struct stela_nv_render_compilation *owner,
    enum stela_air_stage stage_kind, const struct nv_device_info *device, unsigned va_bits,
    const struct stela_nv_air_buffer_view *views, uint32_t count, void *output, size_t bytes)
{
    const struct render_stage *stage = get_stage(owner, stage_kind);
    if (!stage || !device || !device_valid(device) || !va_bits || va_bits > 64) return STELA_NV_RENDER_INVALID;
    const struct nv_device_info *compiled = &owner->provenance.device;
    if (device->sm != compiled->sm || device->max_warps_per_mp != compiled->max_warps_per_mp ||
        device->cls_eng3d != compiled->cls_eng3d) return STELA_NV_RENDER_DEVICE;
    if (count != stage->binding_count || (count && (!views || !output)) || bytes < stage->table_bytes)
        return STELA_NV_RENDER_BINDING;
    uint64_t addresses[MAX_BINDINGS]; uint32_t lengths[MAX_BINDINGS];
    bool seen[MAX_BINDINGS] = {false};
    for (unsigned i = 0; i < count; ++i) {
        const struct stela_nv_air_buffer_view *view = &views[i];
        unsigned row;
        for (row = 0; row < stage->binding_count; ++row)
            if (stage->bindings[row].buffer.argument == view->argument && stage->bindings[row].buffer.index == view->index) break;
        if (row == stage->binding_count || seen[row]) return STELA_NV_RENDER_BINDING;
        seen[row] = true;
        const struct stela_air_buffer *buffer = &stage->bindings[row].buffer;
        if (view->device != device || !view->owner || !view->bytes || view->bytes > UINT32_MAX ||
            !(view->available_access & STELA_AIR_READ) || (view->available_access & ~(uint32_t)STELA_AIR_READ_WRITE) ||
            view->offset > view->allocation_bytes || view->bytes > view->allocation_bytes - view->offset ||
            !within_vm(view->allocation_va, view->allocation_bytes, va_bits) ||
            view->offset > UINT64_MAX - view->allocation_va ||
            (view->allocation_va + view->offset) % buffer->type_alignment) return STELA_NV_RENDER_BINDING;
        addresses[row] = view->allocation_va + view->offset;
        lengths[row] = (uint32_t)view->bytes;
    }
    if (stage->table_bytes) memset(output, 0, stage->table_bytes);
    for (unsigned i = 0; i < count; ++i) {
        uint8_t *row = (uint8_t *)output + stage->bindings[i].cbuf_offset;
        for (unsigned byte = 0; byte < 8; ++byte) row[byte] = (uint8_t)(addresses[i] >> (8 * byte));
        for (unsigned byte = 0; byte < 4; ++byte) row[8 + byte] = (uint8_t)(lengths[i] >> (8 * byte));
    }
    return STELA_NV_RENDER_OK;
}
const struct nak_shader_bin *stela_nv_render_binary(const struct stela_nv_render_compilation *owner, enum stela_air_stage kind)
{ const struct render_stage *stage = get_stage(owner, kind); return stage ? stage->bin : NULL; }
const nir_shader *stela_nv_render_nir(const struct stela_nv_render_compilation *owner, enum stela_air_stage kind)
{ const struct render_stage *stage = get_stage(owner, kind); return stage ? stage->nir : NULL; }
const struct stela_metal_stage_view *stela_nv_render_source(const struct stela_nv_render_compilation *owner, enum stela_air_stage kind)
{ const struct render_stage *stage = get_stage(owner, kind); return stage ? stela_metal_assembly_stage(stage->source) : NULL; }
const struct stela_nv_render_upload *stela_nv_render_upload(const struct stela_nv_render_compilation *owner, enum stela_air_stage kind)
{ const struct render_stage *stage = get_stage(owner, kind); return stage ? &stage->upload : NULL; }
const struct stela_nv_render_binding *stela_nv_render_bindings(const struct stela_nv_render_compilation *owner,
    enum stela_air_stage kind, uint32_t *count, uint32_t *bytes)
{
    const struct render_stage *stage = get_stage(owner, kind);
    if (count) *count = stage ? stage->binding_count : 0;
    if (bytes) *bytes = stage ? stage->table_bytes : 0;
    return stage ? stage->bindings : NULL;
}
const struct stela_nv_render_provenance *stela_nv_render_provenance(const struct stela_nv_render_compilation *owner)
{ return owner ? &owner->provenance : NULL; }
const nir_shader_compiler_options *stela_nv_render_nir_options(const struct stela_nv_render_compilation *owner)
{ return owner ? &owner->nir_options : NULL; }
