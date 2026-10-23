/* SPDX-License-Identifier: MIT */
#include "air_graphics.h"
#include "fp_controls.h"
#include "compiler/nir/nir_builder.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/compiler/gen/gen.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BINDINGS 64u /* Original full surface-group ceiling. */
#define MAX_CODE (64u * 1024u * 1024u)
struct stela_intel_graphics_compilation {
    struct stela_metal_assembly *assemblies[2];
    struct stela_intel_graphics_provenance provenance;
    struct stela_intel_graphics_stage_binary binaries[2];
    struct stela_intel_graphics_binding bindings[2][MAX_BINDINGS];
    uint32_t binding_count[2];
    struct stela_air_varying_slot varyings[32];
    unsigned varying_count;
    nir_shader_compiler_options nir_options[2];
    nir_shader *nir[2];
    struct brw_vs_prog_data brw_vs;
    struct brw_fs_prog_data brw_fs;
    struct elk_vs_prog_data elk_vs;
    struct elk_fs_prog_data elk_fs;
    void *context, *work;
    bool type_reference;
};
struct binding_call { struct stela_intel_graphics_compilation *owner; unsigned stage; };

static int ordinal(enum stela_air_stage stage)
{
    return stage == STELA_AIR_VERTEX ? 0 : stage == STELA_AIR_FRAGMENT ? 1 : -1;
}
static enum stela_intel_graphics_status report(struct stela_intel_graphics_error *error,
    enum stela_intel_graphics_status status, const char *detail)
{
    if (error) { error->status = status; snprintf(error->detail, sizeof(error->detail), "%s", detail); }
    return status;
}
void stela_intel_graphics_destroy(struct stela_intel_graphics_compilation **slot)
{
    if (!slot || !*slot) return;
    struct stela_intel_graphics_compilation *owner = *slot; *slot = NULL;
    ralloc_free(owner->nir[0]); ralloc_free(owner->nir[1]);
    ralloc_free(owner->work); ralloc_free(owner->context);
    stela_metal_assembly_destroy(&owner->assemblies[0]);
    stela_metal_assembly_destroy(&owner->assemblies[1]);
    if (owner->type_reference) glsl_type_singleton_decref();
    free(owner);
}
const struct stela_intel_graphics_provenance *stela_intel_graphics_provenance(
    const struct stela_intel_graphics_compilation *owner)
{
    return owner ? &owner->provenance : NULL;
}
const struct stela_intel_graphics_stage_binary *stela_intel_graphics_binary(
    const struct stela_intel_graphics_compilation *owner, enum stela_air_stage stage)
{
    int i = ordinal(stage); return owner && i >= 0 ? &owner->binaries[i] : NULL;
}
const struct stela_intel_graphics_binding *stela_intel_graphics_bindings(
    const struct stela_intel_graphics_compilation *owner, enum stela_air_stage stage, uint32_t *count)
{
    int i = ordinal(stage);
    if (count) *count = owner && i >= 0 ? owner->binding_count[i] : 0;
    return owner && i >= 0 ? owner->bindings[i] : NULL;
}
const nir_shader *stela_intel_graphics_nir(const struct stela_intel_graphics_compilation *owner,
    enum stela_air_stage stage)
{
    int i = ordinal(stage); return owner && i >= 0 ? owner->nir[i] : NULL;
}
static bool device_supported(const struct intel_device_info *device, bool elk)
{
    if (!device || !device->slice_masks || !device->subslice_total || !device->num_thread_per_eu ||
        !device->max_vs_threads || !device->max_threads_per_psd) return false;
    if (elk) return device->verx10 == 70 || device->verx10 == 75 || device->verx10 == 80;
    switch (device->verx10) {
    case 90: case 110: case 120: case 125: case 200: case 300: case 350: return true;
    default: return false;
    }
}
static enum stela_intel_graphics_status selected(const struct stela_metal_assembly *assembly,
    enum stela_air_stage role, const struct stela_metal_stage_view **selected_view,
    struct stela_metal_input_view *raw, struct stela_intel_graphics_error *error)
{
    const struct stela_metal_stage_view *view = stela_metal_assembly_stage(assembly);
    if (!view || view->size != sizeof(*view) || view->abi != STELA_METAL_ASSEMBLY_ABI ||
        !view->reflection || !view->identity || !view->provenance ||
        view->reflection->stage != role || view->identity->entry.kind != (role == STELA_AIR_VERTEX ? 0u : 1u) ||
        stela_metal_assembly_manifest(assembly) ||
        view->identity->size != sizeof(*view->identity) || view->identity->abi != STELA_METAL_LIBRARY_ABI)
        return report(error, STELA_INTEL_GRAPHICS_INVALID, "Requires actual canonical selected vertex/fragment owners");
    struct stela_metal_input_view original = {.size = sizeof(original), .abi = STELA_METAL_INPUT_ABI};
    const struct stela_metal_function_record *identity = view->identity;
    if (stela_metal_assembly_original(assembly, &original, NULL) != STELA_METAL_ASSEMBLY_OK ||
        identity->air_offset > original.length || identity->air_bytes > original.length - identity->air_offset ||
        identity->air_bytes < 4 || identity->air_bytes > AIR_MAX_BITCODE_BYTES ||
        !identity->name || !identity->name_bytes || identity->name_bytes > 4096 ||
        memchr(identity->name, 0, (size_t)identity->name_bytes) || identity->name[identity->name_bytes])
        return report(error, STELA_INTEL_GRAPHICS_INVALID, "Invalid canonical selected AIR span/name");
    *raw = original; raw->bytes += identity->air_offset; raw->length = identity->air_bytes;
    raw->original_offset = identity->air_offset; *selected_view = view;
    return STELA_INTEL_GRAPHICS_OK;
}
static enum stela_intel_graphics_status reflect_bindings(struct stela_intel_graphics_compilation *owner,
    unsigned stage, const struct stela_air_stage_entry *entry, struct stela_intel_graphics_error *error)
{
    if (entry->input_count > AIR_MAX_ARGUMENTS || (entry->input_count && !entry->inputs))
        return report(error, STELA_INTEL_GRAPHICS_INVALID, "Invalid selected-stage inputs");
    for (unsigned i = 0; i < entry->input_count; i++) {
        const struct stela_air_stage_io *input = &entry->inputs[i];
        if (input->semantic != STELA_AIR_STAGE_BUFFER) continue;
        const struct stela_air_buffer *buffer = &input->buffer;
        unsigned n = owner->binding_count[stage];
        if (buffer->address_space != 2 || buffer->access != STELA_AIR_READ ||
            !buffer->type_size || !buffer->type_alignment ||
            (buffer->type_alignment & (buffer->type_alignment - 1)))
            return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Unsupported stage-buffer ABI");
        if (n >= MAX_BINDINGS)
            return report(error, STELA_INTEL_GRAPHICS_LIMIT, "Original surface-group limit exceeded");
        for (unsigned j = 0; j < n; j++)
            if (owner->bindings[stage][j].buffer.index == buffer->index ||
                owner->bindings[stage][j].buffer.argument == buffer->argument)
                return report(error, STELA_INTEL_GRAPHICS_INVALID, "Aliased selected-stage buffer identities");
        owner->bindings[stage][n] = (struct stela_intel_graphics_binding){.buffer = *buffer, .logical_slot = n};
        owner->binding_count[stage]++;
    }
    return STELA_INTEL_GRAPHICS_OK;
}
static bool bind_ssbo(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
    const struct binding_call *call = data;
    for (unsigned i = 0; i < call->owner->binding_count[call->stage]; i++) {
        const struct stela_air_buffer *b = &call->owner->bindings[call->stage][i].buffer;
        if (buffer->argument == b->argument && buffer->index == b->index &&
            buffer->address_space == b->address_space && buffer->access == b->access &&
            buffer->type_size == b->type_size && buffer->type_alignment == b->type_alignment) {
            *slot = i; return true;
        }
    }
    return false;
}
/* The admitted stages bind only render targets and read-only SSBOs. As in
 * the iris and crocus tables, a fragment shader's render targets come first,
 * then the SSBOs the stage uses, in index order, and each SSBO access is
 * rewritten to name its table entry. Returns the table's size in bytes. */
static uint32_t bind_surfaces(nir_shader *nir, unsigned render_targets, unsigned count,
    uint64_t used, struct stela_intel_graphics_binding *bindings)
{
    uint32_t next = render_targets;
    for (unsigned j = 0; j < count; j++) {
        bindings[j].used = bindings[j].table_entry = (used >> j) & 1;
        bindings[j].bti = bindings[j].used ? next++ : 0;
    }
    nir_builder b = nir_builder_create(nir_shader_get_entrypoint(nir));
    nir_foreach_block(block, b.impl) nir_foreach_instr(instr, block) {
        if (instr->type != nir_instr_type_intrinsic) continue;
        nir_intrinsic_instr *in = nir_instr_as_intrinsic(instr);
        if (in->intrinsic != nir_intrinsic_load_ssbo && in->intrinsic != nir_intrinsic_get_ssbo_size) continue;
        b.cursor = nir_before_instr(instr);
        nir_src_rewrite(&in->src[0], nir_imm_intN_t(&b, bindings[nir_src_as_uint(in->src[0])].bti,
                                                    in->src[0].ssa->bit_size));
    }
    return next * 4;
}
static void snapshot_policy(struct stela_intel_graphics_compilation *owner,
    const struct brw_compiler *brw, const struct elk_compiler *elk)
{
    struct stela_intel_graphics_policy *p = &owner->provenance.policy;
    p->original_compiler_config = brw ? brw_get_compiler_config_value(brw) : elk_get_compiler_config_value(elk);
    memcpy(p->debug, intel_debug, sizeof(p->debug)); p->simd = intel_simd; p->simd_overridden = intel_simd_overridden;
    if (brw) {
        p->spilling_rate = brw->spilling_rate; p->register_file_size = brw->register_file_size;
        p->register_pressure_threshold = brw->register_pressure_threshold;
    } else {
        p->spilling_rate = elk->spilling_rate;
        p->scalar_vertex = elk->scalar_stage[MESA_SHADER_VERTEX];
        p->scalar_fragment = elk->scalar_stage[MESA_SHADER_FRAGMENT];
        p->constant_buffer_0_is_relative = elk->constant_buffer_0_is_relative;
        p->supports_shader_constants = elk->supports_shader_constants; p->has_negative_rhw_bug = elk->has_negative_rhw_bug;
    }
}
static enum stela_intel_graphics_status prepare_nir(struct stela_intel_graphics_compilation *owner,
    const struct brw_compiler *brw, const struct elk_compiler *elk, struct stela_metal_input_view raw[2],
    struct stela_intel_graphics_error *error)
{
    const struct stela_metal_stage_view *views[] = {owner->provenance.vertex, owner->provenance.fragment};
    struct stela_air_error air;
    if (!stela_air_link_stage_io(views[0]->reflection, views[1]->reflection,
        owner->provenance.options.max_varying_slots, owner->varyings, ARRAY_SIZE(owner->varyings),
        &owner->varying_count, &air)) {
        if (error) error->air = air;
        return report(error, STELA_INTEL_GRAPHICS_FRONTEND, "Selected vertex/fragment IO does not link");
    }
    for (unsigned i = 0; i < 2; i++) {
        unsigned count = owner->binding_count[i];
        struct binding_call call = {owner, i};
        const struct stela_air_stage_options opts = {
            .stage = i ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX,
            .resources = {.max_instructions = owner->provenance.options.max_instructions,
                .bind_ssbo = count ? bind_ssbo : NULL, .ssbo_count = count, .binding_data = &call,
                .fp_profile = i ? owner->provenance.options.fragment_fp_profile : owner->provenance.options.vertex_fp_profile},
            .varyings = owner->varyings, .varying_count = owner->varying_count,
            .max_varying_slots = owner->provenance.options.max_varying_slots,
        };
        owner->nir[i] = stela_air_stage_to_nir(raw[i].bytes, (size_t)raw[i].length,
            (const char *)views[i]->identity->name, &owner->nir_options[i], &opts, &air);
        if (!owner->nir[i]) {
            if (error) error->air = air;
            return report(error, STELA_INTEL_GRAPHICS_FRONTEND, "Shared stage frontend refused selected input/policy");
        }
        if (brw) { const struct brw_nir_compiler_opts o = {0}; brw_preprocess_nir(brw, owner->nir[i], &o); }
        else { const struct elk_nir_compiler_opts o = {0}; elk_preprocess_nir(elk, owner->nir[i], &o); }
        nir_shader *nir = owner->nir[i];
        nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
        if ((i && nir->info.outputs_written != BITFIELD64_BIT(FRAG_RESULT_DATA0)) ||
            (!i && !(nir->info.outputs_written & VARYING_BIT_POS)))
            return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Stage outputs exceed the explicit raster model");
        if (i) nir_foreach_shader_out_variable(var, nir) {
            if (var->data.location != FRAG_RESULT_DATA0 || var->data.index)
                return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Extra/dual-source fragment output requires its real policy");
        }
        if (stela_intel_fp_controls(&owner->provenance.device, &nir->info))
            return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Stage FP mode unsupported by actual device contract");
        /* The admitted AIR stage frontend has no such resource operations.
         * If original preprocessing introduces constant/uniform storage, its
         * actual original uniform lowering/upload owner must be added first.
         */
        if (nir->num_uniforms || nir->constant_data_size || nir->info.num_ubos || nir->info.num_images ||
            nir->info.outputs_read || nir->info.num_ssbos != count ||
            BITSET_LAST_BIT(nir->info.textures_used) || BITSET_LAST_BIT(nir->info.samplers_used))
            return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Stage needs an unimplemented resource/effect owner");
        if (elk && i) elk_nir_lower_fs_outputs(nir);
        uint64_t resource_use = 0;
        nir_foreach_function_impl(impl, nir) nir_foreach_block(block, impl) nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic) continue;
            nir_intrinsic_instr *in = nir_instr_as_intrinsic(instr);
            if (in->intrinsic == nir_intrinsic_store_ssbo || in->intrinsic == nir_intrinsic_ssbo_atomic ||
                in->intrinsic == nir_intrinsic_ssbo_atomic_swap)
                return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Readonly stage produced a write/atomic effect");
            if (in->intrinsic != nir_intrinsic_load_ssbo && in->intrinsic != nir_intrinsic_get_ssbo_size) continue;
            if (!nir_src_is_const(in->src[0]) || nir_src_as_uint(in->src[0]) >= count)
                return report(error, STELA_INTEL_GRAPHICS_BACKEND, "Unexpected logical stage resource index");
            resource_use |= 1ull << nir_src_as_uint(in->src[0]);
        }
        owner->binaries[i].binding_table_bytes =
            bind_surfaces(nir, i ? 1 : 0, count, resource_use, owner->bindings[i]);
    }
    return STELA_INTEL_GRAPHICS_OK;
}

static bool all_zero(const void *data, unsigned bytes)
{
    const uint8_t *p = data;
    for (unsigned i = 0; i < bytes; i++) if (p[i]) return false;
    return true;
}
enum stela_intel_graphics_status stela_intel_graphics_validate_brw(
    const struct intel_device_info *device, void *context, const void *code,
    uint32_t bytes, unsigned end_alignment)
{
    if (!device || !context || !code || !bytes || bytes > INT32_MAX || (bytes & 7) ||
        (end_alignment != 16 && end_alignment != 32 && end_alignment != 64))
        return STELA_INTEL_GRAPHICS_BACKEND;
    /* Original brw_generator validates the whole gen_insts CFG, not a prefix
     * ending at the first EOT. Its allocate_output zero-fills only alignment:
     * 64 before another SIMD variant, 32 before constants, 16 at final output.
     * Use the original raw instruction-layout scanner to retain every real
     * instruction (including every EOT path and compact NOP), excluding only
     * a wholly zero suffix whose exact extent is that original alignment.
     * A zero instruction inside the program remains for original validation.
     */
    gen_inst_layout *layouts = ralloc_array(context, gen_inst_layout, bytes / 8);
    if (!layouts) return STELA_INTEL_GRAPHICS_ALLOCATION;
    gen_scan_raw_layout_params layout = {.raw_bytes = code, .raw_bytes_size = (int)bytes,
        .layouts = layouts, .num_insts = (int)(bytes / 8)};
    if (!gen_scan_raw_layout(&layout) || !layout.num_insts || layout.end_offset > (int)bytes)
        return STELA_INTEL_GRAPHICS_BACKEND;
    unsigned real_bytes = (unsigned)layout.end_offset;
    if (!all_zero((const uint8_t *)code + real_bytes, bytes - real_bytes))
        return STELA_INTEL_GRAPHICS_BACKEND;
    int count = layout.num_insts;
    while (count) {
        const gen_inst_layout *last = &layouts[count - 1];
        unsigned size = last->was_compacted ? 8 : 16;
        if (!all_zero((const uint8_t *)code + last->offset, size)) break;
        real_bytes = (unsigned)last->offset; count--;
    }
    if (!count || ((real_bytes + end_alignment - 1) & ~(end_alignment - 1)) != bytes)
        return STELA_INTEL_GRAPHICS_BACKEND;
    gen_decode_params decoded = {.devinfo = device, .mem_ctx = context,
        .raw_bytes = code, .raw_bytes_size = (int)real_bytes};
    if (!gen_decode(&decoded) || decoded.num_insts != count) return STELA_INTEL_GRAPHICS_BACKEND;
    gen_validate_params validation = {.devinfo = device, .mem_ctx = context,
        .insts = decoded.insts, .num_insts = decoded.num_insts};
    return gen_validate(&validation) ? STELA_INTEL_GRAPHICS_OK : STELA_INTEL_GRAPHICS_BACKEND;
}
static enum stela_intel_graphics_status capture(struct stela_intel_graphics_compilation *owner,
    const struct elk_compiler *elk, unsigned i, const void *code, const char *message,
    struct stela_intel_graphics_error *error)
{
    struct brw_stage_prog_data *b = i ? &owner->brw_fs.base : &owner->brw_vs.base.base;
    struct elk_stage_prog_data *e = i ? &owner->elk_fs.base : &owner->elk_vs.base.base;
    unsigned bytes = elk ? e->program_size : b->program_size;
    unsigned constants = elk ? e->const_data_size : b->const_data_size;
    unsigned offset = elk ? e->const_data_offset : b->const_data_offset;
    unsigned relocs = elk ? e->num_relocs : b->num_relocs;
    const struct intel_shader_reloc *reloc = elk ? e->relocs : b->relocs;
    if (!code || message || !bytes || (elk ? e->stage : b->stage) != (i ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX) ||
        offset > bytes || (constants && (!offset || constants > bytes - offset)) || (relocs && !reloc) ||
        (elk && e->nr_params && !e->param))
        return report(error, STELA_INTEL_GRAPHICS_BACKEND, message ? message : "Inconsistent original stage output");
    if (bytes > owner->provenance.options.max_code_bytes)
        return report(error, STELA_INTEL_GRAPHICS_LIMIT, "Resident stage code exceeds explicit budget");
    unsigned executable = constants ? offset : bytes;
    for (unsigned j = 0; j < relocs; j++) {
        unsigned span = reloc[j].type == INTEL_SHADER_RELOC_TYPE_U32 ? 4 :
            reloc[j].type == INTEL_SHADER_RELOC_TYPE_MOV_IMM ? 16 : 0;
        if (!span || reloc[j].offset % 8 || reloc[j].offset > executable || executable - reloc[j].offset < span)
            return report(error, STELA_INTEL_GRAPHICS_BACKEND, "Invalid original stage relocation span");
    }
    unsigned starts[3] = {0}, n = 1;
    if (i) {
        n = 0;
        if (elk ? owner->elk_fs.dispatch_8 : owner->brw_fs.dispatch_8 || owner->brw_fs.dispatch_multi) starts[n++] = 0;
        if (elk ? owner->elk_fs.dispatch_16 : owner->brw_fs.dispatch_16)
            starts[n++] = elk ? owner->elk_fs.prog_offset_16 : owner->brw_fs.prog_offset_16;
        if (elk ? owner->elk_fs.dispatch_32 : owner->brw_fs.dispatch_32)
            starts[n++] = elk ? owner->elk_fs.prog_offset_32 : owner->brw_fs.prog_offset_32;
    }
    if (!n || starts[0]) return report(error, STELA_INTEL_GRAPHICS_BACKEND, "Missing original fragment dispatch variant");
    for (unsigned j = 0; j < n; j++) {
        unsigned stop = j + 1 < n ? starts[j + 1] : executable;
        if ((starts[j] & 63) || starts[j] >= stop || stop > executable)
            return report(error, STELA_INTEL_GRAPHICS_BACKEND, "Invalid original SIMD code offsets");
        const uint8_t *kernel = (const uint8_t *)code + starts[j];
        unsigned end_alignment = j + 1 < n ? 64 : constants ? 32 : 16;
        enum stela_intel_graphics_status status = elk ?
            (stela_intel_graphics_validate_elk(elk, kernel, stop - starts[j], end_alignment) ?
                STELA_INTEL_GRAPHICS_OK : STELA_INTEL_GRAPHICS_BACKEND) :
            stela_intel_graphics_validate_brw(&owner->provenance.device, owner->work,
                kernel, stop - starts[j], end_alignment);
        if (status) return report(error, status, status == STELA_INTEL_GRAPHICS_ALLOCATION ?
            "ISA layout allocation failed" : "Original ISA validation refused stage output");
    }
    owner->binaries[i].code = code; owner->binaries[i].code_bytes = bytes;
    owner->binaries[i].executable_bytes = executable;
    owner->binaries[i].stage = i ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX;
    if (elk) {
        if (i) owner->binaries[i].elk_fs = &owner->elk_fs; else owner->binaries[i].elk_vs = &owner->elk_vs;
        if (e->param) ralloc_steal(owner->context, e->param);
    } else {
        if (i) owner->binaries[i].brw_fs = &owner->brw_fs; else owner->binaries[i].brw_vs = &owner->brw_vs;
    }
    ralloc_steal(owner->context, (void *)code);
    if (reloc) ralloc_steal(owner->context, (void *)reloc);
    return STELA_INTEL_GRAPHICS_OK;
}

static enum stela_intel_graphics_status compile_stages(struct stela_intel_graphics_compilation *owner,
    const struct brw_compiler *brw, const struct elk_compiler *elk, void *log_data,
    struct stela_intel_graphics_error *error)
{
    const void *code; const char *message;
    if (brw) {
        struct brw_vs_prog_key key = {.base = {.vue_layout = INTEL_VUE_LAYOUT_FIXED}};
        struct brw_compile_vs_params p = {.base = {.mem_ctx = owner->work, .nir = owner->nir[0],
            .key = &key.base, .prog_data = &owner->brw_vs.base.base, .log_data = log_data}};
        code = brw_compile(brw, &p.base); message = p.base.error_str;
    } else {
        struct elk_vs_prog_key key = {0};
        owner->elk_vs.base.base.param = ralloc_array(owner->work, uint32_t, 0);
        if (!owner->elk_vs.base.base.param) return report(error, STELA_INTEL_GRAPHICS_ALLOCATION, "Original parameter allocation failed");
        elk_compute_vue_map(elk->devinfo, &owner->elk_vs.base.vue_map, owner->nir[0]->info.outputs_written,
            INTEL_VUE_LAYOUT_FIXED, 1);
        struct elk_compile_vs_params p = {.base = {.mem_ctx = owner->work, .nir = owner->nir[0], .log_data = log_data},
            .key = &key, .prog_data = &owner->elk_vs};
        code = elk_compile_vs(elk, &p); message = p.base.error_str;
    }
    enum stela_intel_graphics_status status = capture(owner, elk, 0, code, message, error);
    if (status) return status;
    if (brw) {
        struct brw_fs_prog_key key = {.base = {.vue_layout = INTEL_VUE_LAYOUT_FIXED},
            .nr_color_regions = 1, .ignore_sample_mask_out = true};
        struct brw_compile_fs_params p = {.base = {.mem_ctx = owner->work, .nir = owner->nir[1],
            .key = &key.base, .prog_data = &owner->brw_fs.base, .log_data = log_data},
            .vue_map = &owner->brw_vs.base.vue_map, .max_polygons = 1};
        code = brw_compile(brw, &p.base); message = p.base.error_str;
    } else {
        struct elk_fs_prog_key key = {.input_slots_valid = owner->elk_vs.base.vue_map.slots_valid,
            .nr_color_regions = 1, .color_outputs_valid = 1, .ignore_sample_mask_out = true};
        owner->elk_fs.base.param = ralloc_array(owner->work, uint32_t, 0);
        if (!owner->elk_fs.base.param) return report(error, STELA_INTEL_GRAPHICS_ALLOCATION, "Original parameter allocation failed");
        struct elk_compile_fs_params p = {.base = {.mem_ctx = owner->work, .nir = owner->nir[1], .log_data = log_data},
            .key = &key, .prog_data = &owner->elk_fs, .vue_map = &owner->elk_vs.base.vue_map,
            .allow_spilling = true, .max_polygons = 1};
        code = elk_compile_fs(elk, &p); message = p.base.error_str;
    }
    return capture(owner, elk, 1, code, message, error);
}

enum stela_intel_graphics_status stela_intel_graphics_compile(const struct brw_compiler *brw,
    const struct elk_compiler *elk, void *log_data, struct stela_metal_assembly **vertex,
    struct stela_metal_assembly **fragment, const struct stela_intel_graphics_options *options,
    struct stela_intel_graphics_compilation **output, struct stela_intel_graphics_error *error)
{
    if (error) memset(error, 0, sizeof(*error));
    if (!vertex || !fragment || !output || vertex == fragment ||
        (void *)output == (void *)vertex || (void *)output == (void *)fragment)
        return report(error, STELA_INTEL_GRAPHICS_INVALID, "Aliased/missing exclusive owning slots");
    if (!*vertex || !*fragment || *vertex == *fragment || *output ||
        !!brw == !!elk || !options || options->size != sizeof(*options) || options->abi != STELA_INTEL_GRAPHICS_ABI)
        return report(error, STELA_INTEL_GRAPHICS_INVALID, "Invalid exclusive selected-stage/compiler ABI");
    const struct intel_device_info *device = brw ? brw->devinfo : elk->devinfo;
    if (!device_supported(device, elk != NULL) || (brw && (brw->isa.devinfo != device || !brw->reg_set.regs ||
        !brw->shader_debug_log || !brw->shader_perf_log)) || (elk && (elk->isa.devinfo != device ||
        !elk->fs_reg_sets[0].regs || !elk->shader_debug_log || !elk->shader_perf_log ||
        (!elk->scalar_stage[MESA_SHADER_VERTEX] && !elk->vec4_reg_set.regs))))
        return report(error, STELA_INTEL_GRAPHICS_DEVICE, "Actual matching initialized graphics compiler required");
    if (device->ver >= 35 || options->samples != 1 || options->color_regions != 1)
        return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Graphics generation/model qualification hold");
    if (brw && (intel_use_jay(device, MESA_SHADER_VERTEX) || intel_use_jay(device, MESA_SHADER_FRAGMENT)))
        return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Actual selected JAY stage backend requires its own integration");
    if ((options->vertex_fp_profile != STELA_AIR_FP_IEEE_DEFAULT &&
         options->vertex_fp_profile != STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41) ||
        (options->fragment_fp_profile != STELA_AIR_FP_IEEE_DEFAULT &&
         options->fragment_fp_profile != STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41))
        return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Unknown selected-stage FP policy");
    if (!options->max_instructions || !options->max_code_bytes || options->max_code_bytes > MAX_CODE ||
        options->max_varying_slots > 32)
        return report(error, STELA_INTEL_GRAPHICS_LIMIT, "Explicit bounded code/IO budgets required");
    const nir_shader_compiler_options *nir_options[2];
    for (unsigned i = 0; i < 2; i++) {
        mesa_shader_stage stage = i ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX;
        nir_options[i] = brw ? &brw->nir_options[stage] : elk->nir_options[stage];
        if (!nir_options[i] || nir_options[i]->cb_data)
            return report(error, STELA_INTEL_GRAPHICS_UNSUPPORTED, "Opaque NIR option lifetime is unavailable");
    }
    struct stela_metal_input_view raw[2];
    const struct stela_metal_stage_view *views[2];
    enum stela_intel_graphics_status status = selected(*vertex, STELA_AIR_VERTEX, &views[0], &raw[0], error);
    if (!status) status = selected(*fragment, STELA_AIR_FRAGMENT, &views[1], &raw[1], error);
    if (status) return status;
    struct stela_intel_graphics_compilation *owner = calloc(1, sizeof(*owner));
    if (!owner) return report(error, STELA_INTEL_GRAPHICS_ALLOCATION, "Graphics package allocation failed");
    owner->provenance = (struct stela_intel_graphics_provenance){.backend = brw ? STELA_INTEL_GRAPHICS_BRW : STELA_INTEL_GRAPHICS_ELK,
        .device = *device, .options = *options, .vertex = views[0], .fragment = views[1]};
    snapshot_policy(owner, brw, elk);
    for (unsigned i = 0; i < 2 && !status; i++) {
        owner->nir_options[i] = *nir_options[i];
        status = reflect_bindings(owner, i, views[i]->reflection, error);
    }
    if (!status) {
        owner->context = ralloc_context(NULL); owner->work = ralloc_context(NULL);
        if (!owner->context || !owner->work) status = report(error, STELA_INTEL_GRAPHICS_ALLOCATION, "Original ralloc owner allocation failed");
    }
    if (!status) {
        glsl_type_singleton_init_or_ref(); owner->type_reference = true;
        status = prepare_nir(owner, brw, elk, raw, error);
    }
    if (!status) status = compile_stages(owner, brw, elk, log_data, error);
    if (status) { stela_intel_graphics_destroy(&owner); return status; }
    ralloc_free(owner->work); owner->work = NULL;
    /* No failures/allocations below. Both complete original input owners move
     * exactly once; copied views/maps borrow from those now-retained owners. */
    owner->assemblies[0] = *vertex; owner->assemblies[1] = *fragment;
    *vertex = NULL; *fragment = NULL; *output = owner;
    return STELA_INTEL_GRAPHICS_OK;
}
