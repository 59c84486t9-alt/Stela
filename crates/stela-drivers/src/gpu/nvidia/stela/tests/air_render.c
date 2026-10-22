/* SPDX-License-Identifier: MIT */
/* Hosted compiler-only qualification. No graphics pipeline, device or draw. */
#include "air_to_nir.h"
#include "nouveau/compiler/nak.h"
#include "stela/tests/air_probe.h"
#include "stela/tests/targets/nvidia.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TABLE_CB 2u
#define ROW_BYTES 16u
#define TABLE_BYTES 64u
#define MAX_BINDINGS 2u

/* Test ABI only: each cbuf row contains a runtime view base64, exact length32
 * and zero reserved32. No row payload becomes a constant in compiled code.
 * The original shared bridge provides full-width logical bounds checks; the
 * original nir_lower_ssbo supplies global accesses. This is no NVK descriptor,
 * native graphics resource binding or production capability declaration. */
struct binding {
    struct stela_air_buffer buffer;
    struct stela_air_ssbo_view view;
    uint64_t allocation_address;
    unsigned logical_elements;
};
struct raster_model {
    unsigned samples;
    bool sample_shading, depth_feedback, conservative_underestimate;
};
struct run {
    const void *bytes;
    size_t size;
    const char *vertex, *fragment, *output;
    const struct stela_air_stage_entry *vs;
    struct stela_air_varying_slot map[32];
    unsigned varying_count, binding_count, callbacks, binding_attempts, backend_calls;
    struct binding bindings[MAX_BINDINGS];
};
struct capture {
    struct nak_shader_info info;
    unsigned code_size;
    void *code;
    char *assembly;
};
static bool same_buffer(const struct stela_air_buffer *a, const struct stela_air_buffer *b)
{
    return a->argument == b->argument && a->index == b->index && a->address_space == b->address_space &&
        a->access == b->access && a->type_size == b->type_size && a->type_alignment == b->type_alignment;
}
static bool pack_table(const struct run *run, const struct binding *bindings,
                       unsigned count, uint8_t output[TABLE_BYTES])
{
    if (count != run->binding_count || count > MAX_BINDINGS || (count && !bindings)) return false;
    uint64_t addresses[MAX_BINDINGS];
    for (unsigned i = 0; i < count; ++i) {
        const struct binding *row = &bindings[i];
        const struct stela_air_buffer *buffer = &run->bindings[i].buffer;
        const struct stela_air_ssbo_view *view = &row->view;
        if (!same_buffer(&row->buffer, buffer) || buffer->address_space != 2 || buffer->access != STELA_AIR_READ ||
            !stela_air_ssbo_view_valid(view, MAX_BINDINGS) || view->slot != i ||
            view->access != STELA_AIR_READ || view->available_access != STELA_AIR_READ ||
            view->alignment < buffer->type_alignment || !row->logical_elements ||
            buffer->type_size > UINT64_MAX / row->logical_elements ||
            view->size != (uint64_t)buffer->type_size * row->logical_elements ||
            row->allocation_address > UINT64_MAX - view->offset) return false;
        addresses[i] = row->allocation_address + view->offset;
        if (addresses[i] % view->alignment || view->size > UINT64_MAX - addresses[i]) return false;
    }
    /* Validate every row before changing even a padding byte. */
    memset(output, 0, TABLE_BYTES);
    for (unsigned i = 0; i < count; ++i) {
        uint64_t address = addresses[i];
        uint32_t size = (uint32_t)bindings[i].view.size;
        for (unsigned byte = 0; byte < 8; ++byte) output[i * ROW_BYTES + byte] = (uint8_t)(address >> (8 * byte));
        for (unsigned byte = 0; byte < 4; ++byte) output[i * ROW_BYTES + 8 + byte] = (uint8_t)(size >> (8 * byte));
    }
    return true;
}
static bool bind_ssbo(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
    struct run *run = data;
    run->binding_attempts++;
    CHECK(buffer->address_space == 2 && buffer->access == STELA_AIR_READ);
    uint8_t table[TABLE_BYTES];
    if (!pack_table(run, run->bindings, run->binding_count, table)) return false;
    for (unsigned i = 0; i < run->binding_count; ++i) {
        if (!same_buffer(buffer, &run->bindings[i].buffer)) continue;
        run->callbacks++;
        *slot = i;
        return true;
    }
    return false;
}
static bool lower_table(nir_builder *b, nir_intrinsic_instr *intrinsic, void *data)
{
    const struct run *run = data;
    if (intrinsic->intrinsic != nir_intrinsic_load_ssbo_address &&
        intrinsic->intrinsic != nir_intrinsic_get_ssbo_size) return false;
    CHECK(nir_src_is_const(intrinsic->src[0]));
    uint64_t selected = nir_src_as_uint(intrinsic->src[0]);
    CHECK(selected < run->binding_count && selected < MAX_BINDINGS);
    unsigned slot = (unsigned)selected;
    bool address = intrinsic->intrinsic == nir_intrinsic_load_ssbo_address;
    if (address) CHECK(nir_src_is_const(intrinsic->src[1]) && nir_src_as_uint(intrinsic->src[1]) == 0);
    b->cursor = nir_before_instr(&intrinsic->instr);
    nir_def *value = nir_ldc_nv(b, 1, address ? 64 : 32,
        nir_imm_int(b, TABLE_CB), nir_imm_int(b, 0),
        .base = slot * ROW_BYTES + (address ? 0 : 8),
        .align_mul = address ? 8 : 4, .align_offset = 0);
    nir_def_rewrite_uses(&intrinsic->def, value);
    nir_instr_remove(&intrinsic->instr);
    return true;
}
static void validate_frontend(nir_shader *nir, mesa_shader_stage stage, const struct run *run)
{
    CHECK(nir->info.stage == stage && !nir->info.shared_size);
    unsigned loads = 0, sizes = 0, outputs = 0, inputs = 0, vertex_ids = 0, output_mask = 0;
    nir_foreach_function_impl(impl, nir) nir_foreach_block(block, impl) nir_foreach_instr(instr, block) {
        if (instr->type != nir_instr_type_intrinsic) continue;
        nir_intrinsic_instr *i = nir_instr_as_intrinsic(instr);
        CHECK(i->intrinsic != nir_intrinsic_store_ssbo && i->intrinsic != nir_intrinsic_store_global);
        if (i->intrinsic == nir_intrinsic_load_ssbo) { loads++; CHECK(nir_src_is_const(i->src[0]) && nir_src_as_uint(i->src[0]) < run->binding_count); }
        if (i->intrinsic == nir_intrinsic_get_ssbo_size) sizes++;
        if (i->intrinsic == nir_intrinsic_load_vertex_id) vertex_ids++;
        if (i->intrinsic == nir_intrinsic_store_deref) {
            nir_variable *v = nir_intrinsic_get_var(i, 0); outputs++;
            if (stage == MESA_SHADER_VERTEX) {
                CHECK(v->data.location == VARYING_SLOT_POS || v->data.location == VARYING_SLOT_VAR0);
                output_mask |= v->data.location == VARYING_SLOT_POS ? 1u : 2u;
            } else CHECK(v->data.location == FRAG_RESULT_DATA0 && v->data.index == 0);
        }
        if (i->intrinsic == nir_intrinsic_load_deref && nir_intrinsic_get_var(i, 0)->data.mode == nir_var_shader_in) {
            nir_variable *v = nir_intrinsic_get_var(i, 0); inputs++;
            CHECK(stage == MESA_SHADER_FRAGMENT && v->data.location == VARYING_SLOT_VAR0 &&
                  v->data.interpolation == INTERP_MODE_SMOOTH && !v->data.centroid && !v->data.sample);
        }
    }
    if (stage == MESA_SHADER_VERTEX) CHECK(loads && sizes && vertex_ids && outputs == 2 && output_mask == 3 && !inputs);
    else CHECK(!loads && !sizes && !vertex_ids && inputs && outputs == 1 && nir->info.fs.origin_upper_left);
    nir_validate_shader(nir, "frozen original AIR stage before NAK");
}
static void validate_dynamic_abi(nir_shader *nir, const struct run *run)
{
    unsigned globals = 0, lengths = 0;
    nir_foreach_function_impl(impl, nir) nir_foreach_block(block, impl) nir_foreach_instr(instr, block) {
        if (instr->type == nir_instr_type_load_const) {
            nir_load_const_instr *load = nir_instr_as_load_const(instr);
            if (load->def.bit_size == 64) for (unsigned k = 0; k < load->def.num_components; ++k)
                for (unsigned i = 0; i < run->binding_count; ++i) {
                    CHECK(load->value[k].u64 != run->bindings[i].allocation_address);
                    CHECK(load->value[k].u64 != run->bindings[i].allocation_address + run->bindings[i].view.offset);
                }
        }
        if (instr->type != nir_instr_type_intrinsic) continue;
        nir_intrinsic_instr *i = nir_instr_as_intrinsic(instr);
        CHECK(i->intrinsic != nir_intrinsic_load_ssbo && i->intrinsic != nir_intrinsic_get_ssbo_size &&
              i->intrinsic != nir_intrinsic_load_ssbo_address && i->intrinsic != nir_intrinsic_store_global);
        if (i->intrinsic == nir_intrinsic_load_global) { CHECK(!nir_src_is_const(i->src[0])); globals++; }
        if (i->intrinsic == nir_intrinsic_ldc_nv) {
            CHECK(nir_src_is_const(i->src[0]) && nir_src_as_uint(i->src[0]) == TABLE_CB);
            if (i->def.bit_size == 32) lengths++;
        }
    }
    if (nir->info.stage == MESA_SHADER_VERTEX) CHECK(globals && lengths);
    else CHECK(!globals && !lengths);
}
static struct capture compile(nir_shader *nir, struct nak_compiler *compiler,
                               const struct nak_fs_key *key, struct run *run)
{
    nak_preprocess_nir(nir, compiler);
    const nir_lower_ssbo_options ssbo = {0};
    nir_lower_ssbo(nir, &ssbo); /* Original Mesa algorithm, bridge already bounds-checks at64bits. */
    nir_shader_intrinsics_pass(nir, lower_table, nir_metadata_none, run);
    validate_dynamic_abi(nir, run);
    nir_validate_shader(nir, "dynamic test cbuf ABI before original NAK postprocess");
    run->backend_calls++;
    /* Exactly one internal postprocess, including actual VTG/FS IO and SPH. */
    struct nak_shader_bin *bin = nak_compile_shader(nir, true, compiler, 0, key, false);
    CHECK(bin && bin->code && bin->code_size && bin->asm_str && bin->info.num_instrs);
    struct capture result = {.info = bin->info, .code_size = bin->code_size};
    result.code = malloc(bin->code_size);
    result.assembly = malloc(strlen(bin->asm_str) + 1);
    CHECK(result.code && result.assembly);
    memcpy(result.code, bin->code, bin->code_size);
    strcpy(result.assembly, bin->asm_str);
    nak_shader_bin_destroy(bin);
    ralloc_free(nir);
    return result;
}
static void drop_capture(struct capture *capture)
{ free(capture->code); free(capture->assembly); *capture = (struct capture){0}; }
/* A compile target: "sm<N>-samples<N>-<stage>", also its artifacts' stem. */
static void target_name(char name[64], unsigned sm, unsigned samples, const char *stage)
{
    snprintf(name, 64, "sm%u-samples%u-%s", sm, samples, stage);
}
static void write_artifact(const struct run *run, const char *target,
    const char *suffix, const void *bytes, size_t size)
{
    if (!run->output) return;
    char name[128], path[1024];
    int n = snprintf(name, sizeof(name), "%s.%s", target, suffix);
    CHECK(n > 0 && (size_t)n < sizeof(name));
    n = snprintf(path, sizeof(path), "%s/%s", run->output, name);
    CHECK(n > 0 && (size_t)n < sizeof(path));
    FILE *stream = fopen(path, "wb"); CHECK(stream);
    CHECK(fwrite(bytes, 1, size, stream) == size && !fclose(stream));
    record_artifact(name);
}
static bool model_key(const struct raster_model *model, struct nak_fs_key *key)
{
    if ((model->samples != 1 && model->samples != 4) || model->depth_feedback ||
        model->conservative_underestimate || (model->samples == 1 && model->sample_shading)) return false;
    *key = (struct nak_fs_key){.zs_self_dep = model->depth_feedback,
        .force_sample_shading = model->sample_shading, .uses_underestimate = model->conservative_underestimate, .pad = 0};
    return true;
}
static void frontend_refusals(struct run *run, const nir_shader_compiler_options *options)
{
    struct stela_air_stage_options valid = {.stage = STELA_AIR_VERTEX,
        .resources = {.max_instructions = 10000, .bind_ssbo = bind_ssbo,
            .ssbo_count = MAX_BINDINGS, .binding_data = run,
            .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41},
        .varyings = run->map, .varying_count = run->varying_count, .max_varying_slots = 32};
    const unsigned calls = run->callbacks, backend = run->backend_calls;
    for (unsigned failure = 0; failure < 7; ++failure) {
        unsigned attempts = run->binding_attempts;
        struct stela_air_stage_options bad = valid; struct stela_air_varying_slot rows[2] = {run->map[0], run->map[0]};
        struct binding saved = run->bindings[0];
        switch (failure) {
        case 0: bad.resources.workgroup_size[0] = 1; break;
        case 1: bad.stage = STELA_AIR_FRAGMENT; break;
        case 2: bad.max_varying_slots = 0; break;
        case 3: rows[0].location = UINT32_MAX; bad.varyings = rows; break;
        case 4: bad.varyings = rows; bad.varying_count = 2; break;
        case 5: run->bindings[0].view.available_access = STELA_AIR_WRITE; break;
        case 6: run->bindings[0].view.size = run->bindings[0].buffer.type_size; break;
        }
        struct stela_air_error error;
        nir_shader *nir = stela_air_stage_to_nir(run->bytes, run->size, run->vertex, options, &bad, &error);
        CHECK(!nir && error.kind != STELA_AIR_OK && run->callbacks == calls && run->backend_calls == backend);
        CHECK(run->binding_attempts == attempts + (failure >= 5 ? 1u : 0u));
        run->bindings[0] = saved;
    }
}
static void compile_target(struct run *run, const struct stela_air_stage_entry *fs,
                             unsigned sm, const struct raster_model *model)
{
    /* These are compiler model facts, never discovered hardware/provenance. */
    const struct nv_device_info device = stela_nv_compiler_device(sm);
    const struct nak_constant_offset_info layout = nak_const_offsets_base;
    CHECK(TABLE_CB != layout.sample_info_cb && TABLE_CB != layout.printf_cb);
    struct nak_fs_key key; CHECK(model_key(model, &key));
    struct nak_compiler *compiler = nak_compiler_create(&device); CHECK(compiler);
    const nir_shader_compiler_options *options = nak_nir_options(compiler); CHECK(options && !options->cb_data);
    if (sm == 75 && model->samples == 1) frontend_refusals(run, options);
    for (unsigned stage = 0; stage < 2; ++stage) {
        const struct stela_air_stage_entry *entry = stage ? fs : run->vs;
        struct stela_air_stage_options air = {.stage = stage ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX,
            .resources = {.max_instructions = 10000, .bind_ssbo = stage ? NULL : bind_ssbo,
                .ssbo_count = stage ? 0 : MAX_BINDINGS, .binding_data = run,
                .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41},
            .varyings = run->map, .varying_count = run->varying_count, .max_varying_slots = 32};
        struct stela_air_error error;
        nir_shader *nir = stela_air_stage_to_nir(run->bytes, run->size, entry->name, options, &air, &error);
        if (!nir) fprintf(stderr, "stage %s refused: %u %s\n", entry->name, error.kind, error.detail);
        CHECK(nir && error.kind == STELA_AIR_OK);
        validate_frontend(nir, stage ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX, run);
        nir_shader *oracle = nir_shader_clone(NULL, nir); CHECK(oracle);
        struct capture actual = compile(nir, compiler, stage ? &key : NULL, run);
        /* The direct original recapture sees a different valid table payload.
         * Runtime addresses are data, never compiler constants or a cache key. */
        uint8_t original_table[TABLE_BYTES]; CHECK(pack_table(run, run->bindings, run->binding_count, original_table));
        uint64_t original_address = run->bindings[0].allocation_address;
        run->bindings[0].allocation_address += 0x10000;
        uint8_t changed_table[TABLE_BYTES]; CHECK(pack_table(run, run->bindings, run->binding_count, changed_table));
        struct capture expected = compile(oracle, compiler, stage ? &key : NULL, run);
        run->bindings[0].allocation_address = original_address;
        CHECK(actual.info.sm == sm && actual.info.stage == (stage ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX));
        CHECK(actual.code_size == expected.code_size && !memcmp(actual.code, expected.code, actual.code_size));
        CHECK(!memcmp(&actual.info, &expected.info, sizeof(actual.info)) && !strcmp(actual.assembly, expected.assembly));
        CHECK(!actual.info.num_control_barriers);
        CHECK(strstr(actual.assembly, stage ? "ipa" : "ast"));
        if (!stage) CHECK(strstr(actual.assembly, "ldc") && strstr(actual.assembly, "ld.global") && strstr(actual.assembly, "ald"));
        if (stage) CHECK(!actual.info.fs.writes_depth && !actual.info.fs.reads_sample_mask &&
                         !actual.info.fs.uses_sample_shading); /* Original shader-info bit describes shader builtins,
                          * not the separate forced-sample raster key (from_nir.rs). */
        char target[64]; target_name(target, sm, model->samples, stage ? "fs" : "vs");
        write_artifact(run, target, "code", actual.code, actual.code_size);
        write_artifact(run, target, "info", &actual.info, sizeof(actual.info));
        write_artifact(run, target, "hdr", actual.info.hdr, sizeof(actual.info.hdr));
        write_artifact(run, target, "asm", actual.assembly, strlen(actual.assembly));
        if (stage) write_artifact(run, target, "fs-key", &key, sizeof(key));
        else {
            write_artifact(run, target, "model-table", original_table, sizeof(original_table));
            write_artifact(run, target, "alternate-model-table", changed_table, sizeof(changed_table));
        }
        record_compiled(target, actual.code_size);
        record_object("facts");
        record_str("entry", entry->name);
        record_uint("max_warps_per_mp", device.max_warps_per_mp);
        record_bool("sample_shading", model->sample_shading);
        record_bool("depth_feedback", model->depth_feedback);
        record_bool("conservative_underestimate", model->conservative_underestimate);
        record_bool("fs_key_passed", stage);
        record_uint("fp_profile", STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41);
        record_uint("max_instructions", 10000);
        record_uint("max_varying_slots", 32);
        record_uint("sample_info_cb", layout.sample_info_cb);
        record_uint("sample_locations_offset", layout.sample_locations_offset);
        record_uint("sample_masks_offset", layout.sample_masks_offset);
        record_uint("printf_cb", layout.printf_cb);
        record_uint("printf_buffer_offset", layout.printf_buffer_offset);
        record_uint("argument_cbuf", TABLE_CB);
        record_uint("row_bytes", ROW_BYTES);
        record_uint("table_bytes", TABLE_BYTES);
        record_uint("instructions", actual.info.num_instrs);
        record_blake3("code_blake3", actual.code, actual.code_size);
        record_blake3("info_blake3", &actual.info, sizeof(actual.info));
        record_blake3("hdr_blake3", actual.info.hdr, sizeof(actual.info.hdr));
        record_end();
        drop_capture(&actual); drop_capture(&expected);
    }
    nak_compiler_destroy(compiler);
}
static void binding_refusals(struct run *run)
{
    struct binding rows[MAX_BINDINGS]; uint8_t out[TABLE_BYTES], before[TABLE_BYTES];
    for (unsigned failure = 0; failure < 9; ++failure) {
        memcpy(rows, run->bindings, sizeof(rows)); memset(out, 0xa5, sizeof(out)); memcpy(before, out, sizeof(out));
        switch (failure) {
        case 0: rows[0].view.available_access = STELA_AIR_WRITE; break;
        case 1: rows[0].view.access = STELA_AIR_READ_WRITE; break;
        case 2: rows[0].view.size = rows[0].buffer.type_size; break; /* Stride alone is not the3-vertex extent. */
        case 3: rows[0].view.offset = rows[0].view.buffer_size; break;
        case 4: rows[0].view.size = (uint64_t)UINT32_MAX + 1; rows[0].view.buffer_size = rows[0].view.size; break;
        case 5: rows[0].allocation_address = UINT64_MAX; break;
        case 6: rows[0].allocation_address++; break;
        case 7: rows[1].view.slot = 0; break;
        case 8: rows[0].buffer.address_space = 1; break;
        }
        CHECK(!pack_table(run, rows, run->binding_count, out) && !memcmp(out, before, sizeof(out)));
    }
}
static bool fragment(const struct stela_air_inspection *inspection,
                      const struct stela_air_stage_entry *fs, void *data)
{
    (void)inspection;
    struct run *run = data; struct stela_air_error error;
    CHECK(stela_air_link_stage_io(run->vs, fs, 32, run->map, 32, &run->varying_count, &error));
    CHECK(run->varying_count == 1 && fs->output_count == 1);
    for (unsigned i = 0; i < run->vs->input_count; ++i) {
        const struct stela_air_stage_io *input = &run->vs->inputs[i];
        if (input->semantic != STELA_AIR_STAGE_BUFFER) continue;
        CHECK(run->binding_count < MAX_BINDINGS && input->used);
        unsigned slot = run->binding_count++;
        CHECK(input->buffer.address_space == 2 && input->buffer.access == STELA_AIR_READ);
        struct binding *row = &run->bindings[slot]; row->buffer = input->buffer;
        row->logical_elements = slot ? 1u : 3u;
        row->allocation_address = slot ? UINT64_C(0x256780000) : UINT64_C(0x123450000);
        row->view = (struct stela_air_ssbo_view){.slot = slot, .buffer_size = slot ? 32u : 160u,
            .offset = slot ? 8u : 16u, .size = (uint64_t)input->buffer.type_size * row->logical_elements,
            .access = STELA_AIR_READ, .available_access = STELA_AIR_READ, .alignment = input->buffer.type_alignment};
    }
    CHECK(run->binding_count == 2);
    CHECK(run->bindings[0].buffer.argument == 1 && run->bindings[0].buffer.index == 0 &&
          run->bindings[0].buffer.type_size == 32 && run->bindings[0].buffer.type_alignment == 16);
    CHECK(run->bindings[1].buffer.argument == 2 && run->bindings[1].buffer.index == 1 &&
          run->bindings[1].buffer.type_size == 8 && run->bindings[1].buffer.type_alignment == 8);
    for (unsigned i = 0; i < run->binding_count; ++i) {
        const struct binding *b = &run->bindings[i];
        record_begin("evidence");
        record_str("topic", "render-binding");
        record_object("facts");
        record_uint("slot", i);
        record_uint("argument", b->buffer.argument);
        record_uint("metal_index", b->buffer.index);
        record_uint("address_space", b->buffer.address_space);
        record_uint("required_access", b->view.access);
        record_uint("available_access", b->view.available_access);
        record_uint("type_stride", b->buffer.type_size);
        record_uint("logical_elements", b->logical_elements);
        record_uint("buffer_size", b->view.buffer_size);
        record_uint("offset", b->view.offset);
        record_uint("view_size", b->view.size);
        record_uint("alignment", b->view.alignment);
        record_uint("allocation_address_model", b->allocation_address);
        record_end();
    }
    uint8_t table[TABLE_BYTES], changed[TABLE_BYTES]; CHECK(pack_table(run, run->bindings, 2, table));
    binding_refusals(run);
    struct binding rows[MAX_BINDINGS]; memcpy(rows, run->bindings, sizeof(rows));
    rows[0].allocation_address += 0x10000; CHECK(pack_table(run, rows, 2, changed) && memcmp(table, changed, sizeof(table)));
    struct raster_model models[] = {{.samples = 1}, {.samples = 4, .sample_shading = true}};
    struct nak_fs_key untouched; memset(&untouched, 0xa5, sizeof(untouched)); uint8_t before[sizeof(untouched)]; memcpy(before, &untouched, sizeof(before));
    struct raster_model bad = {.samples = 1, .sample_shading = true}; CHECK(!model_key(&bad, &untouched) && !memcmp(&untouched, before, sizeof(before)));
    for (unsigned i = 0; i < ARRAY_SIZE(stela_nv_sms); ++i) {
        for (unsigned m = 0; m < ARRAY_SIZE(models); ++m) {
            char target[64];
            target_name(target, stela_nv_sms[i], models[m].samples, "vs"); record_expect(target, NULL);
            target_name(target, stela_nv_sms[i], models[m].samples, "fs"); record_expect(target, NULL);
        }
    }
    for (unsigned i = 0; i < ARRAY_SIZE(stela_nv_sms); ++i)
        for (unsigned m = 0; m < ARRAY_SIZE(models); ++m) compile_target(run, fs, stela_nv_sms[i], &models[m]);
    /* Each model compiles both stages twice and binds the vertex buffers once;
     * the two failed view refusals each attempted one binding. */
    const unsigned models_compiled = ARRAY_SIZE(stela_nv_sms) * ARRAY_SIZE(models);
    CHECK(run->backend_calls == 4 * models_compiled && run->callbacks == MAX_BINDINGS * models_compiled &&
          run->binding_attempts == MAX_BINDINGS * models_compiled + 2);
    puts("Compiler only: full original code/info/hdr/assembly recaptured after original bin destruction; "
         "model views/keys are not a graphics PSO or runtime resource owner");
    return true;
}
static bool vertex(const struct stela_air_inspection *inspection,
                    const struct stela_air_stage_entry *entry, void *data)
{
    (void)inspection;
    struct run *run = data; run->vs = entry; struct stela_air_error error;
    /* Nested inspection keeps both descriptor/string sets live; neither is
     * retained after this callback, and translated NIR owns its own names. */
    bool success = stela_air_inspect_stage(run->bytes, run->size, run->fragment,
        STELA_AIR_FRAGMENT, fragment, run, &error);
    run->vs = NULL;
    memset(run->map, 0, sizeof(run->map));
    run->varying_count = 0;
    return success;
}
static bool name_valid(const char *name)
{
    if (!name || !*name || strlen(name) > 255) return false;
    for (const char *p = name; *p; ++p) if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' || *p == '$')) return false;
    return true;
}
int main(int argc, char **argv)
{
    struct run run = {0}; const char *input = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--input") && !input && i + 1 < argc) input = argv[++i];
        else if (!strcmp(argv[i], "--vertex") && !run.vertex && i + 1 < argc) run.vertex = argv[++i];
        else if (!strcmp(argv[i], "--fragment") && !run.fragment && i + 1 < argc) run.fragment = argv[++i];
        else if (!strcmp(argv[i], "--output") && !run.output && i + 1 < argc) run.output = argv[++i];
        else goto usage;
    }
    if (!input || !name_valid(run.vertex) || !name_valid(run.fragment)) goto usage;
    FILE *stream = fopen(input, "rb"); CHECK(stream && !fseek(stream, 0, SEEK_END)); long size = ftell(stream);
    CHECK(size > 0 && size <= 64 * 1024 * 1024 && !fseek(stream, 0, SEEK_SET));
    void *bytes = malloc((size_t)size); CHECK(bytes && fread(bytes, 1, (size_t)size, stream) == (size_t)size && !fclose(stream));
    run.bytes = bytes; run.size = (size_t)size;
    char input_hash[BLAKE3_HEX_LEN]; stela_digest(bytes, run.size, input_hash);
    stela_air_probe_input_record(true, run.size, input_hash, run.vertex);
    record_object("facts"); record_str("fragment_entry", run.fragment); record_end();
    glsl_type_singleton_init_or_ref(); struct stela_air_error error;
    bool success = stela_air_inspect_stage(bytes, run.size, run.vertex, STELA_AIR_VERTEX, vertex, &run, &error);
    if (!success) fprintf(stderr, "stage inspection failed: %u %s\n", error.kind, error.detail);
    CHECK(success && !run.vs && !run.varying_count);
    glsl_type_singleton_decref(); free(bytes); return 0;
usage:
    fprintf(stderr, "usage: %s --input unchanged.bc --vertex NAME --fragment NAME [--output existing-directory]\n", argv[0]);
    return 2;
}
