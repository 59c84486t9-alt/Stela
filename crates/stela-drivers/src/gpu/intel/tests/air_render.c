/* SPDX-License-Identifier: MIT */
/* Offline VS/FS compiler qualification, not a render pipeline or GPU run.
 * Device profiles come from original Mesa compile models. No allocation,
 * surface, vertex fetch state, URB reservation or render target is published.
 */
#include "air_to_nir.h"
#include "../hosted/fp_controls.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/brw/brw_eu.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/dev/intel_debug.h"
#include "util/ralloc.h"
#include "compiler/tests/air_probe.h"
#include "compiler/tests/targets/intel.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef NDEBUG
#error "Render qualification requires original compiler assertions"
#endif
#define CHECK(x) \
    do { \
        if (!(x)) { \
            fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); \
            abort(); \
        } \
    } while (0)

struct input { void *bytes; size_t size; const char *vertex, *fragment; };
struct binding { unsigned seen, reject; };
struct pair {
    const struct input *input;
    const nir_shader_compiler_options *options[2];
    const struct stela_air_stage_entry *vertex;
    nir_shader *nir[2];
    unsigned linked, reject;
};
struct compiled {
    void *context;
    nir_shader *nir[2];
    const void *code[2];
    union { struct brw_vs_prog_data brw; struct elk_vs_prog_data elk; } vs;
    union { struct brw_fs_prog_data brw; struct elk_fs_prog_data elk; } fs;
};

bool stela_intel_render_elk_valid(const struct elk_compiler *, const void *, unsigned, FILE *);
static FILE *disassembly;

static void compiler_log(void *data, unsigned *id, const char *format, ...)
{
    (void)data; (void)id;
    va_list arguments;
    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
}


/* A compile target: "<platform>-<stage>", also its artifacts' stem. */
static void target_name(char name[64], const char *platform, unsigned stage)
{
    snprintf(name, 64, "%s-%s", platform, stage ? "fragment" : "vertex");
}

static void save(const char *platform, unsigned stage, const char *kind, const void *data,
    size_t size)
{
    const char *directory = getenv("STELA_RENDER_EVIDENCE");
    if (!directory) return;
    char target[64], name[128], path[4096];
    target_name(target, platform, stage);
    int n = snprintf(name, sizeof(name), "%s.%s", target, kind);
    CHECK(n > 0 && (size_t)n < sizeof(name));
    n = snprintf(path, sizeof(path), "%s/%s", directory, name);
    CHECK(n > 0 && (size_t)n < sizeof(path));
    FILE *file = fopen(path, "wb"); CHECK(file);
    CHECK((!size || fwrite(data, 1, size, file) == size) && !fclose(file));
    record_artifact(name);
}

static bool bind_ssbo(const struct stela_air_buffer *b, unsigned *slot, void *data)
{
    struct binding *binding = data;
    /* Fixture ABI, checked against actual inspected descriptors. The two
     * bindings remain distinct exact RAW views; no address is manufactured.
     * A runtime owner still owes base, byte length, rights, cache visibility,
     * BTI placement and original platform-specific resource state.
     */
    if (b->address_space != 2 || b->access != STELA_AIR_READ || b->index > 1 ||
        b->argument != b->index + 1 || b->type_size != (b->index ? 8u : 32u) ||
        b->type_alignment != (b->index ? 8u : 16u) || binding->reject ||
        (binding->seen & (1u << b->index))) return false;
    binding->seen |= 1u << b->index; *slot = b->index;
    return true;
}

static bool fragment(const struct stela_air_inspection *inspection,
                     const struct stela_air_stage_entry *entry, void *data)
{
    (void)inspection;
    struct pair *p = data;
    struct stela_air_varying_slot map[32]; unsigned count = 0;
    struct stela_air_error error;
    unsigned limit = p->reject == 2 ? 0 : 16;
    if (!stela_air_link_stage_io(p->vertex, entry, limit, map, ARRAY_SIZE(map), &count, &error))
        return false;
    CHECK(count && count <= limit);
    p->linked = count;
    if (p->reject == 3) map[0].components = map[0].components == 1 ? 2 : 1;
    struct binding bindings[2] = {{.reject = p->reject == 1}, {0}};
    for (unsigned stage = 0; stage < 2; stage++) {
        const struct stela_air_stage_options opts = {
            .stage = stage ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX,
            .resources = {.max_instructions = p->reject == 4 ? 0 : 10000,
                .bind_ssbo = stage ? NULL : bind_ssbo,
                .ssbo_count = stage ? 0 : p->reject == 5 ? 1 : 2, .binding_data = &bindings[stage],
                .fp_profile = STELA_AIR_FP_METAL},
            .varyings = map, .varying_count = count, .max_varying_slots = limit,
        };
        p->nir[stage] = stela_air_stage_to_nir(p->input->bytes, p->input->size,
            stage ? p->input->fragment : p->input->vertex, p->options[stage], &opts, &error);
        if (!p->nir[stage]) return false;
    }
    CHECK(bindings[0].seen == 3 && !bindings[1].seen);
    return true;
}

static bool vertex(const struct stela_air_inspection *inspection,
                   const struct stela_air_stage_entry *entry, void *data)
{
    (void)inspection;
    struct pair *p = data; p->vertex = entry;
    struct stela_air_error error;
    bool ok = stela_air_inspect_stage(p->input->bytes, p->input->size, p->input->fragment,
        STELA_AIR_FRAGMENT, fragment, p, &error);
    p->vertex = NULL;
    return ok;
}

static void lower_pair(struct pair *p, unsigned reject)
{
    struct stela_air_error error;
    p->reject = reject;
    bool ok = stela_air_inspect_stage(p->input->bytes, p->input->size, p->input->vertex,
        STELA_AIR_VERTEX, vertex, p, &error);
    if (reject) {
        CHECK(!ok && !p->vertex);
        for (unsigned i = 0; i < 2; i++) { ralloc_free(p->nir[i]); p->nir[i] = NULL; }
        return;
    }
    if (!ok) fprintf(stderr, "AIR stage refusal: %u %s\n", error.kind, error.detail);
    CHECK(ok && p->linked && !p->vertex && p->nir[0] && p->nir[1]);
    CHECK(p->nir[0]->info.stage == MESA_SHADER_VERTEX &&
        p->nir[1]->info.stage == MESA_SHADER_FRAGMENT);
    CHECK(p->nir[0]->info.num_ssbos == 2 && !p->nir[1]->info.num_ssbos);
    CHECK(p->nir[0]->info.outputs_written & VARYING_BIT_POS);
    CHECK(p->nir[1]->info.outputs_written == BITFIELD64_BIT(FRAG_RESULT_DATA0));
    unsigned loads = 0, bounds = 0, vertex_ids = 0, wide_bounds = 0, dynamic_offsets = 0;
    nir_foreach_function_impl(impl, p->nir[0]) nir_foreach_block(block, impl)
        nir_foreach_instr(instr, block) {
            CHECK(instr->type != nir_instr_type_tex);
            if (instr->type == nir_instr_type_alu) {
                const nir_alu_instr *alu = nir_instr_as_alu(instr);
                wide_bounds += alu->op == nir_op_uge && alu->src[0].src.ssa->bit_size == 64;
            }
            if (instr->type != nir_instr_type_intrinsic) continue;
            const nir_intrinsic_instr *in = nir_instr_as_intrinsic(instr);
            CHECK(in->intrinsic != nir_intrinsic_load_global &&
                in->intrinsic != nir_intrinsic_store_global &&
                in->intrinsic != nir_intrinsic_store_ssbo);
            if (in->intrinsic == nir_intrinsic_load_ssbo) {
                CHECK(nir_src_is_const(in->src[0]) && nir_src_as_uint(in->src[0]) < 2);
                dynamic_offsets += !nir_src_is_const(in->src[1]);
                loads++;
            }
            bounds += in->intrinsic == nir_intrinsic_get_ssbo_size;
            vertex_ids += in->intrinsic == nir_intrinsic_load_vertex_id;
        }
    CHECK(loads && bounds && vertex_ids && dynamic_offsets && wide_bounds >= 2 * loads);
    unsigned interpolated = 0;
    nir_foreach_shader_in_variable(var, p->nir[1]) {
        if (var->data.location < VARYING_SLOT_VAR0) continue;
        CHECK(var->data.interpolation == INTERP_MODE_SMOOTH && !var->data.sample &&
            !var->data.centroid);
        interpolated++;
    }
    CHECK(interpolated == p->linked);
    for (unsigned i = 0; i < 2; i++)
        nir_validate_shader(p->nir[i], "linked original AIR render stage");
}

static void validate(const struct intel_device_info *dev, const struct elk_compiler *elk,
                     void *context, const void *code, unsigned bytes)
{
    CHECK(code && bytes);
    if (elk) {
        CHECK(stela_intel_render_elk_valid(elk, code, bytes, disassembly));
        CHECK(!stela_intel_render_elk_valid(elk, code, 1, NULL));
        return;
    }
    gen_decode_params decoded = {.devinfo = dev, .mem_ctx = context,
        .raw_bytes = code, .raw_bytes_size = (int)bytes};
    CHECK(gen_decode(&decoded));
    gen_inst_layout *layouts = ralloc_array(context, gen_inst_layout, bytes / 8);
    CHECK(layouts);
    gen_scan_raw_layout_params layout = {.raw_bytes = code, .raw_bytes_size = (int)bytes,
        .layouts = layouts, .num_insts = (int)(bytes / 8)};
    CHECK(gen_scan_raw_layout(&layout) && layout.num_insts == decoded.num_insts &&
          layout.end_offset == (int)bytes);
    /* The original compiler aligns successive SIMD programs to64 bytes with
     * zero padding. Validate real instructions through the original decoded
     * EOT; do not ask the ISA validator to execute alignment bytes as a kernel.
     * The whole allocated blob, including every padding byte, is recaptured.
     */
    int end = -1;
    for (int i = 0; i < decoded.num_insts; i++) {
        const gen_inst *in = &decoded.insts[i];
        if ((in->opcode == GEN_OP_SEND || in->opcode == GEN_OP_SENDC ||
             in->opcode == GEN_OP_SENDS || in->opcode == GEN_OP_SENDSC) && in->send.eot) {
            end = i + 1; break;
        }
    }
    CHECK(end > 0);
    while (end < decoded.num_insts && decoded.insts[end].opcode == GEN_OP_NOP) end++;
    unsigned real_bytes = (unsigned)layouts[end - 1].offset +
        (layouts[end - 1].was_compacted ? 8 : 16);
    for (unsigned i = real_bytes; i < bytes; i++) CHECK(!((const uint8_t *)code)[i]);
    gen_validate_params validation = {.devinfo = dev, .mem_ctx = context,
        .insts = decoded.insts, .num_insts = end};
    bool valid = gen_validate(&validation);
    for (int i = 0; i < validation.num_errors; i++)
        fprintf(stderr, "render ISA %u.%u instruction %d: %s\n", dev->ver, dev->verx10 % 10,
            validation.errors[i].index, validation.errors[i].msg);
    CHECK(valid);
    if (disassembly) {
        gen_print_params print = {.devinfo = dev, .fp = disassembly,
            .flags = GEN_PRINT_HEX | GEN_PRINT_BYTE_OFFSETS | GEN_PRINT_IGNORE_ENV,
            .insts = decoded.insts, .num_insts = end, .raw_bytes = code,
            .raw_bytes_size = (int)real_bytes, .validate = true};
        CHECK(gen_print(&print));
    }
    gen_inst invalid = decoded.insts[0]; invalid.exec_size = 0;
    gen_validate_params negative = {
        .devinfo = dev, .mem_ctx = context, .insts = &invalid, .num_insts = 1};
    CHECK(!gen_validate(&negative));
}

static void compile_pair(const struct input *input, const struct brw_compiler *brw,
                         const struct elk_compiler *elk, struct compiled *out)
{
    const struct intel_device_info *dev = brw ? brw->devinfo : elk->devinfo;
    struct pair p = {.input = input};
    for (unsigned i = 0; i < 2; i++) {
        mesa_shader_stage stage = i ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX;
        p.options[i] = brw ? &brw->nir_options[stage] : elk->nir_options[stage];
    }
    for (unsigned reject = 1; reject <= 5; reject++) lower_pair(&p, reject);
    lower_pair(&p, 0);
    out->context = ralloc_context(NULL); CHECK(out->context);
    for (unsigned i = 0; i < 2; i++) {
        out->nir[i] = p.nir[i];
        if (brw) {
            const struct brw_nir_compiler_opts opts = {0}; brw_preprocess_nir(brw, p.nir[i], &opts);
        } else {
            const struct elk_nir_compiler_opts opts = {0}; elk_preprocess_nir(elk, p.nir[i], &opts);
        }
        nir_shader_gather_info(p.nir[i], nir_shader_get_entrypoint(p.nir[i]));
        CHECK(stela_intel_fp_controls(dev, &p.nir[i]->info) == 0);
    }
    /* Explicit raster fixture: fixed linked VUE, one color region, one sample,
     * pixel-center perspective interpolation; no multisampling, alpha test,
     * sample mask output, coarse dispatch, mesh/multiview or dual source.
     * The original compiler owns stage lowering, VUE slot policy and ISA.
     */
    if (brw) {
        struct brw_vs_prog_key vk = {.base = {.vue_layout = INTEL_VUE_LAYOUT_FIXED}};
        struct brw_compile_vs_params vp = {.base = {.mem_ctx = out->context, .nir = p.nir[0],
            .key = &vk.base, .prog_data = &out->vs.brw.base.base}};
        out->code[0] = brw_compile(brw, &vp.base); CHECK(out->code[0] && !vp.base.error_str);
        struct brw_fs_prog_key fk = {.base = {.vue_layout = INTEL_VUE_LAYOUT_FIXED},
            .nr_color_regions = 1, .ignore_sample_mask_out = true};
        struct brw_compile_fs_params fp = {.base = {.mem_ctx = out->context, .nir = p.nir[1],
            .key = &fk.base, .prog_data = &out->fs.brw.base},
            .vue_map = &out->vs.brw.base.vue_map, .max_polygons = 1};
        out->code[1] = brw_compile(brw, &fp.base); CHECK(out->code[1] && !fp.base.error_str);
    } else {
        struct elk_vs_prog_key vk = {0};
        out->vs.elk.base.base.param = ralloc_array(out->context, uint32_t, 0);
        CHECK(out->vs.elk.base.base.param);
        elk_compute_vue_map(dev, &out->vs.elk.base.vue_map, p.nir[0]->info.outputs_written,
            INTEL_VUE_LAYOUT_FIXED, 1);
        struct elk_compile_vs_params vp = {.base = {.mem_ctx = out->context, .nir = p.nir[0]},
            .key = &vk, .prog_data = &out->vs.elk};
        out->code[0] = elk_compile_vs(elk, &vp); CHECK(out->code[0] && !vp.base.error_str);
        struct elk_fs_prog_key fk = {.input_slots_valid = out->vs.elk.base.vue_map.slots_valid,
            .nr_color_regions = 1, .color_outputs_valid = 1, .ignore_sample_mask_out = true};
        out->fs.elk.base.param = ralloc_array(out->context, uint32_t, 0);
        CHECK(out->fs.elk.base.param);
        struct elk_compile_fs_params fp = {.base = {.mem_ctx = out->context, .nir = p.nir[1]},
            .key = &fk, .prog_data = &out->fs.elk, .vue_map = &out->vs.elk.base.vue_map,
            .allow_spilling = true, .max_polygons = 1};
        out->code[1] = elk_compile_fs(elk, &fp); CHECK(out->code[1] && !fp.base.error_str);
    }
    const struct intel_vue_map *vue = brw ? &out->vs.brw.base.vue_map : &out->vs.elk.base.vue_map;
    CHECK(vue->slots_valid & VARYING_BIT_POS);
    CHECK(vue->slots_valid & BITFIELD64_BIT(VARYING_SLOT_VAR0));
    CHECK(vue->varying_to_slot[VARYING_SLOT_POS] >= 0 &&
        vue->varying_to_slot[VARYING_SLOT_VAR0] >= 0);
    for (unsigned i = 0; i < 2; i++) {
        unsigned bytes = brw ?
            (i ? out->fs.brw.base.program_size : out->vs.brw.base.base.program_size) :
            (i ? out->fs.elk.base.program_size : out->vs.elk.base.base.program_size);
        unsigned constants = brw ?
            (i ? out->fs.brw.base.const_data_size : out->vs.brw.base.base.const_data_size) :
            (i ? out->fs.elk.base.const_data_size : out->vs.elk.base.base.const_data_size);
        unsigned offset = brw ?
            (i ? out->fs.brw.base.const_data_offset : out->vs.brw.base.base.const_data_offset) :
            (i ? out->fs.elk.base.const_data_offset : out->vs.elk.base.base.const_data_offset);
        CHECK(offset <= bytes && (!constants || (offset && constants <= bytes - offset)));
        unsigned executable = constants ? offset : bytes;
        if (!i) {
            if (disassembly) fprintf(disassembly, "VERTEX\n");
            validate(dev, elk, out->context, out->code[i], executable);
        }
        else {
            unsigned starts[3], n = 0;
            if (brw ? out->fs.brw.dispatch_8 || out->fs.brw.dispatch_multi : out->fs.elk.dispatch_8)
                starts[n++] = 0;
            if (brw ? out->fs.brw.dispatch_16 : out->fs.elk.dispatch_16)
                starts[n++] = brw ? out->fs.brw.prog_offset_16 : out->fs.elk.prog_offset_16;
            if (brw ? out->fs.brw.dispatch_32 : out->fs.elk.dispatch_32)
                starts[n++] = brw ? out->fs.brw.prog_offset_32 : out->fs.elk.prog_offset_32;
            CHECK(n && starts[0] == 0);
            for (unsigned j = 0; j < n; j++) {
                unsigned stop = j + 1 < n ? starts[j + 1] : executable;
                CHECK(starts[j] < stop && stop <= executable && !(starts[j] & 63));
                if (disassembly)
                    fprintf(disassembly, "FRAGMENT kernel%u byte_offset%u\n", j, starts[j]);
                validate(dev, elk, out->context, (const uint8_t *)out->code[i] + starts[j],
                    stop - starts[j]);
            }
        }
    }
}

static void compare(struct compiled *a, struct compiled *b, bool elk)
{
    /* Normalize pointer identity only in copies. Actual captured metadata and
     * its deep parameter/relocation allocations stay intact through disposal.
     * Zero-initialized source records make untouched padding deterministic.
     */
    struct compiled left = *a, right = *b; a = &left; b = &right;
    for (unsigned i = 0; i < 2; i++) {
        unsigned bytes;
        if (elk) {
            struct elk_stage_prog_data *x = i ? &a->fs.elk.base : &a->vs.elk.base.base;
            struct elk_stage_prog_data *y = i ? &b->fs.elk.base : &b->vs.elk.base.base;
            CHECK(x->num_relocs == y->num_relocs && x->nr_params == y->nr_params);
            if (x->num_relocs)
                CHECK(!memcmp(x->relocs, y->relocs, x->num_relocs * sizeof(*x->relocs)));
            if (x->nr_params) CHECK(!memcmp(x->param, y->param, x->nr_params * sizeof(*x->param)));
            x->relocs = y->relocs = NULL; x->param = y->param = NULL;
            bytes = x->program_size;
            CHECK(!memcmp(i ? (void *)&a->fs.elk : (void *)&a->vs.elk,
                          i ? (void *)&b->fs.elk : (void *)&b->vs.elk,
                          i ? sizeof(a->fs.elk) : sizeof(a->vs.elk)));
        } else {
            struct brw_stage_prog_data *x = i ? &a->fs.brw.base : &a->vs.brw.base.base;
            struct brw_stage_prog_data *y = i ? &b->fs.brw.base : &b->vs.brw.base.base;
            CHECK(x->num_relocs == y->num_relocs);
            if (x->num_relocs)
                CHECK(!memcmp(x->relocs, y->relocs, x->num_relocs * sizeof(*x->relocs)));
            x->relocs = y->relocs = NULL; bytes = x->program_size;
            CHECK(!memcmp(i ? (void *)&a->fs.brw : (void *)&a->vs.brw,
                          i ? (void *)&b->fs.brw : (void *)&b->vs.brw,
                          i ? sizeof(a->fs.brw) : sizeof(a->vs.brw)));
        }
        CHECK(!memcmp(a->code[i], b->code[i], bytes));
    }
}

static void destroy(struct compiled *c)
{
    ralloc_free(c->nir[0]);
    ralloc_free(c->nir[1]);
    ralloc_free(c->context);
    *c = (struct compiled){0};
}

static void metadata_hash(const struct compiled *c, bool legacy, unsigned stage, char out[3][65])
{
    if (legacy) {
        const struct elk_stage_prog_data *d = stage ? &c->fs.elk.base : &c->vs.elk.base.base;
        stela_digest(stage ? (const void *)&c->fs.elk : (const void *)&c->vs.elk,
             stage ? sizeof(c->fs.elk) : sizeof(c->vs.elk), out[0]);
        stela_digest(d->param, d->nr_params * sizeof(*d->param), out[1]);
        stela_digest(d->relocs, d->num_relocs * sizeof(*d->relocs), out[2]);
    } else {
        const struct brw_stage_prog_data *d = stage ? &c->fs.brw.base : &c->vs.brw.base.base;
        stela_digest(stage ? (const void *)&c->fs.brw : (const void *)&c->vs.brw,
             stage ? sizeof(c->fs.brw) : sizeof(c->vs.brw), out[0]);
        stela_digest(NULL, 0, out[1]);
        stela_digest(d->relocs, d->num_relocs * sizeof(*d->relocs), out[2]);
    }
}

static void target(const struct input *input, const char *name,
    const struct intel_device_info *device)
{
    const struct intel_device_info dev = *device; const int pci = dev.pci_device_id;
    const bool legacy = stela_intel_elk(&dev);
    if (stela_intel_hold(&dev)) {
        for (unsigned i = 0; i < 2; i++) {
            char held[64]; target_name(held, name, i); record_held(held, stela_intel_hold(&dev));
        }
        return;
    }
    void *compiler_context = ralloc_context(NULL); CHECK(compiler_context);
    struct brw_compiler *brw = legacy ? NULL : brw_compiler_create(compiler_context, &dev);
    struct elk_compiler *elk = legacy ? elk_compiler_create(compiler_context, &dev) : NULL;
    CHECK(brw || elk);
    if (brw) brw->shader_debug_log = brw->shader_perf_log = compiler_log;
    else elk->shader_debug_log = elk->shader_perf_log = compiler_log;
    struct compiled a = {0}, b = {0};
    if (disassembly)
        fprintf(disassembly, "TARGET %s PCI-model%04x ver%u RECAPTURE A\n", name, pci, dev.verx10);
    compile_pair(input, brw, elk, &a);
    if (disassembly)
        fprintf(disassembly, "TARGET %s PCI-model%04x ver%u RECAPTURE B\n", name, pci, dev.verx10);
    compile_pair(input, brw, elk, &b); compare(&a, &b, legacy);
    char retained[2][65], metadata[2][3][65];
    for (unsigned i = 0; i < 2; i++) {
        unsigned bytes = legacy ?
            (i ? a.fs.elk.base.program_size : a.vs.elk.base.base.program_size) :
            (i ? a.fs.brw.base.program_size : a.vs.brw.base.base.program_size);
        stela_digest(a.code[i], bytes, retained[i]);
        metadata_hash(&a, legacy, i, metadata[i]);
        save(name, i, "code", a.code[i], bytes);
        unsigned constants, constant_offset, relocs, params = 0, urb_read;
        if (legacy) {
            struct elk_stage_prog_data *d = i ? &a.fs.elk.base : &a.vs.elk.base.base;
            constants = d->const_data_size; constant_offset = d->const_data_offset;
            relocs = d->num_relocs; params = d->nr_params; urb_read = d->curb_read_length;
            save(name, i, "relocs", d->relocs, relocs * sizeof(*d->relocs));
            save(name, i, "params", d->param, params * sizeof(*d->param));
            struct compiled normalized = a;
            if (i) { normalized.fs.elk.base.param = NULL; normalized.fs.elk.base.relocs = NULL;
            } else {
                normalized.vs.elk.base.base.param = NULL;
                normalized.vs.elk.base.base.relocs = NULL;
            }
            save(name, i, "progdata", i ? (void *)&normalized.fs.elk : (void *)&normalized.vs.elk,
                i ? sizeof(normalized.fs.elk) : sizeof(normalized.vs.elk));
        } else {
            const struct brw_stage_prog_data *d = i ? &a.fs.brw.base : &a.vs.brw.base.base;
            constants = d->const_data_size; constant_offset = d->const_data_offset;
            relocs = d->num_relocs; urb_read = 0;
            for (unsigned j = 0; j < ARRAY_SIZE(d->push_sizes); j++) urb_read += d->push_sizes[j];
            save(name, i, "relocs", d->relocs, relocs * sizeof(*d->relocs));
            struct compiled normalized = a;
            if (i) normalized.fs.brw.base.relocs = NULL;
            else normalized.vs.brw.base.base.relocs = NULL;
            save(name, i, "progdata", i ? (void *)&normalized.fs.brw : (void *)&normalized.vs.brw,
                i ? sizeof(normalized.fs.brw) : sizeof(normalized.vs.brw));
        }
        save(name, i, "constants", constants ? (const uint8_t *)a.code[i] + constant_offset : NULL,
            constants);
        char stage_target[64]; target_name(stage_target, name, i);
        record_compiled(stage_target, bytes);
        record_object("facts");
        record_str("backend", legacy ? "elk" : "brw");
        record_uint("pci_model", pci);
        record_uint("verx10", dev.verx10);
        record_str("code_blake3", retained[i]);
        record_uint("samples", 1);
        record_uint("color_regions", 1);
        record_str("vue_layout", "fixed-original");
        record_uint("ssbo_count", i ? 0 : 2);
        record_uint("params", params);
        record_uint("relocs", relocs);
        record_uint("constant_bytes", constants);
        record_uint(legacy ? "push_registers" : "push_bytes", urb_read);
        record_uint("fp_controls", a.nir[i]->info.float_controls_execution_mode);
        record_bool("whole_recapture_equal", true);
        record_end();
    }
    const struct intel_vue_map *vue = legacy ? &a.vs.elk.base.vue_map : &a.vs.brw.base.vue_map;
    CHECK(legacy ? a.vs.elk.uses_vertexid && a.vs.elk.uses_firstvertex :
                   a.vs.brw.uses_vertexid && a.vs.brw.uses_firstvertex);
    record_begin("evidence");
    record_str("topic", "vue-link");
    record_object("facts");
    record_str("platform", name);
    record_int("vue_slots", vue->num_slots);
    record_int("position_slot", vue->varying_to_slot[VARYING_SLOT_POS]);
    record_int("varying0_slot", vue->varying_to_slot[VARYING_SLOT_VAR0]);
    record_uint("barycentric_modes",
                legacy ? a.fs.elk.barycentric_interp_modes : a.fs.brw.barycentric_interp_modes);
    record_bool("vertex_id_includes_base", true);
    record_bool("whole_original_progdata_retained", true);
    record_end();
    /* One sibling output survives independent NIR/context disposal. */
    destroy(&b);
    for (unsigned i = 0; i < 2; i++) {
        unsigned bytes = legacy ?
            (i ? a.fs.elk.base.program_size : a.vs.elk.base.base.program_size) :
            (i ? a.fs.brw.base.program_size : a.vs.brw.base.base.program_size);
        char after[65]; stela_digest(a.code[i], bytes, after); CHECK(!strcmp(after, retained[i]));
        char after_metadata[3][65]; metadata_hash(&a, legacy, i, after_metadata);
        CHECK(!memcmp(metadata[i], after_metadata, sizeof(after_metadata)));
    }
    destroy(&a); ralloc_free(compiler_context);
}

static bool unexpected_stage(const struct stela_air_inspection *inspection,
                             const struct stela_air_stage_entry *entry, void *data)
{
    (void)inspection; (void)entry; (*(unsigned *)data)++; return true;
}

static void inspect_refusals(const struct input *input)
{
    struct stela_air_error error;
    unsigned callbacks = 0;
    CHECK(!stela_air_inspect_stage(input->bytes, input->size, input->vertex, STELA_AIR_FRAGMENT,
        unexpected_stage, &callbacks, &error) && !callbacks && error.kind != STELA_AIR_OK);
    CHECK(!stela_air_inspect_stage(input->bytes, input->size, input->fragment, STELA_AIR_VERTEX,
        unexpected_stage, &callbacks, &error) && !callbacks && error.kind != STELA_AIR_OK);
    CHECK(!stela_air_inspect_stage(input->bytes, 3, input->vertex, STELA_AIR_VERTEX,
        unexpected_stage, &callbacks, &error) && !callbacks && error.kind != STELA_AIR_OK);
    CHECK(!stela_air_inspect_stage(input->bytes, input->size, "", STELA_AIR_VERTEX,
        unexpected_stage, &callbacks, &error) && !callbacks && error.kind != STELA_AIR_OK);
}

static struct input read_input(const char *path, const char *vertex_name, const char *fragment_name)
{
    FILE *file = fopen(path, "rb"); CHECK(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file);
    CHECK(size >= 4 && size <= 16 * 1024 * 1024 && !fseek(file, 0, SEEK_SET));
    struct input input = {.bytes = malloc((size_t)size), .size = (size_t)size,
        .vertex = vertex_name, .fragment = fragment_name}; CHECK(input.bytes);
    CHECK(fread(input.bytes, 1, input.size, file) == input.size && !fclose(file));
    return input;
}

int main(int argc, char **argv)
{
    if (argc != 4 && argc != 6) {
        fprintf(stderr,
            "usage: %s RAW_AIR VERTEX_ENTRY FRAGMENT_ENTRY [REFUSED_RAW REFUSED_FRAGMENT_ENTRY]\n",
            argv[0]);
        return 2;
    }
    struct input input = read_input(argv[1], argv[2], argv[3]);
    char original[65]; stela_digest(input.bytes, input.size, original);
    stela_air_probe_input_record(true, input.size, original, input.vertex);
    record_object("facts"); record_str("fragment_entry", input.fragment); record_end();
    process_intel_debug_variable(); glsl_type_singleton_init_or_ref();
    const char *isa_path = getenv("STELA_RENDER_DISASSEMBLY");
    if (isa_path) { disassembly = fopen(isa_path, "w"); CHECK(disassembly); }
    inspect_refusals(&input);
    if (argc == 6) {
        struct input refused = read_input(argv[4], NULL, argv[5]);
        struct stela_air_error error; unsigned callbacks = 0;
        CHECK(!stela_air_inspect_stage(refused.bytes, refused.size, refused.fragment,
                  STELA_AIR_FRAGMENT, unexpected_stage, &callbacks, &error) &&
            !callbacks && error.kind != STELA_AIR_OK);
        record_begin("evidence");
        record_str("topic", "refused-input");
        record_object("facts");
        record_uint("bytes", refused.size);
        record_blake3("blake3", refused.bytes, refused.size);
        record_str("entry", refused.fragment);
        record_uint("metadata_error", error.kind);
        record_uint("callbacks", 0);
        record_end();
        free(refused.bytes);
    }
    struct intel_device_info device; const char *platform;
    STELA_INTEL_FOREACH_TARGET(platform, device) {
        for (unsigned i = 0; i < 2; i++) {
            char name[64];
            target_name(name, platform, i);
            record_expect(name, stela_intel_hold(&device));
        }
    }
    STELA_INTEL_FOREACH_TARGET(platform, device) target(&input, platform, &device);
    char after[65]; stela_digest(input.bytes, input.size, after); CHECK(!strcmp(after, original));
    if (disassembly) CHECK(!fclose(disassembly));
    glsl_type_singleton_decref(); free(input.bytes); return 0;
}
