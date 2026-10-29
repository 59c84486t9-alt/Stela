/* SPDX-License-Identifier: MIT */
/* Canonical selected-stage owner/compiled package tests. Synthetic MTLB outer
 * framing identifies actual vertex0/fragment1 roles around unchanged externally
 * supplied AIR. It is not claimed to be an original Apple-produced archive or
 * source-request provenance. Device profiles/placements are CPU-only models.
 */
#include "../hosted/air_graphics.h"
#include "compiler/tests/probe_report.h"
#include "compiler/tests/targets/intel.h"
#include "compiler/tests/air_test_fixture.h"
#include "compiler/tests/air_permutation_stage_fixture.h"
#include "util/ralloc.h"
#include <CommonCrypto/CommonDigest.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#error "Graphics owner qualification requires assertions"
#endif
#define CHECK(x) \
    do { \
        if (!(x)) { \
            fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); \
            abort(); \
        } \
    } while (0)

static unsigned live_allocations, live_contexts;
#ifdef STELA_INTEL_GRAPHICS_ALLOCATION_TEST
static unsigned allocations, fail_allocation;
static void *contexts[8];
static void *test_calloc(size_t count, size_t bytes)
{
    if (++allocations == fail_allocation) return NULL;
    void *p = calloc(count, bytes); if (p) live_allocations++; return p;
}
static void test_free(void *p)
{
    if (p) { CHECK(live_allocations); live_allocations--; } free(p);
}
static void *test_ralloc_context(const void *parent)
{
    if (++allocations == fail_allocation) return NULL;
    void *p = ralloc_context(parent); if (!p) return NULL;
    unsigned i; for (i = 0; i < ARRAY_SIZE(contexts); i++) if (!contexts[i]) break;
    CHECK(i < ARRAY_SIZE(contexts)); contexts[i] = p; live_contexts++; return p;
}
static void *test_ralloc_array_size(const void *parent, size_t bytes, unsigned count)
{
    if (++allocations == fail_allocation) return NULL;
    return ralloc_array_size(parent, bytes, count);
}
static void test_ralloc_free(void *p)
{
    for (unsigned i = 0; i < ARRAY_SIZE(contexts); i++) if (p && p == contexts[i]) {
        CHECK(live_contexts); live_contexts--; contexts[i] = NULL; break;
    }
    ralloc_free(p);
}
#define calloc test_calloc
#define free test_free
#define ralloc_context test_ralloc_context
#define ralloc_array_size test_ralloc_array_size
#define ralloc_free test_ralloc_free
#endif
/* The production TU itself, so the allocation build denies only its own
 * allocations; original compiler and canonical-assembly allocators are real. */
#include "../hosted/air_graphics.c"
#ifdef STELA_INTEL_GRAPHICS_ALLOCATION_TEST
#undef calloc
#undef free
#undef ralloc_context
#undef ralloc_array_size
#undef ralloc_free
#endif

struct bytes { uint8_t *data; size_t size; };
static void append(struct bytes *b, const void *data, size_t bytes)
{
    CHECK(bytes <= SIZE_MAX - b->size);
    b->data = realloc(b->data, b->size + bytes); CHECK(b->data);
    memcpy(b->data + b->size, data, bytes); b->size += bytes;
}
static void little(void *data, uint64_t value, unsigned bytes)
{
    for (unsigned i = 0; i < bytes; i++) ((uint8_t *)data)[i] = (uint8_t)(value >> (8 * i));
}
static void tag(struct bytes *b, const char name[4], const void *data, size_t bytes)
{
    uint8_t length[2]; CHECK(bytes <= UINT16_MAX); little(length, bytes, 2);
    append(b, name, 4); append(b, length, 2); append(b, data, bytes);
}
static struct bytes archive(const void *air, size_t bytes, const char *entry,
    enum stela_air_stage role)
{
    CHECK(bytes <= AIR_MAX_BITCODE_BYTES);
    struct bytes record = {0};
    uint8_t prefix[4] = {0}, kind = role == STELA_AIR_VERTEX ? 0 : 1, digest[32];
    CC_SHA256(air, (CC_LONG)bytes, digest);
    append(&record, prefix, 4); tag(&record, "NAME", entry, strlen(entry) + 1);
    tag(&record, "TYPE", &kind, 1); tag(&record, "HASH", digest, sizeof(digest));
    uint8_t length[8], offsets[24] = {0}, versions[8]; little(length, bytes, 8);
    tag(&record, "MDSZ", length, 8); tag(&record, "OFFT", offsets, sizeof(offsets));
    little(versions, 2, 2); little(versions + 2, 9, 2);
    little(versions + 4, 4, 2); little(versions + 6, 1, 2);
    tag(&record, "VERS", versions, sizeof(versions)); append(&record, "ENDT", 4);
    little(record.data, record.size, 4);
    uint8_t header[88] = {0}; memcpy(header, "MTLB", 4);
    little(header + 4, 0x8001, 2); little(header + 6, 2, 2); little(header + 8, 9, 2);
    header[11] = 0x81; little(header + 12, 27, 2); little(header + 14, 2, 2);
    size_t start = 92 + record.size;
    little(header + 16, start + bytes, 8);
    little(header + 24, 88, 8);
    little(header + 32, record.size, 8);
    little(header + 40, start, 8); little(header + 56, start, 8);
    little(header + 72, start, 8); little(header + 80, bytes, 8);
    struct bytes result = {0}; append(&result, header, sizeof(header)); little(prefix, 1, 4);
    append(&result, prefix, 4);
    append(&result, record.data, record.size);
    append(&result, air, bytes);
    free(record.data); return result;
}
static struct stela_metal_assembly *stage(const struct bytes *raw, const char *entry,
    enum stela_air_stage role)
{
    struct bytes framed = archive(raw->data, raw->size, entry, role);
    struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
    struct stela_metal_assembly_error error; struct stela_metal_assembly *owner = NULL;
    enum stela_metal_assembly_status status = stela_metal_assemble_selected_stage_archive(
        &options, framed.data, framed.size, 0, role, &owner, &error);
    if (status) fprintf(stderr,"Selected stage: %u %s\n",status,error.detail);
    CHECK(status == STELA_METAL_ASSEMBLY_OK && owner && !stela_metal_assembly_manifest(owner));
    const struct stela_metal_stage_view *view = stela_metal_assembly_stage(owner);
    CHECK(view && view->reflection->stage == role && !view->provenance->entries &&
        !view->provenance->entry_count);
    memset(framed.data, 0xa5, framed.size); free(framed.data);
    CHECK(view->identity->name_bytes == strlen(entry) &&
        !strcmp((const char *)view->identity->name, entry));
    return owner;
}
static struct stela_intel_graphics_options options(void)
{
    return (struct stela_intel_graphics_options){
        .size = sizeof(struct stela_intel_graphics_options),
        .abi = STELA_INTEL_GRAPHICS_ABI,
        .max_instructions = 10000,
        .max_code_bytes = 1024 * 1024,
        .max_varying_slots = 16,
        .color_regions = 1,
        .samples = 1,
        .vertex_fp_profile = STELA_AIR_FP_METAL,
        .fragment_fp_profile = STELA_AIR_FP_METAL};
}
static void compiler_log(void *data, unsigned *id, const char *format, ...)
{
    (void)data; (void)id;
    va_list args; va_start(args, format); vfprintf(stderr, format, args); va_end(args);
}
static void golden(const char *directory, const char *target, unsigned stage_index,
    const char *kind, const void *bytes, size_t size)
{
    char path[4096]; int length = snprintf(path,sizeof(path),"%s/%s-%s.%s",directory,target,
        stage_index ? "fragment" : "vertex",kind);
    CHECK(length > 0 && (size_t)length < sizeof(path));
    FILE *file = fopen(path,"rb"); CHECK(file && !fseek(file,0,SEEK_END));
    CHECK(ftell(file) == (long)size && !fseek(file,0,SEEK_SET));
    uint8_t *copy = malloc(size ? size : 1); CHECK(copy);
    CHECK((!size || fread(copy,1,size,file) == size) && !fclose(file));
    CHECK(!size || !memcmp(copy,bytes,size)); free(copy);
}
static void compare(const struct stela_intel_graphics_compilation *owner, const char *directory,
    const char *target)
{
    const struct stela_intel_graphics_provenance *p = stela_intel_graphics_provenance(owner);
    for (unsigned i = 0; i < 2; i++) {
        const struct stela_intel_graphics_stage_binary *b = stela_intel_graphics_binary(owner,
            i ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX);
        CHECK(b && b->code && b->code_bytes && b->executable_bytes <= b->code_bytes);
        golden(directory,target,i,"code",b->code,b->code_bytes);
        unsigned constants, offset;
        if (p->backend == STELA_INTEL_GRAPHICS_ELK) {
            struct elk_vs_prog_data vs = {0}; struct elk_fs_prog_data fs = {0};
            if (i) fs = *b->elk_fs; else vs = *b->elk_vs;
            struct elk_stage_prog_data *d = i ? &fs.base : &vs.base.base;
            golden(directory,target,i,"params",d->param,d->nr_params*sizeof(*d->param));
            golden(directory,target,i,"relocs",d->relocs,d->num_relocs*sizeof(*d->relocs));
            constants = d->const_data_size;
            offset = d->const_data_offset;
            d->param = NULL;
            d->relocs = NULL;
            golden(directory, target, i, "progdata", i ? (void *)&fs : (void *)&vs,
                i ? sizeof(fs) : sizeof(vs));
        } else {
            struct brw_vs_prog_data vs = {0}; struct brw_fs_prog_data fs = {0};
            if (i) fs = *b->brw_fs; else vs = *b->brw_vs;
            struct brw_stage_prog_data *d = i ? &fs.base : &vs.base.base;
            golden(directory,target,i,"relocs",d->relocs,d->num_relocs*sizeof(*d->relocs));
            constants = d->const_data_size; offset = d->const_data_offset; d->relocs = NULL;
            golden(directory, target, i, "progdata", i ? (void *)&fs : (void *)&vs,
                i ? sizeof(fs) : sizeof(vs));
        }
        golden(directory, target, i, "constants",
            constants ? (const uint8_t *)b->code + offset : NULL, constants);
    }
}
static void failures(const struct brw_compiler *brw, const struct elk_compiler *elk,
    struct stela_metal_assembly **v, struct stela_metal_assembly **f)
{
    struct stela_metal_assembly *vertex = *v, *fragment = *f;
    struct stela_intel_graphics_compilation *output = NULL;
    struct stela_intel_graphics_error error;
    struct stela_intel_graphics_options o = options();
    CHECK(stela_intel_graphics_compile(brw, elk, NULL, v, v, &o, &output, &error) ==
        STELA_INTEL_GRAPHICS_INVALID);
    CHECK(stela_intel_graphics_compile(brw, elk, NULL, v, f, &o,
              (struct stela_intel_graphics_compilation **)v,
              &error) == STELA_INTEL_GRAPHICS_INVALID);
    CHECK(stela_intel_graphics_compile(brw, elk, NULL, f, v, &o, &output, &error) ==
        STELA_INTEL_GRAPHICS_INVALID);
    for (unsigned i = 0; i < 5; i++) {
        o = options();
        if (i == 0) o.samples = 2;
        if (i == 1) o.color_regions = 2;
        if (i == 2) o.vertex_fp_profile = (enum stela_air_fp_profile)99;
        if (i == 3) o.max_instructions = 0;
        if (i == 4) o.max_code_bytes = 1;
        enum stela_intel_graphics_status status = stela_intel_graphics_compile(brw, elk, NULL, v, f,
            &o, &output, &error);
        CHECK(status != STELA_INTEL_GRAPHICS_OK && error.status == status && !output &&
            *v == vertex && *f == fragment);
    }
    CHECK(!output && *v == vertex && *f == fragment);
}

static bool validate_span(const struct brw_compiler *brw, const struct elk_compiler *elk,
    void *context, const void *code, unsigned bytes, unsigned alignment)
{
    return elk ? stela_intel_graphics_validate_elk(elk, code, bytes, alignment) :
                 stela_intel_graphics_validate_brw(brw->devinfo, context, code, bytes, alignment) ==
            STELA_INTEL_GRAPHICS_OK;
}
static void whole_span(const struct brw_compiler *brw, const struct elk_compiler *elk,
    const struct stela_intel_graphics_compilation *owner)
{
    const struct stela_intel_graphics_stage_binary *vertex = stela_intel_graphics_binary(owner,
        STELA_AIR_VERTEX);
    unsigned size = vertex->executable_bytes;
    CHECK(size && size == vertex->code_bytes && !(size & 15) && size <= (UINT32_MAX - 128) / 2);
    void *context = ralloc_context(NULL); CHECK(context);
    uint8_t *bytes = malloc(2 * size + 128); CHECK(bytes);
    /* Consumer span witnesses, not a claim that concatenating kernels creates
     * an original compiled CFG. Both complete original instruction sequences
     * contain their own EOT: validating the second sequence must not stop at
     * the first one's EOT. An illegal zero instruction in between must fail.
     */
    memcpy(bytes,vertex->code,size); memcpy(bytes+size,vertex->code,size);
    CHECK(validate_span(brw,elk,context,bytes,2*size,16));
    memset(bytes+size,0,16); memcpy(bytes+size+16,vertex->code,size);
    CHECK(!validate_span(brw,elk,context,bytes,2*size+16,16));
    /* Exact original zero-filled alignment is admitted, arbitrary zero extent
     * and nonzero trailing storage are not reclassified as padding. */
    unsigned aligned = (size + 63) & ~63u;
    memcpy(bytes,vertex->code,size); memset(bytes+size,0,128);
    CHECK(validate_span(brw,elk,context,bytes,aligned,64));
    CHECK(!validate_span(brw,elk,context,bytes,aligned+64,64));
    if (aligned != size) {
        bytes[aligned-1] = 1;
        CHECK(!validate_span(brw,elk,context,bytes,aligned,64));
    }
    CHECK(!validate_span(brw,elk,context,bytes,size-1,16));
    CHECK(!validate_span(brw,elk,context,bytes,size,8));
    free(bytes); ralloc_free(context);
}

static void target(const struct bytes *raw, const char *vs, const char *fs, const char *name,
    const struct intel_device_info *model, const char *directory)
{
    const struct intel_device_info device = *model; const bool legacy = stela_intel_elk(&device);
    void *context = ralloc_context(NULL); CHECK(context);
    struct brw_compiler *brw = legacy ? NULL : brw_compiler_create(context,&device);
    struct elk_compiler *elk = legacy ? elk_compiler_create(context,&device) : NULL;
    CHECK(brw || elk);
    if (brw) brw->shader_debug_log = brw->shader_perf_log = compiler_log;
    else elk->shader_debug_log = elk->shader_perf_log = compiler_log;
    struct stela_metal_assembly *v = stage(raw, vs, STELA_AIR_VERTEX),
                                *f = stage(raw, fs, STELA_AIR_FRAGMENT);
    struct stela_intel_graphics_compilation *output = NULL;
    struct stela_intel_graphics_options o = options(); struct stela_intel_graphics_error error;
    if (stela_intel_hold(&device)) {
        CHECK(stela_intel_graphics_compile(brw, elk, NULL, &v, &f, &o, &output, &error) ==
            STELA_INTEL_GRAPHICS_UNSUPPORTED);
        CHECK(v && f && !output);
        stela_metal_assembly_destroy(&v);
        stela_metal_assembly_destroy(&f);
        ralloc_free(context);
        record_held(name,stela_intel_hold(&device)); return;
    }
    failures(brw,elk,&v,&f);
#ifdef STELA_INTEL_GRAPHICS_ALLOCATION_TEST
    bool success = false;
    for (unsigned n = 1; n <= 32; n++) {
        allocations = 0; fail_allocation = n;
        enum stela_intel_graphics_status status = stela_intel_graphics_compile(brw, elk, NULL, &v,
            &f, &o, &output, &error);
        if (!status) { success = true; break; }
        CHECK(v && f && !output && !live_allocations && !live_contexts);
    }
    fail_allocation = 0; CHECK(success);
#else
    CHECK(stela_intel_graphics_compile(brw, elk, NULL, &v, &f, &o, &output, &error) ==
        STELA_INTEL_GRAPHICS_OK);
#endif
    CHECK(output && !v && !f);
    const struct stela_intel_graphics_provenance *p = stela_intel_graphics_provenance(output);
    CHECK(p && p->vertex->reflection->stage == STELA_AIR_VERTEX &&
        p->fragment->reflection->stage == STELA_AIR_FRAGMENT);
    CHECK(!p->vertex->provenance->entries && !p->fragment->provenance->entries);
    CHECK(memcmp(p->vertex->provenance->input.original_sha256,
        p->fragment->provenance->input.original_sha256, 32));
    CHECK(!memcmp(p->vertex->identity->air_sha256,p->fragment->identity->air_sha256,32));
    compare(output,directory,name);
    whole_span(brw,elk,output);
    for (unsigned i = 0; i < 2; i++) {
        uint32_t count; enum stela_air_stage role = i ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX;
        const struct stela_intel_graphics_binding *bindings = stela_intel_graphics_bindings(output,
            role, &count);
        CHECK(bindings && count == (i ? 0u : 2u));
        for (unsigned j = 0; j < count; j++)
            CHECK(bindings[j].used && bindings[j].table_entry &&
                bindings[j].buffer.access == STELA_AIR_READ &&
                bindings[j].buffer.address_space == 2 && bindings[j].bti == j);
        CHECK(stela_intel_graphics_nir(output,role));
    }
    /* Original compiler context/options/callback payload no longer own the
     * result's bytes, metadata, NIR options or canonical input identities. */
    ralloc_free(context); compare(output,directory,name);
    CHECK(!strcmp((const char *)p->vertex->identity->name, vs) &&
        !strcmp((const char *)p->fragment->identity->name, fs));
    /* The package equals the render probe's original code, metadata and
     * identities after its compiler is gone. */
    const struct stela_intel_graphics_stage_binary *vertex = stela_intel_graphics_binary(output,
        STELA_AIR_VERTEX);
    const struct stela_intel_graphics_stage_binary *fragment = stela_intel_graphics_binary(output,
        STELA_AIR_FRAGMENT);
    record_compiled(name,(uint64_t)vertex->code_bytes + fragment->code_bytes);
    record_object("facts");
    record_str("backend",legacy ? "elk" : "brw");
    record_uint("vertex_code_bytes",vertex->code_bytes);
    record_uint("fragment_code_bytes",fragment->code_bytes);
    record_end();
    stela_intel_graphics_destroy(&output); CHECK(!output && !live_allocations && !live_contexts);
    stela_intel_graphics_destroy(&output);
}
static void permutation_stage_options_tests(void)
{
    LLVMMemoryBufferRef bitcode = stela_air_test_custom_bitcode("",
        stela_air_permutation_stage_fixture, "", "");
    struct bytes raw = {.data = (uint8_t *)LLVMGetBufferStart(bitcode),
                        .size = LLVMGetBufferSize(bitcode)};
    const char *platforms[] = {"bdw", "skl"};
    for (unsigned target_index = 0; target_index < ARRAY_SIZE(platforms); target_index++) {
        const char *platform = platforms[target_index];
        struct intel_device_info device;
        int pci = intel_device_name_to_pci_device_id(platform);
        CHECK(pci >= 0 && intel_get_device_info_for_build(pci, &device));
        bool legacy = stela_intel_elk(&device);
        void *context = ralloc_context(NULL); CHECK(context);
        struct brw_compiler *brw = legacy ? NULL : brw_compiler_create(context, &device);
        struct elk_compiler *elk = legacy ? elk_compiler_create(context, &device) : NULL;
        CHECK(brw || elk);
        if (brw) brw->shader_debug_log = brw->shader_perf_log = compiler_log;
        else elk->shader_debug_log = elk->shader_perf_log = compiler_log;
        const nir_shader_compiler_options *original[2];
        uint64_t original_mask[2];
        for (unsigned i = 0; i < 2; i++) {
            mesa_shader_stage role = i ? MESA_SHADER_FRAGMENT : MESA_SHADER_VERTEX;
            original[i] = brw ? &brw->nir_options[role] : elk->nir_options[role];
            original_mask[i] = original[i]->lower_int64_options;
        }
        struct stela_metal_assembly *vertex = stage(&raw, "permutation_vertex", STELA_AIR_VERTEX);
        struct stela_metal_assembly *fragment = stage(&raw, "permutation_fragment", STELA_AIR_FRAGMENT);
        struct stela_intel_graphics_compilation *output = NULL;
        struct stela_intel_graphics_options opts = options();
        opts.vertex_fp_profile = opts.fragment_fp_profile = STELA_AIR_FP_IEEE_DEFAULT;
        struct stela_intel_graphics_error error;
#ifdef STELA_INTEL_GRAPHICS_ALLOCATION_TEST
        bool success = false;
        for (unsigned n = 1; n <= 32; n++) {
            allocations = 0; fail_allocation = n;
            enum stela_intel_graphics_status status = stela_intel_graphics_compile(brw, elk, NULL,
                &vertex, &fragment, &opts, &output, &error);
            if (!status) { success = true; break; }
            CHECK(vertex && fragment && !output && !live_allocations && !live_contexts);
        }
        fail_allocation = 0; CHECK(success);
#else
        enum stela_intel_graphics_status status = stela_intel_graphics_compile(brw, elk, NULL,
            &vertex, &fragment, &opts, &output, &error);
        if (status) fprintf(stderr, "permutation stages %s status%u: %s AIR%u %s\n",
            platform, status, error.detail, error.air.kind, error.air.detail);
        CHECK(status == STELA_INTEL_GRAPHICS_OK);
#endif
        CHECK(output && !vertex && !fragment);
        for (unsigned i = 0; i < 2; i++) {
            const nir_shader *actual = stela_intel_graphics_nir(output,
                i ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX);
            CHECK(actual && actual->options != original[i] &&
                actual->options->lower_int64_options == (original_mask[i] |
                    (elk ? nir_lower_bitfield_reverse64 : 0)));
            CHECK(original[i]->lower_int64_options == original_mask[i]);
            if (elk) {
                unsigned reversals = 0;
                nir_foreach_function_impl(impl, (nir_shader *)actual) {
                    nir_foreach_block(block, impl) {
                        nir_foreach_instr(instr, block) {
                            if (instr->type == nir_instr_type_alu &&
                                nir_instr_as_alu(instr)->op == nir_op_bitfield_reverse) {
                                CHECK(nir_instr_as_alu(instr)->def.bit_size == 32);
                                reversals++;
                            }
                        }
                    }
                }
                CHECK(reversals); /* Actual owner after the real ELK postprocess. */
            }
        }
        whole_span(brw, elk, output); /* Actual complete compiled ISA. */
        const struct stela_intel_graphics_stage_binary *vs = stela_intel_graphics_binary(output, STELA_AIR_VERTEX);
        const struct stela_intel_graphics_stage_binary *fs = stela_intel_graphics_binary(output, STELA_AIR_FRAGMENT);
        CHECK(vs && fs && vs->code_bytes && fs->code_bytes);
        char target[64]; snprintf(target, sizeof(target), "integer-permutation-graphics/%s", platform);
        record_expect(target, NULL);
        record_compiled(target, (uint64_t)vs->code_bytes + fs->code_bytes);
        ralloc_free(context);
        for (unsigned i = 0; i < 2; i++) {
            const nir_shader *actual = stela_intel_graphics_nir(output,
                i ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX);
            CHECK(actual->options->lower_int64_options == (original_mask[i] |
                (legacy ? nir_lower_bitfield_reverse64 : 0)));
        }
        stela_intel_graphics_destroy(&output);
        CHECK(!output && !live_allocations && !live_contexts);
    }
    LLVMDisposeMemoryBuffer(bitcode);
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--permutation")) {
        process_intel_debug_variable(); glsl_type_singleton_init_or_ref();
        permutation_stage_options_tests();
        glsl_type_singleton_decref();
        return 0;
    }
    CHECK(argc == 5); /* Actual rawAIR,VSentry,FSentry, immutable original05c output directory. */
    FILE *file = fopen(argv[1],"rb"); CHECK(file && !fseek(file,0,SEEK_END));
    long size = ftell(file);
    CHECK(size >= 4 && size <= AIR_MAX_BITCODE_BYTES && !fseek(file, 0, SEEK_SET));
    struct bytes raw = {.data = malloc((size_t)size), .size = (size_t)size}; CHECK(raw.data);
    CHECK(fread(raw.data,1,raw.size,file) == raw.size && !fclose(file));
    process_intel_debug_variable(); glsl_type_singleton_init_or_ref();
    struct intel_device_info device; const char *platform;
    STELA_INTEL_FOREACH_TARGET(platform,device) record_expect(platform,stela_intel_hold(&device));
    STELA_INTEL_FOREACH_TARGET(platform, device)
    target(&raw, argv[2], argv[3], platform, &device, argv[4]);
    glsl_type_singleton_decref(); free(raw.data); return 0;
}
