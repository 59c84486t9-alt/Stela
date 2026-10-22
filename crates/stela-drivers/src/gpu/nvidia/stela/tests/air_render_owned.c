/* SPDX-License-Identifier: MIT */
#include "nouveau/compiler/nak_shader_layout.h"
#include "nouveau/compiler/nak_nir_lower_constant.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonDigest.h>
#include "util/mesa-blake3.h"
#include "stela/air_test_fixture.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

#ifdef STELA_NV_RENDER_ALLOC_TEST
static size_t allocation_attempts, fail_allocation, live_allocations;
static void *owner_calloc(size_t count, size_t bytes)
{
    if (++allocation_attempts == fail_allocation) return NULL;
    void *result = calloc(count, bytes);
    if (result) ++live_allocations;
    return result;
}
static void owner_free(void *pointer)
{
    if (pointer) { CHECK(live_allocations); --live_allocations; }
    free(pointer);
}
#define calloc owner_calloc
#define free owner_free
#endif
/* Actual production TU, not an exported raw-NIR or fault-injection API. This
 * permits original synthetic NIR to qualify private CPU image formation. */
#include "../hosted/render_compile.c"
#ifdef STELA_NV_RENDER_ALLOC_TEST
#undef calloc
#undef free
#endif

/* Expected byte boundaries are independent of the helper's running-size
 * implementation. Fermi graphics is not an admitted render target: its
 * historical NVK helper asserts when asked for an aligned code offset. We
 * still preserve and qualify its size/header/alignment branch with that
 * optional output omitted. No unchecked helper is fed overflowing input. */
static void layout_tests(void)
{
    static const uint16_t classes[] = {0, KEPLER_A - 1, KEPLER_A,
        TURING_A - 1, TURING_A, 0xc797, 0xcd97, UINT16_MAX};
    static const uint32_t code_sizes[] = {0, 1, 63, 64, 127, 128, 257, 4096,
        UINT32_MAX - 1024};
    unsigned cases = 0;
    for (unsigned c = 0; c < ARRAY_SIZE(classes); ++c) {
        const struct nv_device_info dev = {.cls_eng3d = classes[c]};
        const bool old_header = classes[c] < TURING_A;
        const uint32_t cbuf_align = old_header ? 256u : 64u;
        const uint32_t instruction_align = classes[c] < KEPLER_A ? 64u : 128u;
        CHECK(nak_min_cbuf_alignment(&dev) == cbuf_align);
        CHECK(nak_shader_get_shader_alignment(&dev) == instruction_align);
        for (unsigned stage = MESA_SHADER_VERTEX; stage <= MESA_SHADER_MESH; ++stage) {
            for (unsigned mesh_header = 0; mesh_header < 2; ++mesh_header) {
                struct nak_shader_info info = {.stage = (mesa_shader_stage)stage};
                if (stage == MESA_SHADER_MESH) info.mesh.has_gs_sph = mesh_header != 0;
                const bool compute = stage == MESA_SHADER_COMPUTE;
                const uint32_t header_bytes = compute ? 0u : old_header ? 80u : 128u;
                const uint32_t prefix = !compute && classes[c] >= KEPLER_A && old_header ? 48u : 0u;
                CHECK(nak_shader_get_hdr_size(&dev, &info) == header_bytes);
                for (unsigned code = 0; code < ARRAY_SIZE(code_sizes); ++code) {
                    const uint32_t code_offset_expected = prefix + header_bytes;
                    const uint32_t code_end = code_offset_expected + code_sizes[code];
                    uint32_t expected_gs = 0, expected_size = code_end;
                    if (stage == MESA_SHADER_MESH && mesh_header) {
                        expected_gs = (code_end + cbuf_align - 1u) & ~(cbuf_align - 1u);
                        expected_size = expected_gs + header_bytes;
                    }
                    uint32_t hdr = UINT32_MAX, code_offset = UINT32_MAX, gs = UINT32_MAX;
                    const bool request_code = compute || classes[c] >= KEPLER_A;
                    const uint32_t size = nak_shader_get_shader_size(&dev, &info,
                        code_sizes[code], &hdr, request_code ? &code_offset : NULL, &gs);
                    CHECK(size == expected_size && hdr == prefix && gs == expected_gs);
                    if (request_code) CHECK(code_offset == code_offset_expected && code_offset % instruction_align == 0);
                    CHECK(nak_shader_get_shader_size(&dev, &info, code_sizes[code], NULL, NULL, NULL) == size);
                    ++cases;
                }
            }
        }
    }
    printf("layout_cases=%u\n", cases);
}

static bool lower_constant(nir_builder *b, nir_intrinsic_instr *load, void *data)
{
    if (load->intrinsic != nir_intrinsic_load_constant) return false;
    return nak_nir_lower_load_constant(b, load, *(const uint32_t *)data);
}

static void constant_tests(void)
{
    glsl_type_singleton_init_or_ref();
    const nir_shader_compiler_options options = {0};
    unsigned cases = 0;
    for (unsigned bits = 8; bits <= 64; bits *= 2) {
        for (unsigned components = 1; components <= 4; ++components) {
            for (unsigned dynamic = 0; dynamic < 2; ++dynamic) {
                nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_VERTEX, &options,
                    "original constant-data lowering");
                b.shader->constant_data_size = 128;
                b.shader->constant_data = ralloc_size(b.shader, 128);
                CHECK(b.shader->constant_data);
                for (unsigned byte = 0; byte < 128; ++byte)
                    ((uint8_t *)b.shader->constant_data)[byte] = (uint8_t)byte;
                nir_def *offset = dynamic ? nir_iand_imm(&b, nir_load_vertex_id(&b), 3) : nir_imm_int(&b, 4);
                nir_def *load = nir_load_constant(&b, components, bits, offset,
                    .base = 8, .range = 64, .align_mul = dynamic ? 1 : 4, .align_offset = 0);
                const glsl_type *type = glsl_vector_type(glsl_get_base_type(glsl_uintN_t_type(bits)), components);
                nir_variable *local = nir_local_variable_create(b.impl, type, "keep load result");
                nir_store_var(&b, local, load, BITFIELD_MASK(components));
                nir_validate_shader(b.shader, "before original constant-data lowering");
                const uint32_t cbuf = components;
                CHECK(nir_shader_intrinsics_pass(b.shader, lower_constant, nir_metadata_none, (void *)&cbuf));
                unsigned ldc = 0;
                nir_foreach_block(block, b.impl) nir_foreach_instr(instr, block) {
                    if (instr->type != nir_instr_type_intrinsic) continue;
                    nir_intrinsic_instr *intrin = nir_instr_as_intrinsic(instr);
                    if (intrin->intrinsic != nir_intrinsic_ldc_nv) continue;
                    ++ldc;
                    CHECK(intrin->def.num_components == components && intrin->def.bit_size == bits);
                    CHECK(nir_src_is_const(intrin->src[0]) && nir_src_as_uint(intrin->src[0]) == cbuf);
                    CHECK(nir_intrinsic_align_mul(intrin) == (dynamic ? 1u : 4u));
                    CHECK(nir_intrinsic_align_offset(intrin) == 0 && nir_intrinsic_base(intrin) == 0);
                    CHECK(!nir_def_is_unused(&intrin->def));
                    nir_alu_instr *sum = nir_instr_as_alu(nir_def_instr(intrin->src[1].ssa));
                    CHECK(sum->op == nir_op_iadd && sum->src[0].src.ssa == offset);
                    CHECK(nir_src_is_const(sum->src[1].src) && nir_src_as_uint(sum->src[1].src) == 8);
                }
                CHECK(ldc == 1);
                nir_validate_shader(b.shader, "after original constant-data lowering");
                ralloc_free(b.shader);
                ++cases;
            }
        }
    }
    glsl_type_singleton_decref();
    printf("constant_cases=%u\n", cases);
}
static void constant_image_tests(void)
{
    glsl_type_singleton_init_or_ref();
    static const struct { uint8_t sm, warps; uint16_t cls; } targets[] = {
        {30, 64, KEPLER_A}, {70, 64, 0xc397}, {75, 32, TURING_A},
    };
    unsigned cases = 0;
    for (unsigned t = 0; t < ARRAY_SIZE(targets); ++t) for (unsigned dynamic = 0; dynamic < 2; ++dynamic) {
        const struct nv_device_info device = {.sm = targets[t].sm, .max_warps_per_mp = targets[t].warps,
            .cls_eng3d = targets[t].cls};
        const struct nak_constant_offset_info layout = {.sample_info_cb = 0,
            .sample_locations_offset = 0, .sample_masks_offset = 256, .printf_cb = 1};
        struct nak_compiler *compiler = nak_compiler_create(&device, &layout, &layout); CHECK(compiler);
        nir_shader_compiler_options options = *nak_nir_options(compiler); CHECK(!options.cb_data);
        nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_VERTEX, &options, "original constant upload");
        b.shader->constant_data_size = 115;
        b.shader->constant_data = ralloc_size(b.shader, 115); CHECK(b.shader->constant_data);
        for (unsigned byte = 0; byte < 115; ++byte)
            ((uint8_t *)b.shader->constant_data)[byte] = (uint8_t)(0x13u + 17u * byte);
        nir_def *offset = dynamic ? nir_ishl_imm(&b, nir_iand_imm(&b, nir_load_vertex_id(&b), 3), 2) : nir_imm_int(&b, 4);
        nir_def *value = nir_load_constant(&b, 4, 32, offset, .base = 8, .range = 64, .align_mul = 4);
        nir_def *lanes[4];
        for (unsigned c = 0; c < 4; ++c) lanes[c] = nir_u2f32(&b, nir_channel(&b, value, c));
        nir_variable *position = nir_variable_create(b.shader, nir_var_shader_out, glsl_vec4_type(), "position");
        position->data.location = VARYING_SLOT_POS;
        nir_store_var(&b, position, nir_vec(&b, lanes, 4), 0xf);
        nir_shader_gather_info(b.shader, b.impl);
        nak_preprocess_nir(b.shader, compiler);
        struct render_stage stage = {.nir = b.shader};
        const struct lower_context lower = {.stage = &stage, .table_cbuf = 2, .data_cbuf = 3};
        CHECK(validate_resources(&stage, false, false, &lower));
        nir_shader_intrinsics_pass(b.shader, lower_resource, nir_metadata_none, (void *)&lower);
        CHECK(validate_resources(&stage, true, false, &lower));
        stage.bin = nak_compile_shader(b.shader, true, compiler, 0, NULL, false);
        CHECK(stage.bin && stage.bin->code && stage.bin->code_size && stage.bin->asm_str);
        CHECK(validate_resources(&stage, true, true, &lower));
        CHECK(make_upload(&stage, &device, 3, 65536) == STELA_NV_RENDER_OK);
        const struct stela_nv_render_upload *image = &stage.upload;
        const uint32_t header = t == 2 ? 128u : 80u, prefix = t == 2 ? 0u : 48u;
        const uint32_t alignment = t == 2 ? 64u : 256u;
        /* Original preprocess folds a fully direct constant load and drops
         * its now-unused data. Dynamic offsets retain the genuine data span. */
        const uint32_t logical_bytes = b.shader->constant_data_size;
        CHECK(logical_bytes == (dynamic ? 115u : 0u));
        const uint32_t data_offset = logical_bytes ? (128u + stage.bin->code_size + alignment - 1u) & ~(alignment - 1u) : 0;
        const uint32_t data_size = logical_bytes ? (t == 2 ? 128u : 256u) : 0;
        const uint32_t image_size = logical_bytes ? data_offset + data_size : 128u + stage.bin->code_size;
        CHECK(image->header_offset == prefix && image->header_size == header && image->code_offset == 128);
        CHECK(image->data_offset == data_offset && image->data_size == data_size && image->size == image_size);
        CHECK(image->alignment == (logical_bytes && t != 2 ? 256u : 128u));
        for (uint32_t byte = 0; byte < image->size; ++byte) {
            uint8_t expected = 0;
            if (byte >= prefix && byte - prefix < header) expected = ((const uint8_t *)stage.bin->info.hdr)[byte - prefix];
            else if (byte >= 128 && byte - 128 < stage.bin->code_size) expected = ((const uint8_t *)stage.bin->code)[byte - 128];
            else if (logical_bytes && byte >= data_offset && byte - data_offset < logical_bytes) expected = ((const uint8_t *)b.shader->constant_data)[byte - data_offset];
            CHECK(((const uint8_t *)image->bytes)[byte] == expected);
        }
#ifdef STELA_NV_RENDER_ALLOC_TEST
        owner_free((void *)stage.upload.bytes);
#else
        free((void *)stage.upload.bytes);
#endif
        stage.upload = (struct stela_nv_render_upload){0};
        if (logical_bytes) CHECK(make_upload(&stage, &device, 3, 114) == STELA_NV_RENDER_LIMIT && !stage.upload.bytes);
        /* Invalid metadata is a CPU bounds refusal, not a fabricated valid bin. */
        struct nak_shader_bin *actual = stage.bin;
        struct nak_shader_bin overflow = *actual; overflow.code_size = UINT32_MAX;
        stage.bin = &overflow;
        CHECK(make_upload(&stage, &device, 3, 65536) == STELA_NV_RENDER_LIMIT && !stage.upload.bytes);
        stage.bin = actual;
#ifdef STELA_NV_RENDER_ALLOC_TEST
        allocation_attempts = 0; fail_allocation = 1;
        CHECK(make_upload(&stage, &device, 3, 65536) == STELA_NV_RENDER_ALLOCATION && !stage.upload.bytes);
        CHECK(allocation_attempts == 1 && !live_allocations); fail_allocation = 0;
#endif
        nak_shader_bin_destroy(stage.bin); ralloc_free(b.shader); nak_compiler_destroy(compiler);
        ++cases;
    }
    glsl_type_singleton_decref();
    printf("original_constant_images=%u\n", cases);
}

struct bytes { uint8_t *data; size_t count; };
static void append(struct bytes *bytes, const void *data, size_t count)
{
    CHECK(count <= SIZE_MAX - bytes->count);
    bytes->data = realloc(bytes->data, bytes->count + count); CHECK(bytes->data);
    memcpy(bytes->data + bytes->count, data, count); bytes->count += count;
}
static void little(void *data, uint64_t value, unsigned bytes)
{ for (unsigned i = 0; i < bytes; ++i) ((uint8_t *)data)[i] = (uint8_t)(value >> (8 * i)); }
static void tag(struct bytes *bytes, const char *name, const void *data, size_t count)
{
    CHECK(count <= UINT16_MAX); uint8_t length[2]; little(length, count, 2);
    append(bytes, name, 4); append(bytes, length, 2); append(bytes, data, count);
}
/* The existing one-entry framing fixture, with true TYPE0/1, not a parser or
 * source-compiler authentication. Canonical Rust validates all extents/hashes;
 * canonical LLVM selected-stage admission validates original names/reflection. */
static struct bytes archive(const void *air, size_t size, const char *name, uint8_t kind)
{
    struct bytes record = {0}; uint8_t prefix[4] = {0}, hash[32];
    CHECK(size <= AIR_MAX_BITCODE_BYTES); CC_SHA256(air, (CC_LONG)size, hash);
    append(&record, prefix, 4); tag(&record, "NAME", name, strlen(name) + 1);
    tag(&record, "TYPE", &kind, 1); tag(&record, "HASH", hash, 32);
    uint8_t length[8], offsets[24] = {0}, versions[8]; little(length, size, 8);
    tag(&record, "MDSZ", length, 8); tag(&record, "OFFT", offsets, 24);
    little(versions, 2, 2); little(versions + 2, 9, 2);
    little(versions + 4, 4, 2); little(versions + 6, 1, 2);
    tag(&record, "VERS", versions, 8); append(&record, "ENDT", 4); little(record.data, record.count, 4);
    uint8_t header[88] = {0}; memcpy(header, "MTLB", 4);
    little(header + 4, 0x8001, 2); little(header + 6, 2, 2); little(header + 8, 9, 2);
    header[11] = 0x81; little(header + 12, 27, 2); little(header + 14, 2, 2);
    size_t start = 92 + record.count;
    little(header + 16, start + size, 8); little(header + 24, 88, 8); little(header + 32, record.count, 8);
    little(header + 40, start, 8); little(header + 56, start, 8);
    little(header + 72, start, 8); little(header + 80, size, 8);
    struct bytes result = {0}; append(&result, header, sizeof(header));
    little(prefix, 1, 4); append(&result, prefix, 4); append(&result, record.data, record.count);
    append(&result, air, size); free(record.data); return result;
}
static void assemble_pair(const struct bytes input[2], struct stela_metal_assembly *sources[2])
{
    struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
    for (unsigned s = 0; s < 2; ++s) {
        sources[s] = NULL; struct stela_metal_assembly_error error;
        enum stela_metal_assembly_status status = stela_metal_assemble_selected_stage_archive(&options,
            input[s].data, input[s].count, 0, s ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX, &sources[s], &error);
        if (status) fprintf(stderr, "canonical stage%u: %u %s\n", s, status, error.detail);
        CHECK(status == STELA_METAL_ASSEMBLY_OK && sources[s]);
        CHECK(!stela_metal_assembly_manifest(sources[s]));
    }
}
static void digest(const void *data, size_t size)
{
    blake3_hash hash; _mesa_blake3_compute(data, size, hash);
    for (unsigned i = 0; i < sizeof(hash); ++i) printf("%02x", hash[i]);
}
static void artifact(const char *directory, unsigned sm, unsigned samples, const char *stage,
    const char *suffix, const void *data, size_t bytes)
{
    if (!directory) return;
    char path[1024]; int count = snprintf(path, sizeof(path), "%s/sm%u-samples%u-%s.%s", directory, sm, samples, stage, suffix);
    CHECK(count > 0 && (size_t)count < sizeof(path));
    FILE *file = fopen(path, "wb"); CHECK(file);
    CHECK(fwrite(data, 1, bytes, file) == bytes && !fclose(file));
}
static struct stela_nv_render_options render_options(unsigned samples)
{
    return (struct stela_nv_render_options){.size = sizeof(struct stela_nv_render_options),
        .abi = STELA_NV_RENDER_ABI, .max_instructions = 10000, .max_code_bytes = 1024 * 1024,
        .max_constant_bytes = 65536, .max_varying_slots = 32, .argument_cbuf = {2, 2},
        .constant_data_cbuf = {3, 3}, .record_assembly = 1,
        .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41,
        .fs_key = {.force_sample_shading = samples > 1}, .raster_samples = samples,
        .sample_shading_enable = samples > 1, .min_sample_shading = samples > 1 ? 1.0f : 0.0f};
}
/* Reused original authored LLVM fixture from the shared stage validator. It is
 * not Apple compiler output and its consistency llvm.ident is no provenance. */
static const char stage_fixture[] =
 "target datalayout = \"e-p:64:64-i32:32-i64:64-f32:32-v128:128-n8:16:32\"\n"
 "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
 "%Input = type { <4 x float> }\n"
 "define <{<4 x float>,<4 x float>}> @test_vertex(i32 %id, ptr addrspace(2) %buffer) {\n"
 " %index = zext i32 %id to i64\n"
 " %p = getelementptr %Input, ptr addrspace(2) %buffer, i64 %index, i32 0\n"
 " %position = load <4 x float>, ptr addrspace(2) %p, align 16\n"
 " %a = insertvalue <{<4 x float>,<4 x float>}> undef, <4 x float> %position, 0\n"
 " %b = insertvalue <{<4 x float>,<4 x float>}> %a, <4 x float> <float 1.0,float 0.5,float 0.25,float 0.0>, 1\n"
 " ret <{<4 x float>,<4 x float>}> %b\n}\n"
 "define <4 x float> @test_fragment(<4 x float> %position, <4 x float> %color) { ret <4 x float> %color }\n"
 "!air.vertex = !{!0}\n!air.fragment = !{!10}\n"
 "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
 "!air.compile_options = !{!23,!24,!25}\n"
 "!0 = !{ptr @test_vertex,!1,!4}\n!1 = !{!2,!3}\n"
 "!2 = !{!\"air.position\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"pos\"}\n"
 "!3 = !{!\"air.vertex_output\",!\"test.opaque.link\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"colour\"}\n"
 "!4 = !{!5,!6}\n!5 = !{i32 0,!\"air.vertex_id\",!\"air.arg_type_name\",!\"uint\",!\"air.arg_name\",!\"id\"}\n"
 "!6 = !{i32 1,!\"air.buffer\",!\"air.location_index\",i32 0,i32 1,!\"air.read\",!\"air.address_space\",i32 2,"
 "!\"air.struct_type_info\",!7,!\"air.arg_type_size\",i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"Input\",!\"air.arg_name\",!\"vertices\"}\n"
 "!7 = !{i32 0,i32 16,i32 0,!\"float4\",!\"position\"}\n"
 "!10 = !{ptr @test_fragment,!11,!13}\n!11 = !{!12}\n!12 = !{!\"air.render_target\",i32 0,i32 0,!\"air.arg_type_name\",!\"float4\"}\n"
 "!13 = !{!14,!15}\n"
 "!14 = !{i32 0,!\"air.position\",!\"air.center\",!\"air.no_perspective\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"position\",!\"air.arg_unused\"}\n"
 "!15 = !{i32 1,!\"air.fragment_input\",!\"test.opaque.link\",!\"air.center\",!\"air.perspective\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"color\"}\n"
 "!20 = !{i32 2,i32 9,i32 0}\n!21 = !{!\"Metal\",i32 4,i32 1,i32 0}\n"
 "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
 "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";
static char *replace_text(const char *source, const char *old, const char *replacement)
{
    const char *at = strstr(source, old); CHECK(at);
    size_t prefix = (size_t)(at - source), tail = strlen(at + strlen(old));
    char *result = malloc(prefix + strlen(replacement) + tail + 1); CHECK(result);
    memcpy(result, source, prefix); memcpy(result + prefix, replacement, strlen(replacement));
    memcpy(result + prefix + strlen(replacement), at + strlen(old), tail + 1); return result;
}
static void unused_owner_tests(void)
{
    for (unsigned all_unused = 0; all_unused < 2; ++all_unused) {
        char *a = replace_text(stage_fixture, "ptr addrspace(2) %buffer) {",
            "ptr addrspace(2) %buffer, ptr addrspace(2) %unused) {");
        char *b = replace_text(a, "!4 = !{!5,!6}", "!4 = !{!5,!6,!8}"); free(a); a = b;
        if (all_unused) {
            b = replace_text(a, " %p = getelementptr %Input, ptr addrspace(2) %buffer, i64 %index, i32 0\n %position = load <4 x float>, ptr addrspace(2) %p, align 16",
                " %position = fadd <4 x float> zeroinitializer, zeroinitializer"); free(a); a = b;
        }
        const char *extra = "\n!8 = !{i32 2,!\"air.buffer\",!\"air.location_index\",i32 7,i32 1,!\"air.read\",!\"air.address_space\",i32 2,!\"air.arg_type_size\",i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"unused\"}\n";
        LLVMMemoryBufferRef module = stela_air_test_custom_bitcode(a, "", "", extra); free(a);
        const void *raw = LLVMGetBufferStart(module); size_t raw_size = LLVMGetBufferSize(module);
        struct bytes input[2] = {archive(raw, raw_size, "test_vertex", 0), archive(raw, raw_size, "test_fragment", 1)};
        LLVMDisposeMemoryBuffer(module);
        struct stela_metal_assembly *sources[2]; assemble_pair(input, sources);
        const struct nv_device_info device = {.sm = 75, .max_warps_per_mp = 32, .cls_eng3d = TURING_A};
        const struct nak_constant_offset_info layout = {.sample_info_cb = 0, .sample_masks_offset = 256, .printf_cb = 1};
        struct nak_compiler *compiler = nak_compiler_create(&device, &layout, &layout); CHECK(compiler);
        struct stela_nv_render_options options = render_options(1);
        struct stela_nv_render_compilation *result = NULL; struct stela_nv_render_error error;
        enum stela_nv_render_status status = stela_nv_render_compile(&device, compiler, &sources[0], &sources[1], &options, &result, &error);
        if (status) fprintf(stderr, "unused stage: %u %s\n", status, error.detail);
        CHECK(!status && result && !sources[0] && !sources[1]);
        const struct stela_metal_stage_view *source = stela_nv_render_source(result, STELA_AIR_VERTEX);
        CHECK(source->reflection->input_count == 3 && !source->reflection->inputs[2].used);
        uint32_t count, bytes; stela_nv_render_bindings(result, STELA_AIR_VERTEX, &count, &bytes);
        CHECK(count == (all_unused ? 0u : 1u) && bytes == (all_unused ? 0u : 64u));
        stela_nv_render_bindings(result, STELA_AIR_FRAGMENT, &count, &bytes); CHECK(!count && !bytes);
        if (all_unused) CHECK(!stela_nv_render_pack_arguments(result, STELA_AIR_VERTEX, &device, 49, NULL, 0, NULL, 0));
        stela_nv_render_destroy(&result); nak_compiler_destroy(compiler);
        for (unsigned i = 0; i < 2; ++i) free(input[i].data);
#ifdef STELA_NV_RENDER_ALLOC_TEST
        CHECK(!live_allocations);
#endif
    }
    puts("canonical_unused_stage_cases=2");
}

static void expect_failure(const struct nv_device_info *device, struct nak_compiler *compiler,
    struct stela_metal_assembly *sources[2], const struct stela_nv_render_options *options,
    enum stela_nv_render_status expected)
{
    struct stela_metal_assembly *before[2] = {sources[0], sources[1]};
    struct stela_nv_render_compilation *result = NULL; struct stela_nv_render_error error;
    enum stela_nv_render_status status = stela_nv_render_compile(device, compiler,
        &sources[0], &sources[1], options, &result, &error);
    if (status != expected) fprintf(stderr, "expected %u got %u: %s\n", expected, status, error.detail);
    CHECK(status == expected && !result && sources[0] == before[0] && sources[1] == before[1]);
}
static void refusals(const struct nv_device_info *device, struct nak_compiler *compiler,
    struct stela_metal_assembly *sources[2], const struct stela_nv_render_options *options)
{
    struct stela_nv_render_options bad = *options;
    bad.argument_cbuf[0] = compiler->const_offsets_base.sample_info_cb;
    expect_failure(device, compiler, sources, &bad, STELA_NV_RENDER_UNSUPPORTED);
    bad = *options; bad.fs_key.force_sample_shading = !bad.fs_key.force_sample_shading;
    expect_failure(device, compiler, sources, &bad, STELA_NV_RENDER_UNSUPPORTED);
    bad = *options; bad.max_varying_slots = 0;
    expect_failure(device, compiler, sources, &bad, STELA_NV_RENDER_LIMIT);
    struct nv_device_info wrong = *device; wrong.sm++;
    expect_failure(&wrong, compiler, sources, options, STELA_NV_RENDER_DEVICE);
    const void *saved = compiler->nir_options.cb_data; unsigned borrowed = 1;
    compiler->nir_options.cb_data = &borrowed;
#ifdef STELA_NV_RENDER_ALLOC_TEST
    allocation_attempts = 0;
#endif
    expect_failure(device, compiler, sources, options, STELA_NV_RENDER_UNSUPPORTED);
#ifdef STELA_NV_RENDER_ALLOC_TEST
    CHECK(!allocation_attempts);
#endif
    compiler->nir_options.cb_data = saved;
    struct stela_metal_assembly *aliases[2] = {sources[0], sources[0]};
    expect_failure(device, compiler, aliases, options, STELA_NV_RENDER_INVALID);
    struct stela_metal_assembly *swapped[2] = {sources[1], sources[0]};
    expect_failure(device, compiler, swapped, options, STELA_NV_RENDER_INVALID);
    struct stela_nv_render_compilation *empty = NULL;
    CHECK(stela_nv_render_compile(device, compiler, &sources[0], &sources[0], options, &empty, NULL) == STELA_NV_RENDER_INVALID && !empty);
    struct stela_metal_assembly *first = sources[0];
    CHECK(stela_nv_render_compile(device, compiler, &sources[0], &sources[1], options,
        (struct stela_nv_render_compilation **)(void *)&sources[0], NULL) == STELA_NV_RENDER_INVALID && sources[0] == first);
    bad = *options; bad.max_code_bytes = 1;
    expect_failure(device, compiler, sources, &bad, STELA_NV_RENDER_LIMIT);
#ifdef STELA_NV_RENDER_ALLOC_TEST
    CHECK(!live_allocations);
    for (unsigned failure = 1; failure <= 3; ++failure) {
        allocation_attempts = 0; fail_allocation = failure;
        expect_failure(device, compiler, sources, options, STELA_NV_RENDER_ALLOCATION);
        CHECK(allocation_attempts == failure && !live_allocations);
    }
    fail_allocation = 0;
#endif
}
static void packing(const struct stela_nv_render_compilation *result, const struct nv_device_info *device)
{
    uint32_t count, bytes;
    const struct stela_nv_render_binding *map = stela_nv_render_bindings(result, STELA_AIR_VERTEX, &count, &bytes);
    CHECK(count == 2 && bytes == 64); /* This actual unchanged triangle only. */
    struct stela_nv_air_buffer_view views[2];
    for (unsigned i = 0; i < count; ++i) views[i] = (struct stela_nv_air_buffer_view){.device = device,
        .owner = &views[i], .argument = map[i].buffer.argument, .index = map[i].buffer.index,
        .available_access = STELA_AIR_READ, .allocation_va = UINT64_C(0x123400000) + 4096u * i,
        .allocation_bytes = 4096, .offset = 16, .bytes = i ? 8 : 96};
    uint8_t output[64], before[64]; memset(output, 0xa5, sizeof(output));
    CHECK(stela_nv_render_pack_arguments(result, STELA_AIR_VERTEX, device, 49, views, count, output, sizeof(output)) == STELA_NV_RENDER_OK);
    for (unsigned i = 0; i < count; ++i) {
        uint8_t expected[16] = {0}; little(expected, views[i].allocation_va + views[i].offset, 8);
        little(expected + 8, views[i].bytes, 4); CHECK(!memcmp(output + map[i].cbuf_offset, expected, 16));
    }
    for (unsigned i = 32; i < sizeof(output); ++i) CHECK(!output[i]);
    /* A reflected32B stride does not forbid a1B view or a partial last element. */
    views[0].bytes = 1;
    CHECK(stela_nv_render_pack_arguments(result, STELA_AIR_VERTEX, device, 49, views, count, output, sizeof(output)) == STELA_NV_RENDER_OK);
    CHECK(output[8] == 1);
    views[0].bytes = 33;
    CHECK(stela_nv_render_pack_arguments(result, STELA_AIR_VERTEX, device, 49, views, count, output, sizeof(output)) == STELA_NV_RENDER_OK);
    struct stela_nv_air_buffer_view saved = views[0];
    for (unsigned failure = 0; failure < 8; ++failure) {
        views[0] = saved;
        switch (failure) {
        case 0: views[0].bytes = 0; break;
        case 1: views[0].bytes = UINT64_C(1) << 32; break;
        case 2: views[0].available_access = STELA_AIR_WRITE; break;
        case 3: views[0].owner = NULL; break;
        case 4: views[0].offset = views[0].allocation_bytes; break;
        case 5: views[0].allocation_va++; break;
        case 6: views[0].argument = views[1].argument; views[0].index = views[1].index; break;
        case 7: views[0].allocation_va = UINT64_C(1) << 49; break;
        }
        memset(output, 0xa5, sizeof(output)); memcpy(before, output, sizeof(output));
        CHECK(stela_nv_render_pack_arguments(result, STELA_AIR_VERTEX, device, 49, views, count, output, sizeof(output)) == STELA_NV_RENDER_BINDING);
        CHECK(!memcmp(output, before, sizeof(output)));
    }
    views[0] = saved;
    struct stela_nv_air_buffer_view permuted[2] = {views[1], views[0]};
    CHECK(stela_nv_render_pack_arguments(result, STELA_AIR_VERTEX, device, 49, views, 2, output, sizeof(output)) == STELA_NV_RENDER_OK);
    memcpy(before, output, sizeof(output));
    CHECK(stela_nv_render_pack_arguments(result, STELA_AIR_VERTEX, device, 49, permuted, 2, output, sizeof(output)) == STELA_NV_RENDER_OK);
    CHECK(!memcmp(before, output, sizeof(output)));
    CHECK(stela_nv_render_pack_arguments(result, STELA_AIR_FRAGMENT, device, 49, NULL, 0, NULL, 0) == STELA_NV_RENDER_OK);
    stela_nv_render_bindings(result, STELA_AIR_FRAGMENT, &count, &bytes); CHECK(!count && !bytes);
}
static void owned_tests(const struct bytes *raw, const char *vertex, const char *fragment, const char *output)
{
    static const uint8_t sms[] = {75, 80, 86, 87, 89, 90, 100, 104, 120};
    unsigned outputs = 0;
    for (unsigned target = 0; target < ARRAY_SIZE(sms); ++target) for (unsigned profile = 0; profile < 2; ++profile) {
        const unsigned sm = sms[target], samples = profile ? 4u : 1u;
        /* Explicit CPU compiler/class models, never detected GPU facts. No
         * production SM->class inference: every original compiler receives this
         * same actual record, and layout policy independently receives class. */
        const struct nv_device_info device = {.sm = (uint8_t)sm, .cls_eng3d = TURING_A,
            .max_warps_per_mp = sm == 75 ? 32 : (sm == 86 || sm == 87 || sm == 89 || sm == 120 ? 48 : 64)};
        const struct nak_constant_offset_info layout = {.sample_info_cb = 0,
            .sample_locations_offset = 0, .sample_masks_offset = 256, .printf_cb = 1};
        struct nak_compiler *compiler = nak_compiler_create(&device, &layout, &layout); CHECK(compiler);
        struct stela_nv_render_options options = render_options(samples);
        struct bytes input[2] = {archive(raw->data, raw->count, vertex, 0), archive(raw->data, raw->count, fragment, 1)};
        struct stela_metal_assembly *sources[2]; assemble_pair(input, sources);
        if (!target && !profile) refusals(&device, compiler, sources, &options);
        struct stela_nv_render_compilation *result = NULL; struct stela_nv_render_error error;
        enum stela_nv_render_status status = stela_nv_render_compile(&device, compiler, &sources[0], &sources[1], &options, &result, &error);
        if (status) fprintf(stderr, "sm%u samples%u: %u %s\n", sm, samples, status, error.detail);
        CHECK(!status && result && !sources[0] && !sources[1]);
        nak_compiler_destroy(compiler); /* No original compiler pointer retained. */
        for (unsigned s = 0; s < 2; ++s) { memset(input[s].data, 0xa5, input[s].count); free(input[s].data); }
        CHECK(!stela_nv_render_nir_options(result)->cb_data);
        CHECK(stela_nv_render_provenance(result)->options.raster_samples == samples);
        for (unsigned s = 0; s < 2; ++s) {
            enum stela_air_stage kind = s ? STELA_AIR_FRAGMENT : STELA_AIR_VERTEX;
            const struct stela_metal_stage_view *source = stela_nv_render_source(result, kind);
            const struct nak_shader_bin *bin = stela_nv_render_binary(result, kind);
            const struct stela_nv_render_upload *image = stela_nv_render_upload(result, kind);
            CHECK(source && source->identity->entry.kind == s && source->reflection->stage == kind);
            CHECK(!strcmp(source->reflection->name, s ? fragment : vertex));
            CHECK(bin && bin->asm_str && bin->code_size && bin->info.sm == sm);
            CHECK(image && image->header_size == 128 && image->header_offset == 0 && image->code_offset == 128);
            CHECK(image->size == 128 + bin->code_size && !image->data_size && !image->data_offset);
            CHECK(!memcmp(image->bytes, bin->info.hdr, 128));
            CHECK(!memcmp((const char *)image->bytes + image->code_offset, bin->code, bin->code_size));
            CHECK(stela_nv_render_nir(result, kind)->options == stela_nv_render_nir_options(result));
            const char *label = s ? "fs" : "vs";
            artifact(output, sm, samples, label, "code", bin->code, bin->code_size);
            artifact(output, sm, samples, label, "info", &bin->info, sizeof(bin->info));
            artifact(output, sm, samples, label, "hdr", bin->info.hdr, sizeof(bin->info.hdr));
            artifact(output, sm, samples, label, "asm", bin->asm_str, strlen(bin->asm_str));
            printf("OWNED_RENDER sm%u samples%u %s code=", sm, samples, label); digest(bin->code, bin->code_size);
            printf(" info="); digest(&bin->info, sizeof(bin->info));
            printf(" hdr="); digest(bin->info.hdr, sizeof(bin->info.hdr));
            printf(" asm="); digest(bin->asm_str, strlen(bin->asm_str)); putchar('\n');
            ++outputs;
        }
        packing(result, &device);
        stela_nv_render_destroy(&result); CHECK(!result);
#ifdef STELA_NV_RENDER_ALLOC_TEST
        CHECK(!live_allocations);
#endif
    }
    printf("owned_outputs=%u\n", outputs);
}
int main(int argc, char **argv)
{
    const char *input = NULL, *vertex = NULL, *fragment = NULL, *output = NULL;
    for (int i = 1; i < argc; i += 2) {
        CHECK(i + 1 < argc);
        if (!strcmp(argv[i], "--input")) input = argv[i + 1];
        else if (!strcmp(argv[i], "--vertex")) vertex = argv[i + 1];
        else if (!strcmp(argv[i], "--fragment")) fragment = argv[i + 1];
        else if (!strcmp(argv[i], "--output")) output = argv[i + 1];
        else CHECK(false);
    }
    layout_tests(); constant_tests(); constant_image_tests(); unused_owner_tests();
    if (argc == 1) { puts("No external stage input requested; authored fixtures only"); return 0; }
    CHECK(input && vertex && fragment);
    FILE *file = fopen(input, "rb"); CHECK(file);
    CHECK(!fseek(file, 0, SEEK_END)); long size = ftell(file);
    CHECK(size > 0 && (uint64_t)size <= AIR_MAX_BITCODE_BYTES && !fseek(file, 0, SEEK_SET));
    struct bytes bytes = {.data = malloc((size_t)size), .count = (size_t)size}; CHECK(bytes.data);
    CHECK(fread(bytes.data, 1, bytes.count, file) == bytes.count && !fclose(file));
    owned_tests(&bytes, vertex, fragment, output); free(bytes.data); return 0;
}
