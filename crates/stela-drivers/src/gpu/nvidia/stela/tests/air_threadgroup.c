/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "stela/nvidia_compute.h"
#include "llvm-c/Core.h"
#include "nouveau/headers/drf.h"
#include "cl906f.h"
#include "cla0c0.h"
#include "clc5c0.h"
#include "clc6c0.h"
#include "clc7c0.h"
#include "clc9c0.h"
#include "clcbc0.h"
#include "clcdc0.h"
#include "clcec0.h"
#include "clc3c0qmd.h"
#include "clc6c0qmd.h"
#include "clcbc0qmd.h"
#include "clcdc0qmd.h"
#include "util/ralloc.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

struct fixture {
    const char *name, *entry;
    LLVMMemoryBufferRef input;
    unsigned threads, shared, device_argument, shared_argument, shared_index, budget;
    bool dynamic;
    unsigned device_calls, shared_calls;
};

/* Same static target facts as existing nvidia_compute_probe.c and the original
 * Nouveau occupancy table. These CPU fixtures never discover/create a device.
 */
static struct nv_device_info fixture_device(unsigned sm, unsigned cls)
{
    struct nv_device_info dev = {.sm = sm, .cls_compute = cls};
    const uint16_t ampere[] = {0, 8, 16, 32, 64, 100, 132, 164, 196, 228};
    if (sm == 75) {
        dev.max_warps_per_mp = 32; dev.sm_smem_size_count = 2;
        dev.sm_smem_sizes_kB[0] = 32; dev.sm_smem_sizes_kB[1] = 64;
    } else {
        dev.max_warps_per_mp = sm == 86 || sm == 87 || sm == 89 || sm == 120 ? 48 : 64;
        dev.sm_smem_size_count = sm == 80 || sm == 87 ? 8 : sm >= 90 && sm < 120 ? 10 : 6;
        memcpy(dev.sm_smem_sizes_kB, ampere, dev.sm_smem_size_count * sizeof(ampere[0]));
    }
    dev.max_smem_per_wg_kB = dev.sm_smem_sizes_kB[dev.sm_smem_size_count - 1];
    return dev;
}

static nir_def *bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer, void *data)
{
    struct fixture *fixture = data;
    CHECK(buffer->argument == fixture->device_argument && buffer->index == 7 &&
          buffer->address_space == 1 && buffer->access == STELA_AIR_READ_WRITE &&
          buffer->type_size == 4 && buffer->type_alignment == 4);
    fixture->device_calls++;
    return nir_imm_int64(b, 0x100000); /* Test global64 binding, never runtime memory */
}

static bool bind_threadgroup(const struct stela_air_buffer *buffer,
                              struct stela_air_threadgroup_view *view, void *data)
{
    struct fixture *fixture = data;
    CHECK(fixture->dynamic && buffer->argument == fixture->shared_argument &&
          buffer->index == fixture->shared_index && buffer->address_space == 3 &&
          buffer->access == STELA_AIR_READ_WRITE && buffer->type_size == 4 && buffer->type_alignment == 4);
    *view = (struct stela_air_threadgroup_view){fixture->shared, 4, STELA_AIR_READ_WRITE};
    fixture->shared_calls++;
    return true;
}

static void validate_nir(nir_shader *nir, const struct fixture *fixture)
{
    CHECK(nir->info.shared_size == fixture->shared && nir->info.workgroup_size[0] == fixture->threads);
    CHECK(nir->info.workgroup_size[1] == 1 && nir->info.workgroup_size[2] == 1);
    unsigned loads = 0, stores = 0, barriers = 0;
    nir_foreach_function_impl(impl, nir) {
        nir_foreach_block(block, impl) {
            nir_foreach_instr(instr, block) {
                if (instr->type != nir_instr_type_intrinsic) continue;
                nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
                loads += intr->intrinsic == nir_intrinsic_load_shared;
                stores += intr->intrinsic == nir_intrinsic_store_shared;
                if (intr->intrinsic == nir_intrinsic_barrier) {
                    barriers++;
                    CHECK(nir_intrinsic_execution_scope(intr) == SCOPE_WORKGROUP);
                    CHECK(nir_intrinsic_memory_scope(intr) == SCOPE_WORKGROUP);
                    CHECK(nir_intrinsic_memory_semantics(intr) == NIR_MEMORY_ACQ_REL);
                    CHECK(nir_intrinsic_memory_modes(intr) == nir_var_mem_shared);
                }
            }
        }
    }
    CHECK(loads && stores && barriers == 1);
    nir_validate_shader(nir, "corrected AIR threadgroup bridge before NAK");
}

struct decoded_shared { uint32_t bytes, barriers, minimum, target, maximum; };

static struct decoded_shared decode_shared(const struct nv_device_info *dev,
                                            const struct stela_nv_compute_encoded *encoded)
{
#define DECODE(NV, QMD, SHARED) (struct decoded_shared){ \
    .bytes = NVVAL_MW_GET(encoded->qmd, NV, QMD, SHARED), \
    .barriers = NVVAL_MW_GET(encoded->qmd, NV, QMD, BARRIER_COUNT), \
    .minimum = NVVAL_MW_GET(encoded->qmd, NV, QMD, MIN_SM_CONFIG_SHARED_MEM_SIZE), \
    .target = NVVAL_MW_GET(encoded->qmd, NV, QMD, TARGET_SM_CONFIG_SHARED_MEM_SIZE), \
    .maximum = NVVAL_MW_GET(encoded->qmd, NV, QMD, MAX_SM_CONFIG_SHARED_MEM_SIZE)}
    if (dev->cls_compute >= BLACKWELL_COMPUTE_A) {
        struct decoded_shared result = DECODE(NVCDC0, QMDV05_00, SHARED_MEMORY_SIZE_SHIFTED7);
        result.bytes <<= 7;
        return result;
    }
    if (dev->cls_compute >= HOPPER_COMPUTE_A) return DECODE(NVCBC0, QMDV04_00, SHARED_MEMORY_SIZE);
    if (dev->cls_compute >= AMPERE_COMPUTE_A) return DECODE(NVC6C0, QMDV03_00, SHARED_MEMORY_SIZE);
    return DECODE(NVC3C0, QMDV02_02, SHARED_MEMORY_SIZE);
#undef DECODE
}

static uint32_t smem_config(const struct nv_device_info *dev, uint64_t bytes)
{
    for (unsigned i = 0; i < dev->sm_smem_size_count; i++)
        if ((uint64_t)dev->sm_smem_sizes_kB[i] * 1024 >= bytes)
            return dev->sm_smem_sizes_kB[i] / 4 + 1;
    CHECK(!"configuration must fit declared target limits");
    return 0;
}

static void validate_qmd(const struct nv_device_info *dev, const struct nak_shader_info *info,
                          const struct stela_nv_compute_dispatch *dispatch,
                          const struct stela_nv_compute_encoded *encoded)
{
    const struct decoded_shared state = decode_shared(dev, encoded);
    const uint32_t rounded = (dispatch->qmd.smem_size + 255u) & ~255u;
    CHECK(state.bytes == rounded && state.barriers == info->num_control_barriers);
    CHECK(state.minimum == smem_config(dev, rounded));
    CHECK(state.maximum == dev->sm_smem_sizes_kB[dev->sm_smem_size_count - 1] / 4 + 1);
    const uint32_t warps = (info->cs.local_size[0] + 31) / 32;
    const uint32_t capacity = dev->sm_smem_sizes_kB[dev->sm_smem_size_count - 1] * 1024;
    const uint32_t groups = MIN2(info->max_warps_per_sm / warps, capacity / MAX2(rounded, 1));
    CHECK(groups && state.target == smem_config(dev, (uint64_t)rounded * groups));
    CHECK(encoded->qmd_size_B == nak_qmd_size_B(dev));
    uint32_t original[NAK_MAX_QMD_DWORDS] = {0};
    nak_fill_qmd(dev, info, &dispatch->qmd, original, encoded->qmd_size_B);
    CHECK(!memcmp(encoded->qmd, original, encoded->qmd_size_B));
    CHECK(encoded->push_dw == 3);
    CHECK(NVVAL_GET(encoded->push[0], NV906F, DMA, METHOD_ADDRESS) * 4 == NVA0C0_SEND_PCAS_A);
    CHECK(NVVAL_GET(encoded->push[0], NV906F, DMA, METHOD_SUBCHANNEL) == 1);
    CHECK(NVVAL_GET(encoded->push[0], NV906F, DMA, SEC_OP) == NV906F_DMA_SEC_OP_INC_METHOD);
    CHECK(NVVAL_GET(encoded->push[0], NV906F, DMA, METHOD_COUNT) == 1);
    CHECK(encoded->push[1] == dispatch->qmd_addr >> 8);
    const unsigned method = NVVAL_GET(encoded->push[2], NV906F, DMA, METHOD_ADDRESS) * 4;
    CHECK(method == (dev->cls_compute == TURING_COMPUTE_A ?
          NVA0C0_SEND_SIGNALING_PCAS_B : NVC6C0_SEND_SIGNALING_PCAS2_B));
    CHECK(NVVAL_GET(encoded->push[2], NV906F, DMA, METHOD_SUBCHANNEL) == 1);
    CHECK(NVVAL_GET(encoded->push[2], NV906F, DMA, SEC_OP) == NV906F_DMA_SEC_OP_IMMD_DATA_METHOD);
    const uint32_t action = NVVAL_GET(encoded->push[2], NV906F, DMA, IMMD_DATA);
    if (dev->cls_compute == TURING_COMPUTE_A) {
        CHECK(NVVAL_GET(action, NVA0C0, SEND_SIGNALING_PCAS_B, INVALIDATE) ==
              NVA0C0_SEND_SIGNALING_PCAS_B_INVALIDATE_TRUE);
        CHECK(NVVAL_GET(action, NVA0C0, SEND_SIGNALING_PCAS_B, SCHEDULE) ==
              NVA0C0_SEND_SIGNALING_PCAS_B_SCHEDULE_TRUE);
    } else {
        CHECK(action == NVC6C0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INVALIDATE_COPY_SCHEDULE);
    }
}

static void refusal(const struct nv_device_info *dev, const struct nak_shader_bin *shader,
                     const struct stela_nv_compute_dispatch *dispatch, enum stela_nv_compute_error expected)
{
    struct stela_nv_compute_encoded out, before;
    memset(&out, 0xa7, sizeof(out)); memcpy(&before, &out, sizeof(out));
    enum stela_nv_compute_error error;
    CHECK(!stela_nv_compute_encode(dev, shader, dispatch, &out, &error));
    CHECK(error == expected && !memcmp(&out, &before, sizeof(out)));
}

static void shared_limits(const struct nv_device_info *dev, const struct nak_shader_bin *shader,
                           const struct stela_nv_compute_dispatch *dispatch)
{
    struct stela_nv_compute_dispatch test = *dispatch;
    test.qmd.smem_size = shader->info.cs.smem_size - 1;
    refusal(dev, shader, &test, STELA_NV_COMPUTE_SHARED_MEMORY);
    test.qmd.smem_size = dev->max_smem_per_wg_kB * 1024 + 1;
    refusal(dev, shader, &test, STELA_NV_COMPUTE_SHARED_MEMORY);
    test.qmd.smem_size = UINT32_MAX;
    refusal(dev, shader, &test, STELA_NV_COMPUTE_SHARED_MEMORY);
    struct nak_shader_bin too_many = *shader;
    too_many.info.num_control_barriers = DRF_MASK(DRF_MW(NVC3C0_QMDV02_02_BARRIER_COUNT)) + 1;
    refusal(dev, &too_many, dispatch, STELA_NV_COMPUTE_SHADER);
    const uint32_t reservations[] = {shader->info.cs.smem_size, shader->info.cs.smem_size + 1,
        257, dev->max_smem_per_wg_kB * 1024 - 1, dev->max_smem_per_wg_kB * 1024};
    for (unsigned i = 0; i < ARRAY_SIZE(reservations); i++) {
        test.qmd.smem_size = reservations[i];
        struct stela_nv_compute_encoded out;
        enum stela_nv_compute_error error;
        CHECK(stela_nv_compute_encode(dev, shader, &test, &out, &error));
        validate_qmd(dev, &shader->info, &test, &out);
    }
}

static FILE *artifact(const char *directory, const char *name, unsigned sm, const char *extension)
{
    char path[1024];
    const int bytes = snprintf(path, sizeof(path), "%s/%s-sm%u.%s", directory, name, sm, extension);
    CHECK(bytes > 0 && (size_t)bytes < sizeof(path));
    FILE *file = fopen(path, "wbx"); CHECK(file); return file;
}

static void bytes_artifact(const char *directory, const char *name, unsigned sm,
                            const char *extension, const void *bytes, size_t size)
{
    FILE *file = artifact(directory, name, sm, extension);
    CHECK(fwrite(bytes, 1, size, file) == size && fclose(file) == 0);
}

static void compile_fixture(struct fixture *fixture, unsigned sm, unsigned cls, const char *directory)
{
    const struct nv_device_info dev = fixture_device(sm, cls);
    const struct nak_constant_offset_info layout = {
        .sample_info_cb = 0, .sample_locations_offset = 0, .sample_masks_offset = 256,
        .printf_cb = 0, .printf_buffer_offset = 512,
    };
    struct nak_compiler *compiler = nak_compiler_create(&dev, &layout, &layout); CHECK(compiler);
    const struct stela_air_options options = {
        .workgroup_size = {fixture->threads, 1, 1}, .max_instructions = fixture->budget,
        .bind_buffer = bind_buffer, .binding_data = fixture, .fp_profile = STELA_AIR_FP_IEEE_DEFAULT,
        .bind_threadgroup = fixture->dynamic ? bind_threadgroup : NULL,
        .max_threadgroup_bytes = fixture->shared,
    };
    fixture->device_calls = fixture->shared_calls = 0;
    struct stela_air_error error;
    nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(fixture->input), LLVMGetBufferSize(fixture->input),
        fixture->entry, nak_nir_options(compiler), &options, &error);
    if (!nir) fprintf(stderr, "%s SM%u: AIR error%u %s\n", fixture->name, sm, error.kind, error.detail);
    CHECK(nir && fixture->device_calls == 1 && fixture->shared_calls == (fixture->dynamic ? 1u : 0u));
    validate_nir(nir, fixture);
    FILE *file = artifact(directory, fixture->name, sm, "nir");
    nir_print_shader(nir, file); CHECK(fclose(file) == 0);
    nak_preprocess_nir(nir, compiler);
    struct nak_shader_bin *shader = nak_compile_shader(nir, true, compiler, 0, NULL, false);
    CHECK(shader && shader->code && shader->code_size && shader->asm_str);
    CHECK(shader->info.cs.smem_size == fixture->shared && shader->info.cs.local_size[0] == fixture->threads);
    CHECK(strstr(shader->asm_str, "st.shared") && strstr(shader->asm_str, "ld.shared"));
    const unsigned barriers = fixture->threads > NAK_SUBGROUP_SIZE ? 1 : 0;
    CHECK(shader->info.num_control_barriers == barriers);
    CHECK((strstr(shader->asm_str, "bar.sync") != NULL) == (barriers != 0));
    struct stela_nv_compute_dispatch dispatch = {
        .qmd = {.addr = 0x200000, .smem_size = shader->info.cs.smem_size, .global_size = {7, 5, 3},
                .num_cbufs = 2, .cbufs = {{.index = 0, .size = 256, .addr = 0x400000},
                                        {.index = 7, .size = 64, .addr = 0x500000}}},
        .qmd_addr = 0x300000, .va_bits = sm >= 90 ? 57 : 49,
    };
    struct stela_nv_compute_encoded encoded;
    enum stela_nv_compute_error encode_error;
    CHECK(stela_nv_compute_encode(&dev, shader, &dispatch, &encoded, &encode_error));
    validate_qmd(&dev, &shader->info, &dispatch, &encoded);
    shared_limits(&dev, shader, &dispatch);
    bytes_artifact(directory, fixture->name, sm, "code", shader->code, shader->code_size);
    bytes_artifact(directory, fixture->name, sm, "asm", shader->asm_str, strlen(shader->asm_str));
    bytes_artifact(directory, fixture->name, sm, "qmd", encoded.qmd, encoded.qmd_size_B);
    bytes_artifact(directory, fixture->name, sm, "push", encoded.push, encoded.push_dw * sizeof(uint32_t));
    const struct decoded_shared decoded = decode_shared(&dev, &encoded);
    printf("%s SM%u class%04x WG%u: NIR/NAK shared%u, CTAbarriers%u, QMD shared%u barriers%u config%u/%u/%u, code%uB QMD%uB launch%uDW; hardware_executed=false\n",
        fixture->name, sm, cls, fixture->threads, fixture->shared, shader->info.num_control_barriers,
        decoded.bytes, decoded.barriers, decoded.minimum, decoded.target, decoded.maximum,
        shader->code_size, encoded.qmd_size_B, encoded.push_dw);
    nak_shader_bin_destroy(shader); ralloc_free(nir); nak_compiler_destroy(compiler);
}

int main(int argc, char **argv)
{
    CHECK(argc == 5); /* Original AIR, synthetic static, synthetic dynamic, output directory */
    LLVMMemoryBufferRef inputs[3];
    for (unsigned i = 0; i < 3; i++) {
        char *error = NULL;
        CHECK(!LLVMCreateMemoryBufferWithContentsOfFile(argv[i + 1], &inputs[i], &error));
    }
    struct fixture fixtures[] = {
        {.name = "apple-static", .entry = "stela_threadgroup_static", .input = inputs[0],
         .threads = 32, .shared = 128, .device_argument = 0, .budget = 256},
        {.name = "apple-dynamic", .entry = "stela_threadgroup_dynamic", .input = inputs[0],
         .threads = 32, .shared = 128, .device_argument = 0, .shared_argument = 1, .shared_index = 3, .budget = 256, .dynamic = true},
        {.name = "synthetic-static", .entry = "kernel", .input = inputs[1],
         .threads = 64, .shared = 256, .device_argument = 1, .budget = 1000},
        {.name = "synthetic-dynamic", .entry = "kernel", .input = inputs[2],
         .threads = 64, .shared = 256, .device_argument = 1, .shared_argument = 2, .shared_index = 7, .budget = 1000, .dynamic = true},
    };
    const unsigned targets[][2] = {{75, TURING_COMPUTE_A}, {80, AMPERE_COMPUTE_A},
        {86, AMPERE_COMPUTE_B}, {87, AMPERE_COMPUTE_B}, {89, ADA_COMPUTE_A}, {90, HOPPER_COMPUTE_A},
        {100, BLACKWELL_COMPUTE_A}, {104, BLACKWELL_COMPUTE_A}, {120, BLACKWELL_COMPUTE_B}};
    glsl_type_singleton_init_or_ref();
    for (unsigned f = 0; f < ARRAY_SIZE(fixtures); f++)
        for (unsigned t = 0; t < ARRAY_SIZE(targets); t++)
            compile_fixture(&fixtures[f], targets[t][0], targets[t][1], argv[4]);
    glsl_type_singleton_decref();
    for (unsigned i = 0; i < 3; i++) LLVMDisposeMemoryBuffer(inputs[i]);
    return 0;
}
