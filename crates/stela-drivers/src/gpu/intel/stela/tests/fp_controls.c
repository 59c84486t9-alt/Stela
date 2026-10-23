/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "air_probe_input.h"
#include "stela/tests/air_probe.h"
#include "../hosted/compute.h"
#include "../hosted/legacy_compute.h"
#include "../hosted/fp_controls.h"
#include "legacy_elk_validate.h"
#include "fp_controls_elk.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/elk/elk_nir.h"
#include "intel/dev/intel_debug.h"
#include "stela/tests/intel_probe.h"
#include "stela/tests/targets/intel.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void compiler_log(void *data, unsigned *id, const char *format, ...)
{
    (void)data; (void)id;
    va_list args; va_start(args, format); vfprintf(stderr, format, args); va_end(args);
}

static uint32_t controls(bool ftz)
{
    return FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32 |
        (ftz ? FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32 : FLOAT_CONTROLS_DENORM_PRESERVE_FP32);
}

static bool bind_buffer(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
    unsigned *bound = data;
    if (*bound || buffer->index != 7 || buffer->access != STELA_AIR_READ_WRITE ||
        buffer->address_space != 1 || buffer->type_size != 4 || buffer->type_alignment != 4)
        return false;
    *slot = 0; ++*bound;
    return true;
}

static nir_shader *input_shader(const nir_shader_compiler_options *options,
                                LLVMMemoryBufferRef input, const char *entry,
                                enum stela_air_fp_profile profile, bool ftz)
{
    if (input) {
        unsigned bound = 0;
        struct stela_air_error error;
        const struct stela_air_options air_options = {
            .workgroup_size = {32, 1, 1}, .max_instructions = 256,
            .bind_ssbo = bind_buffer, .ssbo_count = 1, .binding_data = &bound,
            .fp_profile = profile,
        };
        nir_shader *nir = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                          entry, options, &air_options, &error);
        if (!nir) fprintf(stderr, "AIR FP32 lowering: %s\n", error.detail);
        assert(nir && error.kind == STELA_AIR_OK && bound == 1);
        assert(nir->info.float_controls_execution_mode == controls(ftz));
        return nir;
    }
    nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, options,
                                                  "stela_fp32_controls_fixture");
    b.shader->info.workgroup_size[0] = 32;
    b.shader->info.workgroup_size[1] = b.shader->info.workgroup_size[2] = 1;
    b.shader->info.num_ssbos = 1;
    b.shader->info.float_controls_execution_mode = controls(ftz);
    b.fp_math_ctrl = nir_fp_no_fast_math;
    nir_def *offset = nir_ishl_imm(&b,
        nir_channel(&b, nir_load_global_invocation_id(&b, 32), 0), 5);
    nir_def *a = nir_load_ssbo(&b, 1, 32, nir_imm_int(&b, 0), offset, .align_mul = 4);
    nir_def *v = nir_load_ssbo(&b, 1, 32, nir_imm_int(&b, 0), nir_iadd_imm(&b, offset, 4),
        .align_mul = 4);
    nir_def *values[] = {nir_fadd(&b, a, v), nir_fsub(&b, a, v), nir_fmul(&b, a, v),
                         nir_i2f32(&b, a), nir_u2f32(&b, v), nir_b2i32(&b, nir_flt(&b, a, v))};
    for (unsigned i = 0; i < ARRAY_SIZE(values); ++i)
        nir_store_ssbo(&b, values[i], nir_imm_int(&b, 0), nir_iadd_imm(&b, offset, 8 + 4 * i),
            .align_mul = 4);
    return b.shader;
}

/* Decode actual emitted bytes with retained Intel decoding, including compact
 * instructions. Track only actual CR0 writes; flags in NIR alone are not proof.
 * Original backend validators run before this additional focused inspection.
 */
static void check_isa(const struct intel_device_info *device, void *context,
                      const struct elk_compiler *elk,
                      const void *code, unsigned bytes, const char *target, bool ftz,
                      uint32_t nir_mode, LLVMMemoryBufferRef input, const char *entry)
{
    struct stela_intel_fp_stats stats = {0};
    if (elk) {
        stela_intel_elk_fp_control_stats(elk, code, bytes, target, ftz, &stats);
    } else {
        gen_decode_params decoded = {.devinfo = device, .raw_bytes = code,
            .raw_bytes_size = bytes, .mem_ctx = context};
        assert(gen_decode(&decoded));
        uint32_t known = 0, value = 0;
        unsigned writes = 0, clear = 0, preserve = 0, floating = 0, conversions = 0, syncs = 0;
        for (int i = 0; i < decoded.num_insts; ++i) {
            const gen_inst *inst = &decoded.insts[i];
            if (inst->dst.file == GEN_ARF && inst->dst.nr == GEN_ARF_CONTROL && !inst->dst.subnr) {
                assert(inst->src[0].file == GEN_ARF && inst->src[0].nr == GEN_ARF_CONTROL &&
                       !inst->src[0].subnr && inst->src[1].file == GEN_IMM);
                assert(inst->exec_size == 1 && inst->no_mask);
                if (device->ver < 12) assert(inst->thread_control == GEN_THREAD_SWITCH);
                else assert(inst->swsb.regdist == 1);
                if (device->ver >= 12) {
                    assert(i + 1 < decoded.num_insts);
                    const gen_inst *next = &decoded.insts[i + 1];
                    if (next->dst.file != GEN_ARF || next->dst.nr != GEN_ARF_CONTROL) {
                        assert(next->opcode == GEN_OP_SYNC && next->sync.func == GEN_SYNC_NOP &&
                               next->swsb.regdist == 1);
                        ++syncs;
                    }
                }
                uint32_t immediate = (uint32_t)inst->src[1].imm;
                if (inst->opcode == GEN_OP_AND) {
                    known |= ~immediate; value &= immediate;
                    clear += immediate == ~UINT32_C(0xb0);
                } else {
                    assert(inst->opcode == GEN_OP_OR);
                    known |= immediate; value |= immediate;
                    preserve += immediate == 0x80;
                }
                ++writes;
                printf("%s CR0 write at instruction %d: %s 0x%x, exec size %u, "
                       "thread control %u, SWSB regdist %u\n", target, i,
                       inst->opcode == GEN_OP_AND ? "and" : "or", immediate,
                       inst->exec_size, inst->thread_control, inst->swsb.regdist);
            }
            bool arithmetic = (inst->opcode == GEN_OP_ADD || inst->opcode == GEN_OP_MUL ||
                               inst->opcode == GEN_OP_MAD || inst->opcode == GEN_OP_CMP) &&
                (inst->dst.type == GEN_TYPE_F || inst->src[0].type == GEN_TYPE_F);
            bool conversion = inst->opcode == GEN_OP_MOV && inst->dst.type == GEN_TYPE_F &&
                (inst->src[0].type == GEN_TYPE_D || inst->src[0].type == GEN_TYPE_UD);
            if (arithmetic || conversion) {
                assert((known & 0xb0) == 0xb0 && (value & 0xb0) == (ftz ? 0u : 0x80u));
                floating += arithmetic; conversions += conversion;
            }
        }
        stats = (struct stela_intel_fp_stats){
            writes, clear, preserve, floating, conversions, syncs};
    }
    assert(stats.clear && stats.writes && stats.floating &&
        (ftz ? !stats.preserve : stats.preserve));
    assert(device->ver < 12 || stats.swsb_syncs);
    record_compiled(target, bytes);
    record_object("facts");
    record_uint("pci_id", device->pci_device_id);
    record_uint("nir_float_controls", nir_mode);
    record_bool("fp32_ftz", ftz);
    record_bool("rte", true);
    record_uint("cr0_writes", stats.writes);
    record_uint("fp_arithmetic", stats.floating);
    record_uint("conversions", stats.conversions);
    record_uint("swsb_syncs", stats.swsb_syncs);
    record_blake3("code_blake3", code, bytes);
    record_str("input_kind", input ? "raw_input" : "direct_nir_fixture");
    if (input)
        record_blake3("input_blake3", LLVMGetBufferStart(input), LLVMGetBufferSize(input));
    record_str("entry", entry);
    record_end();
}

static void check_plan(const struct brw_compiler *brw, const struct elk_compiler *elk,
                       const struct isl_device *isl, const struct brw_cs_prog_data *brw_data,
                       const struct elk_cs_prog_data *elk_data, const struct shader_info *info)
{
    unsigned bytes = brw ? brw_data->base.program_size : elk_data->base.program_size;
    const uint32_t groups[] = {1, 1, 1};
    struct stela_intel_legacy_placement placement = {
        .code_offset = 0x1000,
        .code_span = bytes,
        .binding_table_offset = 0x2000,
        .binding_table_entries = info->num_ssbos,
        .binding_table_span = (uint64_t)info->num_ssbos * 4,
        .curbe_offset = 0x4000,
        .curbe_span = 2048,
        .descriptor_offset = 0x5000,
        .descriptor_span = 32,
    };
    struct stela_intel_compute_placement modern_placement = {
        .code_offset = placement.code_offset, .code_span = placement.code_span,
        .binding_table_offset = placement.binding_table_offset,
        .binding_table_entries = placement.binding_table_entries,
        .binding_table_span = placement.binding_table_span,
    };
    struct stela_intel_legacy_plan legacy, legacy_before;
    struct stela_intel_compute_plan modern, modern_before;
    if (isl->info->verx10 >= 125)
        assert(stela_intel_compute_plan(brw, isl, brw_data, info, &modern_placement, groups, 0,
                   &modern) == 0);
    else if (brw)
        assert(stela_intel_legacy_brw_plan(brw, isl, brw_data, info, &placement, groups, 0,
                   &legacy) == 0);
    else
        assert(stela_intel_legacy_elk_plan(elk, isl, elk_data, info, &placement, groups, &legacy) ==
            0);
    memset(&legacy_before, 0xa5, sizeof(legacy_before));
    memset(&modern_before, 0xa5, sizeof(modern_before));
    const uint32_t rejected[] = {0, FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32,
        FLOAT_CONTROLS_DENORM_PRESERVE_FP32, FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32,
        FLOAT_CONTROLS_ROUNDING_MODE_RTZ_FP32 | FLOAT_CONTROLS_DENORM_PRESERVE_FP32,
        FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32 | FLOAT_CONTROLS_ROUNDING_MODE_RTZ_FP32 |
            FLOAT_CONTROLS_DENORM_PRESERVE_FP32,
        FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32 | FLOAT_CONTROLS_DENORM_PRESERVE_FP32 |
            FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32,
        UINT32_C(0x80000000)};
    for (unsigned i = 0; i < ARRAY_SIZE(rejected) + 5; ++i) {
        struct shader_info bad = *info;
        if (i < ARRAY_SIZE(rejected)) bad.float_controls_execution_mode = rejected[i];
        else switch (i - ARRAY_SIZE(rejected)) {
        case 0: bad.bit_sizes_float |= 16; break;
        case 1: bad.bit_sizes_float |= 64; break;
        case 2: bad.stage = MESA_SHADER_FRAGMENT; break;
        case 3: ++bad.workgroup_size[0]; break;
        case 4: bad.workgroup_size_variable = true; break;
        }
        modern = modern_before; legacy = legacy_before;
        int status = isl->info->verx10 >= 125 ?
            stela_intel_compute_plan(brw, isl, brw_data, &bad, &modern_placement, groups, 0,
                &modern) :
            brw ?
            stela_intel_legacy_brw_plan(brw, isl, brw_data, &bad, &placement, groups, 0, &legacy) :
            stela_intel_legacy_elk_plan(elk, isl, elk_data, &bad, &placement, groups, &legacy);
        assert(status ==
            (i == ARRAY_SIZE(rejected) + 2 || i == ARRAY_SIZE(rejected) + 3 ? -22 : -95));
        assert(!memcmp(&modern, &modern_before, sizeof(modern)));
        assert(!memcmp(&legacy, &legacy_before, sizeof(legacy)));
    }
    if (isl->info->ver == 7) {
        struct shader_info unsupported = *info;
        unsupported.float_controls_execution_mode = controls(false);
        legacy = legacy_before;
        assert(stela_intel_legacy_elk_plan(elk, isl, elk_data, &unsupported,
                                          &placement, groups, &legacy) == -95);
        assert(!memcmp(&legacy, &legacy_before, sizeof(legacy)));
    }
}

static void target_name(char name[32], const char *platform, bool ftz)
{
    snprintf(name, 32, "%s.%s", platform, ftz ? "ftz" : "preserve");
}

/* Stela's FP32 policy refuses denorm preservation before Gen8. */
static void expect(const char *platform, const struct intel_device_info *device, bool ftz)
{
    char target[32];
    target_name(target, platform, ftz);
    if (device->ver == 7 && !ftz)
        record_expect_refusal(target, STELA_REFUSAL_INTEL_GEN7_FP32_PRESERVE);
    else
        record_expect(target, stela_intel_hold(device));
}

static void compile(const char *platform, const struct intel_device_info *device, bool ftz,
                    LLVMMemoryBufferRef input, const char *entry,
                    enum stela_air_fp_profile profile)
{
    char target[32];
    target_name(target, platform, ftz);
    const char *hold = stela_intel_hold(device);
    if (hold) {
        record_held(target, hold);
        return;
    }
    struct isl_device isl = {0}; isl_device_init(&isl, device);
    void *context = ralloc_context(NULL);
    const bool use_elk = stela_intel_elk(device);
    struct brw_compiler *brw = use_elk ? NULL : brw_compiler_create(context, device);
    struct elk_compiler *elk = use_elk ? elk_compiler_create(context, device) : NULL;
    if (brw) brw->shader_debug_log = brw->shader_perf_log = compiler_log;
    if (elk) elk->shader_debug_log = elk->shader_perf_log = compiler_log;
    const nir_shader_compiler_options *options = brw ? &brw->nir_options[MESA_SHADER_COMPUTE] :
                                                       elk->nir_options[MESA_SHADER_COMPUTE];
    nir_shader *nir = input_shader(options, input, entry, profile, ftz);
    if (brw) {
        const struct brw_nir_compiler_opts opts = {0}; brw_preprocess_nir(brw, nir, &opts);
    } else {
        const struct elk_nir_compiler_opts opts = {0}; elk_preprocess_nir(elk, nir, &opts);
    }
    const nir_lower_compute_system_values_options sys = {.has_base_workgroup_id = false};
    NIR_PASS(_, nir, nir_lower_compute_system_values, &sys);
    nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
    int fp_status = stela_intel_fp_controls(device, &nir->info);
    if (fp_status) {
        assert(fp_status == -95 && nir->info.float_controls_execution_mode == controls(false));
        record_refused(target, STELA_REFUSAL_INTEL_GEN7_FP32_PRESERVE);
        ralloc_free(nir); ralloc_free(context);
        return;
    }
    nir->info.min_subgroup_size = nir->info.max_subgroup_size = 16;
    struct brw_cs_prog_data brw_data = {0}; struct elk_cs_prog_data elk_data = {0};
    const unsigned *code;
    if (brw) {
        struct brw_cs_prog_key key = {0};
        brw_nir_lower_cs_intrinsics(nir, device, &brw_data);
        if (brw_nir_lower_cs_subgroup_id(nir, device, 0)) {
            brw_data.base.push_sizes[0] = 4;
            brw_cs_fill_push_const_info(device, &brw_data, 0);
            brw_data.base.push_sizes[0] = align(4, REG_SIZE);
        } else brw_cs_fill_push_const_info(device, &brw_data, -1);
        nir_validate_shader(nir, "FP32 controls original BRW compile");
        struct brw_compile_cs_params p = {.base = {.mem_ctx = context, .nir = nir,
            .key = &key.base, .prog_data = &brw_data.base}};
        code = brw_compile(brw, &p.base);
        if (!code) fprintf(stderr, "%s: %s\n", target, p.base.error_str);
        assert(code && !p.base.error_str);
        unsigned sends;
        assert(validate_intel_code(device, context, code, brw_data.base.program_size, target,
            &sends));
    } else {
        struct elk_cs_prog_key key = {0};
        elk_nir_lower_cs_intrinsics(nir, device, &elk_data);
        nir_validate_shader(nir, "FP32 controls original ELK compile");
        struct elk_compile_cs_params p = {.base = {.mem_ctx = context, .nir = nir},
            .key = &key, .prog_data = &elk_data};
        code = elk_compile_cs(elk, &p);
        if (!code) fprintf(stderr, "%s: %s\n", target, p.base.error_str);
        assert(code && !p.base.error_str);
        assert(stela_legacy_elk_code_valid(elk, code, elk_data.base.program_size));
    }
    assert(nir->info.float_controls_execution_mode == controls(ftz));
    assert(nir->info.bit_sizes_float == 32 && stela_intel_fp_controls(device, &nir->info) == 0);
    check_plan(brw, elk, &isl, &brw_data, &elk_data, &nir->info);
    check_isa(device, context, elk, code,
        brw ? brw_data.base.program_size : elk_data.base.program_size, target, ftz,
        nir->info.float_controls_execution_mode, input, entry);
    ralloc_free(nir); ralloc_free(context);
}

int main(int argc, char **argv)
{
    enum stela_air_fp_profile profile;
    if (!stela_air_probe_profile(&argc, argv, &profile)) return 2;
    const char *entry = "kernel";
    LLVMMemoryBufferRef input = NULL;
    if (argc > 1) {
        input = stela_intel_air_probe_input(argc, argv, &entry);
        if (!input) return 2;
        stela_air_probe_profile_record(profile);
    } else if (profile != STELA_AIR_FP_IEEE_DEFAULT) {
        return 2;
    }
    /* An input requests one FP32 mode through its profile; the direct NIR
     * fixture covers both. */
    const unsigned first = input ? profile == STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41 : 0;
    const unsigned last = input ? first : 1;
    struct intel_device_info device;
    const char *platform;
    STELA_INTEL_FOREACH_TARGET(platform, device) {
        for (unsigned ftz = first; ftz <= last; ++ftz)
            expect(platform, &device, ftz);
    }
    process_intel_debug_variable(); glsl_type_singleton_init_or_ref();
    STELA_INTEL_FOREACH_TARGET(platform, device) {
        for (unsigned ftz = first; ftz <= last; ++ftz)
            compile(platform, &device, ftz, input, input ? entry : "direct_nir_fixture", profile);
    }
    if (input) LLVMDisposeMemoryBuffer(input);
    glsl_type_singleton_decref();
    return 0;
}
