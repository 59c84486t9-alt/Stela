/* SPDX-License-Identifier: MIT */
#include "../hosted/legacy_compute.h"
#include "intel/compiler/brw/brw_nir.h"
#include "intel/compiler/elk/elk_nir.h"
#include "legacy_elk_validate.h"
#include "intel/common/intel_compute_slm.h"
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

static nir_shader *shader(const nir_shader_compiler_options *options, unsigned mode)
{
    nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, options,
                                                  "stela_legacy_compute_fixture");
    b.shader->info.workgroup_size[0] = mode == 2 ? 32 : mode == 1 ? 3 : 33;
    b.shader->info.workgroup_size[1] = mode == 1 ? 11 : 1;
    b.shader->info.workgroup_size[2] = 1;
    b.shader->info.num_ssbos = 1;
    nir_def *index = mode == 2 ? nir_imm_int(&b, 0) :
        nir_channel(&b, nir_load_global_invocation_id(&b, 32), 0);
    nir_def *offset = nir_ishl_imm(&b, index, 2);
    nir_def *value = nir_load_ssbo(&b, 1, 32, nir_imm_int(&b, 0), offset, .align_mul = 4);
    if (mode == 1) {
        b.shader->info.shared_size = b.shader->info.workgroup_size[0] *
                                     b.shader->info.workgroup_size[1] * 4;
        nir_def *local = nir_ishl_imm(&b, nir_load_local_invocation_index(&b), 2);
        nir_store_shared(&b, value, local, .align_mul = 4);
        nir_barrier(&b, .execution_scope = SCOPE_WORKGROUP, .memory_scope = SCOPE_WORKGROUP,
                    .memory_semantics = NIR_MEMORY_ACQ_REL, .memory_modes = nir_var_mem_shared);
        value = nir_load_shared(&b, 1, 32, local, .align_mul = 4);
    }
    nir_store_ssbo(&b, nir_iadd_imm(&b, value, 1), nir_imm_int(&b, 0), offset, .align_mul = 4);
    return b.shader;
}

static struct stela_intel_legacy_placement placement(unsigned program_bytes)
{
    /* Compiler/packet fixture offsets only: no actual bases or mappings. */
    return (struct stela_intel_legacy_placement){
        .code_offset = 0x1000, .code_span = program_bytes,
        .binding_table_offset = 0x2000, .binding_table_entries = 1, .binding_table_span = 4,
        .curbe_offset = 0x4000, .curbe_span = 2048,
        .descriptor_offset = 0x5000, .descriptor_span = 32,
    };
}

static void check(const struct intel_device_info *device, struct intel_cs_dispatch_info info,
                  bool subgroup, unsigned shared, bool barrier, uint32_t kernel,
                  const struct stela_intel_legacy_plan *plan)
{
    assert(plan->dispatch.gfx_verx10 == device->verx10);
    assert(plan->dispatch.simd_size == info.simd_size && plan->dispatch.threads == info.threads);
    assert(plan->dispatch.right_mask == info.right_mask &&
           plan->dispatch.group_size == info.group_size);
    assert(plan->dispatch.groups[0] == 19 && plan->dispatch.groups[1] == 23 &&
           plan->dispatch.groups[2] == 29);
    assert(plan->curbe_bytes == (subgroup ? align(32 * info.threads, 64) : 64));
    for (unsigned i = 0; i < ARRAY_SIZE(plan->curbe); ++i) {
        unsigned expected = i * 4 < plan->curbe_bytes ? 0x5a5a5a5a : 0;
        if (subgroup && i % 8 == 0 && i / 8 < info.threads) expected = i / 8;
        assert(plan->curbe[i] == expected);
    }
    assert(plan->descriptor[0] == kernel);
    unsigned bt_word = device->ver == 7 ? 3 : 4;
    assert(plan->descriptor[bt_word] == (0x2000u >> (device->ver >= 11 ? 3 : 0)) + 1);
    unsigned const_word = device->ver == 7 ? 4 : 5;
    assert(plan->descriptor[const_word] == (subgroup ? 1u << 16 : 0));
    uint32_t group = info.threads | (intel_compute_slm_encode_size(device->ver, shared) << 16) |
                     ((uint32_t)barrier << 21);
    assert(plan->descriptor[const_word + 1] == group);
    if (device->ver >= 12) assert(plan->descriptor[2] & (1u << 20));
    assert(plan->disable_mid_thread_preemption == (device->ver >= 12));
    assert(plan->slm_bytes_per_group == intel_compute_slm_calculate_size(device->ver, shared));
    assert(plan->binding_table_entries == 1 && plan->cs_stall_before_vfe);
    assert(plan->vfe_words == (device->ver == 7 ? 8 : 9));
    unsigned vfe_thread_word = device->ver == 7 ? 2 : 3;
    assert((plan->vfe[vfe_thread_word] >> 16) ==
           device->max_cs_threads * device->subslice_total - 1);
    unsigned curbe_word = device->ver == 7 ? 4 : 5;
    assert((plan->vfe[curbe_word] & 65535) == (subgroup ? align(info.threads, 2) : 0));
    assert(plan->curbe_load[2] == plan->curbe_bytes && plan->curbe_load[3] == 0x4000);
    assert(plan->descriptor_load[2] == 32 && plan->descriptor_load[3] == 0x5000);
    uint32_t native[17] = {0};
    struct stela_intel_commands commands = {native, ARRAY_SIZE(native), 0, 48};
    assert(stela_intel_gpgpu_dispatch(&commands, &plan->dispatch) == 0);
    assert(plan->walker_words == commands.used && !memcmp(native, plan->walker, sizeof(native)));
    assert(!plan->scratch_bytes_per_thread && !plan->scratch_allocation_bytes);
}

static void brw(const char *platform, unsigned mode, unsigned width)
{
    struct intel_device_info device;
    int pci = intel_device_name_to_pci_device_id(platform);
    assert(pci >= 0 && intel_get_device_info_for_build(pci, &device));
    struct isl_device isl = {0}; isl_device_init(&isl, &device);
    void *context = ralloc_context(NULL);
    struct brw_compiler *compiler = brw_compiler_create(context, &device);
    compiler->shader_debug_log = compiler->shader_perf_log = compiler_log;
    nir_shader *nir = shader(&compiler->nir_options[MESA_SHADER_COMPUTE], mode);
    const struct brw_nir_compiler_opts options = {0};
    brw_preprocess_nir(compiler, nir, &options);
    const nir_lower_compute_system_values_options system_values = {.has_base_workgroup_id = false};
    NIR_PASS(_, nir, nir_lower_compute_system_values, &system_values);
    nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
    nir->info.min_subgroup_size = nir->info.max_subgroup_size = width;
    struct brw_cs_prog_data data = {0}; struct brw_cs_prog_key key = {0};
    brw_nir_lower_cs_intrinsics(nir, &device, &data);
    /* Exact retained Iris subgroup push setup, including the padded compiler
     * range after the true one-dword payload layout is calculated. */
    bool subgroup = brw_nir_lower_cs_subgroup_id(nir, &device, 0);
    if (subgroup) {
        data.base.push_sizes[0] = 4;
        brw_cs_fill_push_const_info(&device, &data, 0);
        data.base.push_sizes[0] = align(4, REG_SIZE);
    } else brw_cs_fill_push_const_info(&device, &data, -1);
    nir_validate_shader(nir, "legacy BRW compute program payload fixture");
    struct brw_compile_cs_params parameters = {
        .base = {.mem_ctx = context, .nir = nir, .key = &key.base, .prog_data = &data.base},
    };
    const unsigned *code = brw_compile(compiler, &parameters.base);
    assert(code && data.base.program_size && !parameters.base.error_str);
    unsigned sends;
    assert(validate_intel_code(&device, context, code, data.base.program_size, platform, &sends));
    assert(sends >= (mode == 1 ? 7u : 3u));
    assert(subgroup == (mode != 2) && data.uses_barrier == (mode == 1));
    assert(data.base.total_shared == (mode == 1 ? 132u : 0u));
    struct stela_intel_legacy_placement p = placement(data.base.program_size);
    const uint32_t groups[] = {19, 23, 29};
    struct stela_intel_legacy_plan plan, before;
    for (unsigned variable = 0; variable <= 4096; variable += 1024) {
        assert(stela_intel_legacy_brw_plan(compiler, &isl, &data, &nir->info, &p, groups, variable,
                                           &plan) == 0);
        struct intel_cs_dispatch_info dispatch = brw_cs_get_dispatch_info(&device, &data, NULL);
        check(&device, dispatch, subgroup, data.base.total_shared + variable, data.uses_barrier,
              p.code_offset + brw_cs_prog_data_prog_offset(&data, dispatch.simd_size), &plan);
    }
    memset(&before, 0xa5, sizeof(before));
    for (unsigned i = 0; i < 16; ++i) {
        struct stela_intel_legacy_placement bad = p;
        switch (i) {
        case 0: bad.code_offset++; break;
        case 1: bad.code_span--; break;
        case 2: bad.binding_table_offset++; break;
        case 3: bad.binding_table_span--; break;
        case 4: bad.curbe_offset++; break;
        case 5: bad.curbe_span = 0; break;
        case 6: bad.descriptor_span--; break;
        case 7: bad.descriptor_offset = bad.curbe_offset; break;
        case 8: bad.binding_table_entries++; break;
        case 9: bad.scratch_address = 1024; break;
        case 10: bad.curbe_offset = UINT32_MAX - 31; break;
        case 11: bad.descriptor_offset = UINT32_MAX; break;
        case 12: bad.binding_table_offset = device.ver >= 11 ? 0x80000 : 0x10000; break;
        case 13: bad.code_offset = UINT64_C(1) << 48; break;
        case 14: bad.binding_table_entries = 256; break;
        case 15: bad.code_offset = (UINT64_C(1) << 48) - 64; break;
        }
        plan = before;
        assert(stela_intel_legacy_brw_plan(compiler, &isl, &data, &nir->info, &bad, groups, 0,
                                           &plan) == -22);
        assert(!memcmp(&plan, &before, sizeof(plan)));
    }
    const struct {size_t offset; uint32_t value; int status;} cases[] = {
#define BAD(field, value, status) {offsetof(struct brw_cs_prog_data, field), value, status}
        BAD(base.stage, MESA_SHADER_FRAGMENT, -22), BAD(base.program_size, 0, -22),
        BAD(prog_mask, 0, -22), BAD(prog_mask, 8, -22), BAD(prog_spilled, 8, -22),
        BAD(local_size[0], 0, -95), BAD(local_size[1], 1025, -22),
        BAD(push.per_thread.dwords, 2, -95), BAD(push.cross_thread.regs, 1, -95),
        BAD(base.total_shared, UINT32_MAX, -22),
#undef BAD
    };
    for (unsigned i = 0; i < ARRAY_SIZE(cases); ++i) {
        struct brw_cs_prog_data bad = data;
        memcpy((char *)&bad + cases[i].offset, &cases[i].value, 4);
        plan = before;
        assert(stela_intel_legacy_brw_plan(compiler, &isl, &bad, &nir->info, &p, groups, 0,
                                           &plan) == cases[i].status);
        assert(!memcmp(&plan, &before, sizeof(plan)));
    }
    for (unsigned i = 0; i < 5; ++i) {
        struct shader_info bad_info = nir->info;
        switch (i) {
        case 0: bad_info.num_textures = 1; break;
        case 1: bad_info.samplers_used[0] = 1; break;
        case 2: bad_info.workgroup_size_variable = true; break;
        case 3: bad_info.num_ssbos = 2; break;
        case 4: bad_info.images_used[0] = 1; break;
        }
        plan = before;
        assert(stela_intel_legacy_brw_plan(compiler, &isl, &data, &bad_info, &p, groups, 0,
                                           &plan) == (i == 3 ? -22 : -95));
        assert(!memcmp(&plan, &before, sizeof(plan)));
    }
    /* Deliberately invalid metadata/placement pair: the whole table, not just
     * its encodable pointer, must fit the original 64/512 KiB binder window. */
    struct shader_info invalid_info = nir->info; invalid_info.num_ssbos = 255;
    struct stela_intel_legacy_placement invalid_table = p;
    invalid_table.binding_table_entries = 255;
    invalid_table.binding_table_span = 255 * 4;
    invalid_table.binding_table_offset = 0xffe0u << (device.ver >= 11 ? 3 : 0);
    plan = before;
    assert(stela_intel_legacy_brw_plan(compiler, &isl, &data, &invalid_info, &invalid_table,
                                      groups, 0, &plan) == -22);
    assert(!memcmp(&plan, &before, sizeof(plan)));
    struct brw_cs_prog_data bad = data;
    bad.push.cross_thread.size = 32;
    plan = before;
    assert(stela_intel_legacy_brw_plan(compiler, &isl, &bad, &nir->info, &p, groups, 0, &plan) ==
           -95);
    assert(!memcmp(&plan, &before, sizeof(plan)));
    bad = data; bad.base.total_scratch = 1024;
    assert(stela_intel_legacy_brw_plan(compiler, &isl, &bad, &nir->info, &p, groups, 0, &plan) ==
           -22);
    bad = data; bad.uses_sampler = true;
    assert(stela_intel_legacy_brw_plan(compiler, &isl, &bad, &nir->info, &p, groups, 0, &plan) ==
           -95);
    assert(stela_intel_legacy_brw_plan(compiler, &isl, &data, &nir->info, &p, groups, UINT32_MAX,
                                       &plan) == -22);
    assert(!memcmp(&plan, &before, sizeof(plan)));
    printf("Real BRW legacy %s mode=%u SIMD%u: code=%uB subgroup_push=%u, five plans/checked "
           "packets\n",
           platform, mode, width, data.base.program_size, subgroup);
    ralloc_free(nir); ralloc_free(context);
}

static void elk(const char *platform, unsigned mode, unsigned width)
{
    struct intel_device_info device;
    int pci = intel_device_name_to_pci_device_id(platform);
    assert(pci >= 0 && intel_get_device_info_for_build(pci, &device));
    struct isl_device isl = {0}; isl_device_init(&isl, &device);
    void *context = ralloc_context(NULL);
    struct elk_compiler *compiler = elk_compiler_create(context, &device);
    compiler->shader_debug_log = compiler->shader_perf_log = compiler_log;
    nir_shader *nir = shader(compiler->nir_options[MESA_SHADER_COMPUTE], mode);
    const struct elk_nir_compiler_opts options = {0};
    elk_preprocess_nir(compiler, nir, &options);
    const nir_lower_compute_system_values_options system_values = {.has_base_workgroup_id = false};
    NIR_PASS(_, nir, nir_lower_compute_system_values, &system_values);
    nir_shader_gather_info(nir, nir_shader_get_entrypoint(nir));
    nir->info.min_subgroup_size = nir->info.max_subgroup_size = width;
    struct elk_cs_prog_data data = {0}; struct elk_cs_prog_key key = {0};
    elk_nir_lower_cs_intrinsics(nir, &device, &data);
    nir_validate_shader(nir, "legacy ELK compute program payload fixture");
    struct elk_compile_cs_params parameters = {
        .base = {.mem_ctx = context, .nir = nir}, .key = &key, .prog_data = &data,
    };
    const unsigned *code = elk_compile_cs(compiler, &parameters);
    if (!code || parameters.base.error_str)
        fprintf(stderr, "%s mode=%u: %s\n", platform, mode,
                parameters.base.error_str ? parameters.base.error_str : "no compiled code");
    assert(code && data.base.program_size && !parameters.base.error_str);
    assert(stela_legacy_elk_code_valid(compiler, code, data.base.program_size));
    assert(data.uses_barrier == (mode == 1));
    assert(data.base.total_shared == (mode == 1 ? 132u : 0u));
    struct stela_intel_legacy_placement p = placement(data.base.program_size);
    const uint32_t groups[] = {19, 23, 29};
    struct stela_intel_legacy_plan plan, before;
    assert(stela_intel_legacy_elk_plan(compiler, &isl, &data, &nir->info, &p, groups, &plan) == 0);
    struct intel_cs_dispatch_info dispatch = elk_cs_get_dispatch_info(&device, &data, NULL);
    check(&device, dispatch, true, data.base.total_shared, data.uses_barrier,
          p.code_offset + elk_cs_prog_data_prog_offset(&data, dispatch.simd_size), &plan);
    memset(&before, 0xa5, sizeof(before)); plan = before;
    struct elk_cs_prog_data bad = data; bad.uses_num_work_groups = true;
    assert(stela_intel_legacy_elk_plan(compiler, &isl, &bad, &nir->info, &p, groups, &plan) == -95);
    assert(!memcmp(&plan, &before, sizeof(plan)));
    bad = data; bad.base.param = NULL;
    assert(stela_intel_legacy_elk_plan(compiler, &isl, &bad, &nir->info, &p, groups, &plan) == -95);
    bad = data; bad.base.total_scratch = 1024;
    assert(stela_intel_legacy_elk_plan(compiler, &isl, &bad, &nir->info, &p, groups, &plan) == -22);
    uint32_t bad_param = ELK_PARAM_BUILTIN_SUBGROUP_ID + 1;
    bad = data; bad.base.param = &bad_param;
    assert(stela_intel_legacy_elk_plan(compiler, &isl, &bad, &nir->info, &p, groups, &plan) == -95);
    const uint32_t zero_group[] = {1, 0, 1};
    assert(stela_intel_legacy_elk_plan(compiler, &isl, &data, &nir->info, &p, zero_group, &plan) ==
           -22);
    struct stela_intel_legacy_placement bad_placement = p;
    bad_placement.code_offset = device.ver == 7 ? (UINT64_C(1) << 32) - 64 :
                                                  (UINT64_C(1) << 48) - 64;
    assert(stela_intel_legacy_elk_plan(compiler, &isl, &data, &nir->info, &bad_placement, groups,
                                       &plan) == -22);
    assert(!memcmp(&plan, &before, sizeof(plan)));
    printf("Real ELK legacy %s mode=%u SIMD%u: code=%uB actual subgroup push, checked packets\n",
           platform, mode, width, data.base.program_size);
    ralloc_free(nir); ralloc_free(context);
}

int main(void)
{
    process_intel_debug_variable();
    glsl_type_singleton_init_or_ref();
    /* The legacy producer owns every platform before Gfx12.5's COMPUTE_WALKER. */
    const char *platform;
    struct intel_device_info info;
    STELA_INTEL_FOREACH_TARGET(platform, info) {
        if (info.verx10 >= 125)
            continue;
        const bool use_elk = stela_intel_elk(&info);
        for (unsigned mode = 0; mode < (use_elk ? 2 : 3); ++mode)
            for (unsigned width = 8; width <= 32; width *= 2)
                (use_elk ? elk : brw)(platform, mode, width);
    }
    glsl_type_singleton_decref();
    return 0;
}
