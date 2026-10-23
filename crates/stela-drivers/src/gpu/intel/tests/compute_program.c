/* SPDX-License-Identifier: MIT */
#include "../hosted/compute.h"
#include "compiler/tests/intel_probe.h"
#include "compiler/tests/targets/intel.h"
#include "intel/common/intel_common.h"
#include "intel/common/intel_compute_slm.h"
#include "intel/compiler/brw/brw_nir.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static void compiler_log(void *data, unsigned *id, const char *format, ...)
{
    (void)data; (void)id;
    va_list arguments; va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
}

static void check_plan(const struct brw_compiler *compiler, const struct isl_device *isl,
                       const struct brw_cs_prog_data *program, const struct shader_info *shader)
{
    const struct intel_device_info *device = isl->info;
    const uint32_t groups[] = {19, 23, 29};
    /* Static compile/model placements only. No GPU mappings are established. */
    struct stela_intel_compute_placement placement = {
        .code_offset = 0x1000, .code_span = program->base.program_size,
        .binding_table_offset = 0x2000, .binding_table_entries = 1, .binding_table_span = 4,
    };
    for (uint32_t variable_slm = 0; variable_slm <= 4096; variable_slm += 1024) {
        struct stela_intel_compute_plan plan;
        assert(stela_intel_compute_plan(compiler, isl, program, shader, &placement, groups,
                   variable_slm, &plan) == 0);
        struct intel_cs_dispatch_info info = brw_cs_get_dispatch_info(device, program, NULL);
        uint32_t slm = program->base.total_shared + variable_slm;
        assert(plan.dispatch.gfx_verx10 == device->verx10);
        assert(!memcmp(plan.dispatch.local_size, program->local_size, sizeof(program->local_size)));
        assert(!memcmp(plan.dispatch.groups, groups, sizeof(groups)));
        assert(plan.dispatch.simd_size == info.simd_size && plan.dispatch.threads == info.threads);
        assert(plan.dispatch.right_mask == info.right_mask);
        assert(plan.dispatch.kernel_offset ==
            placement.code_offset + brw_cs_prog_data_prog_offset(program, info.simd_size));
        assert(plan.dispatch.binding_table_offset == placement.binding_table_offset);
        assert(!plan.dispatch.binding_table_entry_count && !plan.dispatch.sampler_count);
        assert(plan.dispatch.slm_encoding == intel_compute_slm_encode_size(device->ver, slm));
        assert(plan.dispatch.preferred_slm_encoding ==
            intel_compute_preferred_slm_calc_encode_size(device, slm, info.group_size,
                info.simd_size));
        assert(plan.dispatch.barrier_encoding == program->uses_barrier);
        assert(plan.dispatch.thread_group_dispatch_size ==
            (uint32_t)intel_compute_threads_group_dispatch_size(info.threads));
        assert(plan.dispatch.register_blocks ==
            (device->ver >= 30 ? ptl_register_blocks(program->base.grf_used) : 0));
        assert(plan.dispatch.generate_local_id == program->generate_local_id);
        assert(plan.dispatch.walk_order == (uint32_t)program->walk_order);
        assert(plan.dispatch.post_sync_mocs == isl_mocs(isl, 0, false));
        assert(!plan.dispatch.push_bytes && !brw_cs_push_const_total_size(program, info.threads));
        assert(plan.requirements.scratch_bytes_per_thread == program->base.total_scratch);
        assert(plan.requirements.slm_bytes_per_group ==
            intel_compute_slm_calculate_size(device->ver, slm));
        assert(plan.requirements.cfe_max_threads ==
            device->max_cs_threads * device->subslice_total);
        assert(plan.requirements.binding_table_entries == 1);
        assert(plan.requirements.apply_async_thread_limits == (device->verx10 < 300));
        uint8_t pixel, z_pass, np_z;
        intel_compute_engine_async_threads_limit(device, info.threads,
            slm != 0 || program->uses_barrier, program->uses_fence, &pixel, &z_pass, &np_z);
        assert(plan.requirements.pixel_async_thread_limit == pixel);
        assert(plan.requirements.z_pass_async_thread_limit == z_pass);
        assert(plan.requirements.np_z_async_throttle == np_z);
        uint32_t words[44]; memset(words, 0xa5, sizeof(words));
        struct stela_intel_commands commands = {words, 44, 1, 48};
        assert(stela_intel_compute_dispatch(&commands, &plan.dispatch) == 0);
        assert(commands.used == (device->verx10 == 125 ? 40 : 41));
        assert(words[0] == 0xa5a5a5a5 && words[commands.used] == 0xa5a5a5a5);
        assert(words[device->verx10 == 125 ? 19 : 20] == plan.dispatch.kernel_offset);
    }
    struct stela_intel_compute_plan plan, before;
    memset(&before, 0xa5, sizeof(before));
    const struct {size_t offset; uint32_t value; int status;} cases[] = {
#define BAD(field, value, status) {offsetof(struct brw_cs_prog_data, field), value, status}
        BAD(base.stage, MESA_SHADER_FRAGMENT, -22), BAD(base.program_size, 0, -22),
        BAD(prog_mask, 0, -22), BAD(prog_mask, 8, -22), BAD(prog_spilled, 8, -22),
        BAD(base.grf_used, 0, -22), BAD(local_size[0], 0, -95),
        BAD(local_size[1], 1025, -22), BAD(local_size[2], 1024, -22),
        BAD(push.per_thread.size, 1, -22), BAD(push.cross_thread.size, 1, -22),
        BAD(push.per_thread.size, 32, -95), BAD(push.cross_thread.size, 32, -95),
        BAD(base.ray_queries, 1, -95), BAD(base.total_shared, UINT32_MAX, -22),
#undef BAD
    };
    for (unsigned i = 0; i < ARRAY_SIZE(cases); ++i) {
        struct brw_cs_prog_data bad = *program;
        memcpy((char *)&bad + cases[i].offset, &cases[i].value, 4);
        plan = before;
        assert(stela_intel_compute_plan(compiler, isl, &bad, shader, &placement, groups, 0,
                   &plan) == cases[i].status);
        assert(!memcmp(&plan, &before, sizeof(plan)));
    }
    for (unsigned i = 0; i < 9; ++i) {
        struct stela_intel_compute_placement bad = placement;
        switch (i) {
        case 0: bad.code_offset++; break;
        case 1: bad.code_offset = UINT64_C(1) << 32; break;
        case 2: bad.code_offset = UINT32_MAX - 63; break;
        case 3: bad.code_span--; break;
        case 4: bad.binding_table_offset++; break;
        case 5: bad.binding_table_offset = 0x200000; break;
        case 6: bad.binding_table_entries = 257; break;
        case 7: bad.binding_table_span--; break;
        case 8: bad.binding_table_entries = UINT32_MAX; break;
        }
        plan = before;
        assert(stela_intel_compute_plan(compiler, isl, program, shader, &bad, groups, 0, &plan) ==
            -22);
        assert(!memcmp(&plan, &before, sizeof(plan)));
    }
    struct brw_cs_prog_data bad = *program;
    bad.uses_sampler = true;
    assert(stela_intel_compute_plan(compiler, isl, &bad, shader, &placement, groups, 0, &plan) ==
        -95);
    bad = *program; bad.uses_btd_stack_ids = true;
    assert(stela_intel_compute_plan(compiler, isl, &bad, shader, &placement, groups, 0, &plan) ==
        -95);
    bad = *program; bad.base.push_sizes[0] = 32;
    assert(stela_intel_compute_plan(compiler, isl, &bad, shader, &placement, groups, 0, &plan) ==
        -95);
    bad = *program;
    unsigned selected = brw_cs_get_dispatch_info(device, program, NULL).simd_size / 16;
    bad.prog_offset[selected] = 1;
    assert(stela_intel_compute_plan(compiler, isl, &bad, shader, &placement, groups, 0, &plan) ==
        -22);
    assert(stela_intel_compute_plan(compiler, isl, program, shader, &placement, groups, UINT32_MAX,
               &plan) == -22);
    struct intel_device_info held = *device; held.verx10 = 350; held.ver = 35;
    struct isl_device held_isl = *isl; held_isl.info = &held;
    struct brw_compiler held_compiler = *compiler; held_compiler.devinfo = &held;
    assert(stela_intel_compute_plan(&held_compiler, &held_isl, program, shader, &placement, groups,
               0, &plan) == -95);
    assert(stela_intel_compute_plan(&held_compiler, isl, program, shader, &placement, groups, 0,
               &plan) == -22);
    assert(stela_intel_compute_plan(NULL, isl, program, shader, &placement, groups, 0, &plan) ==
        -22);
}

static void compile_program(const char *platform, bool barrier)
{
    struct intel_device_info device;
    int pci = intel_device_name_to_pci_device_id(platform);
    assert(pci >= 0 && intel_get_device_info_for_build(pci, &device));
    struct isl_device isl = {0}; isl_device_init(&isl, &device);
    void *context = ralloc_context(NULL);
    struct brw_compiler *compiler = brw_compiler_create(context, &device);
    assert(compiler);
    compiler->shader_debug_log = compiler_log;
    compiler->shader_perf_log = compiler_log;
    nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE,
        &compiler->nir_options[MESA_SHADER_COMPUTE], "stela_compute_program_fixture");
    b.shader->info.workgroup_size[0] = 32;
    b.shader->info.workgroup_size[1] = b.shader->info.workgroup_size[2] = 1;
    /* Compile fixture VA only. No production resource mapping is established. */
    nir_def *address = nir_iadd(&b, nir_imm_int64(&b, 0x100000),
        nir_ishl_imm(&b, nir_u2u64(&b, nir_channel(&b, nir_load_global_invocation_id(&b, 32), 0)),
            2));
    nir_def *input = nir_load_global(&b, 1, 32, address, .align_mul = 4);
    if (barrier)
        nir_barrier(&b, .execution_scope = SCOPE_WORKGROUP, .memory_scope = SCOPE_WORKGROUP,
                     .memory_semantics = NIR_MEMORY_ACQ_REL, .memory_modes = nir_var_mem_global);
    nir_store_global(&b, nir_iadd_imm(&b, input, 1), address, .align_mul = 4);
    const struct brw_nir_compiler_opts options = {0};
    brw_preprocess_nir(compiler, b.shader, &options);
    /* This packet API starts at grid origin zero. Use NIR's original system
     * value lowering for that explicit API contract, including real IDs. */
    const nir_lower_compute_system_values_options system_values = {.has_base_workgroup_id = false};
    NIR_PASS(_, b.shader, nir_lower_compute_system_values, &system_values);
    nir_shader_gather_info(b.shader, nir_shader_get_entrypoint(b.shader));
    b.shader->info.min_subgroup_size = b.shader->info.max_subgroup_size = 16;
    struct brw_cs_prog_key key = {0}; struct brw_cs_prog_data data = {0};
    brw_nir_lower_cs_intrinsics(b.shader, &device, &data);
    brw_cs_fill_push_const_info(&device, &data, -1);
    nir_validate_shader(b.shader, "actual BRW program to native walker fixture");
    struct brw_compile_cs_params parameters = {
        .base = {.mem_ctx = context, .nir = b.shader, .key = &key.base, .prog_data = &data.base},
    };
    const unsigned *code = brw_compile(compiler, &parameters.base);
    assert(code && data.base.program_size && !parameters.base.error_str);
    unsigned sends;
    assert(validate_intel_code(&device, context, code, data.base.program_size, platform, &sends));
    assert(data.uses_barrier == barrier);
    check_plan(compiler, &isl, &data, &b.shader->info);
    printf("Actual BRW program->hosted policy->native walker %s barrier=%u: %u bytes, validated\n",
           platform, barrier, data.base.program_size);
    ralloc_free(b.shader); ralloc_free(context);
}

int main(void)
{
    glsl_type_singleton_init_or_ref();
    /* The COMPUTE_WALKER producer owns Gfx12.5 onward, except held platforms. */
    const char *platform;
    struct intel_device_info info;
    STELA_INTEL_FOREACH_TARGET(platform, info) {
        if (info.verx10 < 125 || stela_intel_hold(&info))
            continue;
        compile_program(platform, false);
        compile_program(platform, true);
    }
    glsl_type_singleton_decref();
    return 0;
}
