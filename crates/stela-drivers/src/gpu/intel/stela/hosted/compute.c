/* SPDX-License-Identifier: MIT */
#include "compute.h"
#include "intel/common/intel_common.h"
#include "intel/common/intel_compute_slm.h"
#include "intel/compiler/brw/brw_reg.h"
#include "intel/compiler/intel_gfx_ver_enum.h"

int stela_intel_compute_plan(const struct brw_compiler *compiler, const struct isl_device *isl,
                             const struct brw_cs_prog_data *program,
                             const struct stela_intel_compute_placement *placement,
                             const uint32_t groups[3], uint32_t variable_slm_bytes,
                             struct stela_intel_compute_plan *output)
{
    if (!compiler || !isl || !isl->info || compiler->devinfo != isl->info ||
        !program || !placement || !groups || !output ||
        !isl->buffer_fill_state_s || !isl->max_buffer_size)
        return -22;
    const struct intel_device_info *device = isl->info;
    switch (device->verx10) {
    case 125: case 200: case 300: break;
    default: return -95; /* Includes the retained Gen35 qualification hold. */
    }
    if (!device->slice_masks || !device->subslice_total || !device->num_thread_per_eu ||
        !device->max_cs_threads || !device->max_cs_workgroup_threads ||
        program->base.stage != MESA_SHADER_COMPUTE || !program->base.program_size ||
        !program->prog_mask || (program->prog_mask & ~7u) ||
        (program->prog_spilled & ~program->prog_mask) ||
        !program->base.grf_used)
        return -22;
    if (program->uses_sampler || program->uses_btd_stack_ids || program->base.ray_queries)
        return -95;
    if (intel_use_jay(device, MESA_SHADER_COMPUTE) &&
        (program->prog_mask & (program->prog_mask - 1)))
        return -22;
    uint64_t group_size = 1;
    for (unsigned i = 0; i < 3; ++i) {
        if (!program->local_size[i])
            return -95; /* Variable workgroups need their real specialization. */
        if (program->local_size[i] > 1024 || !groups[i])
            return -22;
        group_size *= program->local_size[i];
        if ((program->prog_mask & (1u << i)) &&
            ((program->prog_offset[i] & 63) || program->prog_offset[i] >= program->base.program_size))
            return -22;
    }
    if (group_size > 1024 || (placement->code_offset & 63) ||
        placement->code_offset > UINT32_MAX || placement->code_span < program->base.program_size ||
        program->base.program_size > (UINT64_C(1) << 32) - placement->code_offset ||
        (placement->binding_table_offset & 31) || placement->binding_table_offset > 0x1fffe0 ||
        placement->binding_table_entries > 256 ||
        placement->binding_table_span < (uint64_t)placement->binding_table_entries * 4)
        return -22;
    if ((program->push.per_thread.size % REG_SIZE) || (program->push.cross_thread.size % REG_SIZE))
        return -22;
    /* This path has no inline/indirect payload. Do not hide another actual
     * compiled push range merely because the aggregate block was absent. */
    if (program->push.per_thread.size || program->push.cross_thread.size)
        return -95;
    for (unsigned i = 0; i < ARRAY_SIZE(program->base.push_sizes); ++i)
        if (program->base.push_sizes[i])
            return -95;
    uint64_t shared = (uint64_t)program->base.total_shared + variable_slm_bytes;
    uint32_t max_slm = intel_device_info_get_max_slm_size(device);
    if (shared > max_slm)
        return -22;
    uint32_t allocated_slm = intel_compute_slm_calculate_size(device->ver, (uint32_t)shared);
    if (allocated_slm > max_slm || allocated_slm > intel_device_info_get_max_preferred_slm_size(device))
        return -22;
    struct intel_cs_dispatch_info info = brw_cs_get_dispatch_info(device, program, NULL);
    if (!info.threads || info.threads > device->max_cs_workgroup_threads ||
        (device->verx10 >= 200 && info.simd_size == 8))
        return -22;
    uint64_t cfe_threads = (uint64_t)device->max_cs_threads * device->subslice_total;
    uint64_t invocations_per_ss = (uint64_t)intel_device_info_get_eu_count_first_subslice(device) *
                                  device->num_thread_per_eu * info.simd_size;
    if (cfe_threads > UINT32_MAX || invocations_per_ss < group_size ||
        invocations_per_ss > UINT32_MAX ||
        (invocations_per_ss / group_size) * shared > UINT32_MAX)
        return -22;
    uint32_t offset = brw_cs_prog_data_prog_offset(program, info.simd_size);
    struct stela_intel_compute_plan plan = {
        .dispatch = {
            .gfx_verx10 = device->verx10,
            .local_size = {program->local_size[0], program->local_size[1], program->local_size[2]},
            .simd_size = info.simd_size, .threads = info.threads, .right_mask = info.right_mask,
            .groups = {groups[0], groups[1], groups[2]},
            .kernel_offset = (uint32_t)(placement->code_offset + offset),
            .binding_table_offset = placement->binding_table_offset,
            .binding_table_entry_count = 0, /* Original Iris default: no forced prefetch. */
            .slm_encoding = intel_compute_slm_encode_size(device->ver, (uint32_t)shared),
            .preferred_slm_encoding = intel_compute_preferred_slm_calc_encode_size(
                device, (uint32_t)shared, info.group_size, (uint8_t)info.simd_size),
            .barrier_encoding = program->uses_barrier,
            .thread_group_dispatch_size = (uint32_t)intel_compute_threads_group_dispatch_size(info.threads),
            .register_blocks = device->ver >= 30 ? ptl_register_blocks(program->base.grf_used) : 0,
            .generate_local_id = program->generate_local_id,
            .walk_order = program->walk_order,
            .uses_sampler = program->uses_sampler,
            .post_sync_mocs = isl_mocs(isl, 0, false),
            .push_bytes = brw_cs_push_const_total_size(program, info.threads),
        },
        .requirements = {
            .scratch_bytes_per_thread = program->base.total_scratch,
            .slm_bytes_per_group = allocated_slm,
            .cfe_max_threads = (uint32_t)cfe_threads,
            .binding_table_entries = placement->binding_table_entries,
            .apply_async_thread_limits = device->verx10 < 300,
        },
    };
    uint8_t pixel, z_pass, np_z;
    intel_compute_engine_async_threads_limit(device, info.threads,
                                             shared != 0 || program->uses_barrier,
                                             program->uses_fence, &pixel, &z_pass, &np_z);
    plan.requirements.pixel_async_thread_limit = pixel;
    plan.requirements.z_pass_async_thread_limit = z_pass;
    plan.requirements.np_z_async_throttle = np_z;
    if (!plan.dispatch.post_sync_mocs || plan.dispatch.post_sync_mocs > 127)
        return -22;
    *output = plan;
    return 0;
}
