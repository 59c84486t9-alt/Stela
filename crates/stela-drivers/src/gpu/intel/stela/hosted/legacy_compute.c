/*
 * Copyright © 2017 Intel Corporation
 * SPDX-License-Identifier: MIT
 * Subgroup payload/state policy adapted from retained Iris/Crocus. Original
 * compiler dispatch, push-size and Intel SLM policy functions are called.
 */
#include "legacy_compute_internal.h"
#include "intel/common/intel_compute_slm.h"
#include "util/u_math.h"
#include <string.h>

static int validate_program(const struct intel_device_info *device, mesa_shader_stage stage,
                            const struct shader_info *info, const unsigned local_size[3],
                            uint32_t program_bytes, uint32_t mask, uint32_t spilled,
                            const unsigned offsets[3])
{
    if (!info || stage != MESA_SHADER_COMPUTE || info->stage != stage || !program_bytes ||
        !mask || (mask & ~7u) || (spilled & ~mask) || !device->slice_masks ||
        !device->subslice_total || !device->max_cs_threads || !device->max_cs_workgroup_threads)
        return -22;
    if (info->workgroup_size_variable)
        return -95;
    uint64_t size = 1;
    for (unsigned i = 0; i < 3; ++i) {
        if (!local_size[i]) return -95;
        if (local_size[i] != info->workgroup_size[i] || local_size[i] > 1024)
            return -22;
        size *= local_size[i];
        if ((mask & (1u << i)) && ((offsets[i] & 63) || offsets[i] >= program_bytes))
            return -22;
    }
    if (size > 1024)
        return -22;
    /* ELK has no uses_sampler flag. Preserve actual shader resource metadata
     * rather than assuming absent sampler state means no sampler instructions.
     * Binding table is an explicit SSBO-only prefix for this bounded adapter.
     */
    if (info->num_textures || info->num_images || info->num_ubos || info->num_abos)
        return -95;
    for (unsigned i = 0; i < ARRAY_SIZE(info->textures_used); ++i)
        if (info->textures_used[i]) return -95;
    for (unsigned i = 0; i < ARRAY_SIZE(info->samplers_used); ++i)
        if (info->samplers_used[i]) return -95;
    for (unsigned i = 0; i < ARRAY_SIZE(info->images_used); ++i)
        if (info->images_used[i]) return -95;
    return 0;
}

static int build_plan(const struct intel_device_info *device, const struct shader_info *shader,
                       const struct intel_cs_dispatch_info *dispatch,
                       uint32_t program_bytes, uint32_t variant_offset,
                       uint32_t push_bytes, bool subgroup_payload,
                       uint32_t scratch_bytes, uint64_t shared_bytes, bool barrier,
                       const struct stela_intel_legacy_placement *placement,
                       const uint32_t groups[3], struct stela_intel_legacy_plan *output)
{
    if (!placement || !groups || !output || !groups[0] || !groups[1] || !groups[2] ||
        !dispatch->threads || dispatch->threads > device->max_cs_workgroup_threads ||
        dispatch->threads > 64 ||
        (dispatch->simd_size != 8 && dispatch->simd_size != 16 && dispatch->simd_size != 32))
        return -22;
    unsigned table_shift = device->ver >= 11 ? 3 : 0;
    uint64_t code_limit = UINT64_C(1) << (device->ver == 7 ? 32 : 48);
    uint32_t bt_alignment = 32u << table_shift;
    uint32_t payload_bytes = push_bytes ? align(push_bytes, 64) : 64;
    if ((placement->code_offset & 63) || placement->code_offset >= code_limit ||
        program_bytes > code_limit - placement->code_offset ||
        placement->code_span < program_bytes ||
        (placement->binding_table_offset & (bt_alignment - 1)) ||
        placement->binding_table_offset > (0xffe0u << table_shift) ||
        placement->binding_table_entries != shader->num_ssbos ||
        placement->binding_table_span < (uint64_t)placement->binding_table_entries * 4 ||
        (uint64_t)placement->binding_table_entries * 4 >
            (0x10000u << table_shift) - placement->binding_table_offset ||
        (placement->curbe_offset & 63) || (placement->descriptor_offset & 63) ||
        payload_bytes > sizeof(output->curbe) || placement->curbe_span < payload_bytes ||
        payload_bytes > (UINT64_C(1) << 32) - placement->curbe_offset ||
        placement->descriptor_span < sizeof(output->descriptor) ||
        sizeof(output->descriptor) > (UINT64_C(1) << 32) - placement->descriptor_offset ||
        ((uint64_t)placement->curbe_offset < (uint64_t)placement->descriptor_offset + 32 &&
         (uint64_t)placement->descriptor_offset < (uint64_t)placement->curbe_offset + payload_bytes))
        return -22;
    uint32_t max_slm = intel_device_info_get_max_slm_size(device);
    if (shared_bytes > max_slm || shared_bytes > 64 * 1024)
        return -22;
    uint32_t slm = intel_compute_slm_calculate_size(device->ver, (uint32_t)shared_bytes);
    if (slm > max_slm)
        return -22;
    uint64_t max_threads = (uint64_t)device->max_cs_threads * device->subslice_total;
    if (!max_threads || max_threads > 65536)
        return -22;
    uint32_t scratch_encoding = 0;
    uint64_t scratch_span = (uint64_t)scratch_bytes * device->max_scratch_ids[MESA_SHADER_COMPUTE];
    if (scratch_bytes) {
        if (!device->max_scratch_ids[MESA_SHADER_COMPUTE] ||
            (placement->scratch_address & 1023) || !placement->scratch_address ||
            placement->scratch_address >= (UINT64_C(1) << 32) ||
            scratch_span > (UINT64_C(1) << 32) - placement->scratch_address ||
            placement->scratch_span < scratch_span)
            return -22;
        /* Original Crocus Gen7/7.5 and Iris Gen8+ scratch encodings. The
         * initialized owner's max_scratch_ids includes sparse ID workarounds.
         * Iris scratch placement is in its 32-bit shader memory zone.
         */
        if (device->verx10 == 70) {
            if (scratch_bytes % 1024 || scratch_bytes > 12 * 1024) return -22;
            scratch_encoding = scratch_bytes / 1024 - 1;
        } else {
            uint32_t minimum = device->verx10 == 75 ? 2048 : 1024;
            if (scratch_bytes < minimum || scratch_bytes > 2 * 1024 * 1024 ||
                !util_is_power_of_two_nonzero(scratch_bytes))
                return -22;
            scratch_encoding = ffs(scratch_bytes) - (device->verx10 == 75 ? 12 : 11);
        }
    } else if (placement->scratch_address || placement->scratch_span) {
        return -22;
    }
    struct stela_intel_legacy_plan plan = {
        .dispatch = {
            .gfx_verx10 = device->verx10, .group_size = dispatch->group_size,
            .simd_size = dispatch->simd_size, .threads = dispatch->threads,
            .right_mask = dispatch->right_mask,
            .groups = {groups[0], groups[1], groups[2]},
        },
        .curbe_bytes = payload_bytes,
        .scratch_bytes_per_thread = scratch_bytes, .scratch_allocation_bytes = scratch_span,
        .slm_bytes_per_group = slm, .binding_table_entries = placement->binding_table_entries,
        .cs_stall_before_vfe = true, .disable_mid_thread_preemption = device->ver >= 12,
    };
    /* Original Iris/Crocus debug fill and subgroup payload layout: each
     * hardware thread consumes one 32-byte GRF whose first dword is its ID.
     * With no compiled push payload, Iris still loads a 64-byte unused block.
     */
    memset(plan.curbe, 0x5a, payload_bytes);
    if (subgroup_payload)
        for (unsigned t = 0; t < dispatch->threads; t++)
            plan.curbe[8 * t] = t;
    struct stela_intel_legacy_state state = {
        .kernel_offset = placement->code_offset + variant_offset,
        .max_threads = (uint32_t)max_threads, .scratch_encoding = scratch_encoding,
        .curbe_regs = align(push_bytes / 32, 2),
        .per_thread_regs = subgroup_payload ? 1 : 0, .cross_thread_regs = 0,
        .slm_encoding = intel_compute_slm_encode_size(device->ver, (uint32_t)shared_bytes),
        .uses_barrier = barrier,
    };
    switch (device->verx10) {
#define PACK(ver) case ver: stela_intel_legacy_pack_##ver(&state, placement, &plan); break
    PACK(70); PACK(75); PACK(80); PACK(90); PACK(110); PACK(120);
#undef PACK
    default: return -95;
    }
    struct stela_intel_commands commands = {plan.walker, ARRAY_SIZE(plan.walker), 0, 48};
    int status = stela_intel_gpgpu_dispatch(&commands, &plan.dispatch);
    if (status) return status;
    plan.walker_words = commands.used;
    *output = plan;
    return 0;
}

int stela_intel_legacy_brw_plan(const struct brw_compiler *compiler, const struct isl_device *isl,
                               const struct brw_cs_prog_data *program, const struct shader_info *shader,
                               const struct stela_intel_legacy_placement *placement,
                               const uint32_t groups[3], uint32_t variable_slm_bytes,
                               struct stela_intel_legacy_plan *output)
{
    if (!compiler || !isl || !isl->info || compiler->devinfo != isl->info || !program ||
        !isl->buffer_fill_state_s || !isl->max_buffer_size)
        return -22;
    const struct intel_device_info *device = isl->info;
    if (device->verx10 != 90 && device->verx10 != 110 && device->verx10 != 120)
        return -95;
    int status = validate_program(device, program->base.stage, shader, program->local_size,
        program->base.program_size, program->prog_mask, program->prog_spilled, program->prog_offset);
    if (status) return status;
    if (program->uses_sampler || program->uses_btd_stack_ids || program->base.ray_queries ||
        program->uses_systolic || program->generate_local_id)
        return -95;
    bool subgroup = program->push.per_thread.dwords == 1;
    if (program->push.cross_thread.dwords || program->push.cross_thread.regs ||
        program->push.cross_thread.size ||
        program->push.per_thread.dwords > 1 ||
        program->push.per_thread.regs != (unsigned)subgroup ||
        program->push.per_thread.size != (subgroup ? 32u : 0u) ||
        program->base.push_sizes[0] != (subgroup ? 32u : 0u))
        return -95;
    for (unsigned i = 1; i < ARRAY_SIZE(program->base.push_sizes); ++i)
        if (program->base.push_sizes[i]) return -95;
    struct intel_cs_dispatch_info dispatch = brw_cs_get_dispatch_info(device, program, NULL);
    return build_plan(device, shader, &dispatch, program->base.program_size,
        brw_cs_prog_data_prog_offset(program, dispatch.simd_size),
        brw_cs_push_const_total_size(program, dispatch.threads), subgroup,
        program->base.total_scratch, (uint64_t)program->base.total_shared + variable_slm_bytes,
        program->uses_barrier, placement, groups, output);
}

int stela_intel_legacy_elk_plan(const struct elk_compiler *compiler, const struct isl_device *isl,
                               const struct elk_cs_prog_data *program, const struct shader_info *shader,
                               const struct stela_intel_legacy_placement *placement,
                               const uint32_t groups[3], struct stela_intel_legacy_plan *output)
{
    if (!compiler || !isl || !isl->info || compiler->devinfo != isl->info || !program ||
        !isl->buffer_fill_state_s || !isl->max_buffer_size)
        return -22;
    const struct intel_device_info *device = isl->info;
    if (device->verx10 != 70 && device->verx10 != 75 && device->verx10 != 80)
        return -95;
    int status = validate_program(device, program->base.stage, shader, program->local_size,
        program->base.program_size, program->prog_mask, program->prog_spilled, program->prog_offset);
    if (status) return status;
    if (program->uses_num_work_groups || program->base.has_ubo_pull || program->base.use_alt_mode ||
        program->base.zero_push_reg || program->base.nr_params != 1 || !program->base.param ||
        program->base.param[0] != ELK_PARAM_BUILTIN_SUBGROUP_ID ||
        program->push.cross_thread.dwords || program->push.cross_thread.regs ||
        program->push.cross_thread.size || program->push.per_thread.dwords != 1 ||
        program->push.per_thread.regs != 1 || program->push.per_thread.size != 32)
        return -95;
    struct intel_cs_dispatch_info dispatch = elk_cs_get_dispatch_info(device, program, NULL);
    return build_plan(device, shader, &dispatch, program->base.program_size,
        elk_cs_prog_data_prog_offset(program, dispatch.simd_size),
        elk_cs_push_const_total_size(program, dispatch.threads), true,
        program->base.total_scratch, program->base.total_shared,
        program->uses_barrier, placement, groups, output);
}
