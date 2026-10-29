/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_FP_CONTROLS_H
#define STELA_INTEL_HOSTED_FP_CONTROLS_H
#include "compiler/shader_info.h"
#include "intel/dev/intel_device_info.h"

/* Qualification at the owned pipeline boundary, not a second control mapper.
 * Original BRW/ELK consume these NIR flags and emit their own CR0 instructions.
 * A floating-point shader cannot inherit unspecified context rounding/denorm
 * state. Only the explicitly tested FP32 RTE preserve/FTZ modes are admitted.
 * NIR's bit_sizes_float is the OR of used ALU bit sizes (16/32/64).
 */
static inline int stela_intel_fp_controls(const struct intel_device_info *device,
                                         const struct shader_info *info)
{
    if (!device || !info)
        return -22;
    if (info->bit_sizes_float & ~32u)
        return -95;
    const uint32_t mode = info->float_controls_execution_mode;
    if (!info->bit_sizes_float && mode == FLOAT_CONTROLS_DEFAULT_FLOAT_CONTROL_MODE)
        return 0;
    /* Retained vulkan_hasvk/anv_device.c: FP32 preserve starts at Gen8;
     * FTZ and RTE are supported on Gen7+. Legal compiler output alone does
     * not qualify the unsupported Gen7 preserve hardware behavior. */
    if (mode == (FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32 | FLOAT_CONTROLS_DENORM_PRESERVE_FP32))
        return device->ver >= 8 ? 0 : -95;
    if (mode == (FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32 | FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32) &&
        device->ver >= 7)
        return 0;
    return -95;
}
#endif
