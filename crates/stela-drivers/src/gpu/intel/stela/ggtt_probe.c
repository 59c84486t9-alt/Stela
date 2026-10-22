/* SPDX-License-Identifier: MIT */
#include "ggtt_probe.h"
#include <linux/sizes.h>
#include <linux/types.h>
#include "xe_platform_types.h"
/* Normal Make extracts only original scalar defines from retained headers;
 * no duplicated hardware constants, Linux service shim or custom allocator. */
#include "ggtt_probe_defs.h"
#include "regs/xe_gtt_defs.h"
#include "xe_device_types.h"
#include "xe_wopcm.h"
static void invariant(void *context, bool condition)
{
    (void)context;
    if (!condition) __builtin_trap();
}
#define XE_GGTT_PROBE_ASSERT(context, condition) invariant(context, condition)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#include "xe_ggtt_probe_core.h"
#pragma clang diagnostic pop
int stela_intel_gsm_config(uint32_t graphics_verx100, uint16_t *offset)
{
    if (!offset || !graphics_verx100) return -22;
    if (xe_ggtt_probe_fixed_gsm(graphics_verx100)) return 1;
    *offset = SNB_GMCH_CTRL;
    return 0;
}
int stela_intel_gsm_geometry(uint32_t platform, uint32_t graphics_verx100, bool discrete,
    uint64_t actual_bar_bytes, bool config_present, uint16_t gmch_control,
    struct stela_intel_gsm_geometry *out)
{
    if (!out || !platform || platform > INT32_MAX || !graphics_verx100) return -22;
    unsigned int gsm_size;
    if (xe_ggtt_probe_fixed_gsm(graphics_verx100))
        gsm_size = SZ_8M;
    else {
        if (!config_present) return -95;
        gsm_size = xe_ggtt_probe_gsm_decode(gmch_control);
    }
    if (!gsm_size) return -12; /* Original no-preallocated-GSM refusal. */
    uint64_t offset = xe_ggtt_probe_gsm_offset();
    if (offset > actual_bar_bytes || gsm_size > actual_bar_bytes - offset) return -34;
    struct xe_device xe = {.info = {.platform = (enum xe_platform)platform, .is_dgfx = discrete}};
    uint64_t wopcm = xe_wopcm_size(&xe);
    if ((gsm_size / 8) * (uint64_t)XE_PAGE_SIZE <= wopcm) return -34;
    struct stela_intel_gsm_geometry result = {.gsm_offset = offset, .gsm_bytes = gsm_size};
    xe_ggtt_probe_pf_range(gsm_size, wopcm, &result.ggtt_start, &result.ggtt_bytes);
    xe_ggtt_probe_clamp_range(result.ggtt_start, &result.ggtt_bytes);
    *out = result;
    return 0;
}
int stela_intel_gsm_pte_offset(const struct stela_intel_gsm_geometry *geometry,
                              uint64_t address, size_t *out)
{
    if (!geometry || !out || !geometry->gsm_bytes || geometry->gsm_bytes % sizeof(uint64_t) ||
        geometry->gsm_bytes > PTRDIFF_MAX || !geometry->ggtt_bytes ||
        geometry->ggtt_start > GUC_GGTT_TOP ||
        geometry->ggtt_bytes > GUC_GGTT_TOP - geometry->ggtt_start ||
        (address & XE_PTE_MASK) || address >= geometry->ggtt_start + geometry->ggtt_bytes)
        return -22;
    uint64_t index = xe_ggtt_probe_pte_index(NULL, geometry->ggtt_start, geometry->ggtt_bytes, address);
    if (index >= geometry->gsm_bytes / sizeof(uint64_t)) return -34;
    *out = (size_t)index * sizeof(uint64_t);
    return 0;
}
