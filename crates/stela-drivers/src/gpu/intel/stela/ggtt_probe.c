/* SPDX-License-Identifier: MIT */
/* Stela's GSM probe: the PF geometry of xe_ggtt_init_early() and the PTE
 * index of xe_ggtt_get_pte() in Linux's xe_ggtt.c, over its unchanged
 * register and page definitions. */
#include "ggtt_probe.h"
#include <drm/intel/i915_drm.h>
#include <linux/sizes.h>
#include "regs/xe_gtt_defs.h"
#include "xe_bo.h"
#include "xe_device_types.h"
#include "xe_wopcm.h"
#include <linux/string.h>
#include <stela/linux.h>

/* The device xe_wopcm_size reads. Only the running Linux owner uses it, so
 * there is one. */
static struct xe_device device;

/* Graphics 12.50 and later have a fixed 8 MiB GSM for a 4 GiB GGTT. */
static bool fixed_gsm(uint32_t graphics_verx100)
{
    return graphics_verx100 >= 1250;
}
int stela_intel_gsm_config(uint32_t graphics_verx100, uint16_t *offset)
{
    if (!offset || !graphics_verx100) return -22;
    if (fixed_gsm(graphics_verx100)) return 1;
    *offset = SNB_GMCH_CTRL;
    return 0;
}
int stela_intel_gsm_geometry(uint32_t platform, uint32_t graphics_verx100, bool discrete,
    uint64_t actual_bar_bytes, bool config_present, uint16_t gmch_control,
    struct stela_intel_gsm_geometry *out)
{
    if (!out || !platform || platform > INT32_MAX || !graphics_verx100) return -22;
    unsigned int gsm_size;
    if (fixed_gsm(graphics_verx100))
        gsm_size = SZ_8M;
    else {
        if (!config_present) return -95;
        u16 ggms = (gmch_control >> BDW_GMCH_GGMS_SHIFT) & BDW_GMCH_GGMS_MASK;
        gsm_size = ggms ? (unsigned int)SZ_1M << ggms : 0;
    }
    if (!gsm_size) return -12; /* Linux: no preallocated GSM. */
    /* The GSM follows the registers in BAR0. */
    uint64_t offset = SZ_8M;
    if (offset > actual_bar_bytes || gsm_size > actual_bar_bytes - offset) return -34;
    stela_linux_enter(&stela_linux_bare);
    memset(&device, 0, sizeof(device));
    device.info.platform = (enum xe_platform)platform;
    device.info.is_dgfx = discrete;
    uint64_t wopcm = xe_wopcm_size(&device);
    stela_linux_exit();
    if ((gsm_size / 8) * (uint64_t)XE_PAGE_SIZE <= wopcm) return -34;
    /* The GGTT starts above WOPCM and ends where the GSM's PTEs or the GuC's
     * address limit does. */
    uint64_t start = wopcm, size = (gsm_size / 8) * (uint64_t)XE_PAGE_SIZE - start;
    if (size + start > GUC_GGTT_TOP) size = GUC_GGTT_TOP - start;
    *out = (struct stela_intel_gsm_geometry){
        .gsm_offset = offset, .gsm_bytes = gsm_size, .ggtt_start = start, .ggtt_bytes = size,
    };
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
    uint64_t index = address >> XE_PTE_SHIFT;
    if (index >= geometry->gsm_bytes / sizeof(uint64_t)) return -34;
    *out = (size_t)index * sizeof(uint64_t);
    return 0;
}
