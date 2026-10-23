/* SPDX-License-Identifier: MIT */
/* Stela's placement of amdgpu's register and kernel doorbell apertures, with
 * the results Linux's amdgpu_device_init, amdgpu_doorbell_init and
 * amdgpu_doorbell_create_kernel_doorbells give. */
#include "native_bar.h"
#include <drm/amd_asic_type.h>
#include <linux/align.h>
#include <linux/limits.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/stddef.h>

_Static_assert(sizeof(struct stela_amd_bar_layout) == 16, "BAR layout ABI");
_Static_assert(offsetof(struct stela_amd_bar_layout, kernel_doorbell_bytes) == 8, "BAR bytes ABI");

/* SI decodes its registers in BAR 2 and has no doorbells; CIK and later moved
 * the registers to BAR 5 and use BAR 2 for doorbells. */
static uint32_t register_bar(enum amd_asic_type asic)
{
   return asic >= CHIP_BONAIRE ? 5 : 2;
}

enum stela_amd_bar_status
stela_amd_native_register_bar(uint32_t asic_type, uint32_t *bar)
{
   if (!bar || asic_type >= CHIP_LAST)
      return STELA_AMD_BAR_INVALID;
   *bar = register_bar(asic_type);
   return STELA_AMD_BAR_OK;
}

/* The kernel's doorbells are one DWORD for each index up to the highest
 * assignment, within the BAR. From Vega the SDMA paging queues ring in the
 * BAR's second 4 KiB, beyond the assignments. The range is whole pages, and
 * MES takes one more page after it. Linux counts in u32, so an assignment
 * that leaves no doorbells or more than u32 can count is unrepresentable, as
 * is a range beyond the int its allocator sizes with, or beyond the BAR. */
enum stela_amd_bar_status
stela_amd_native_bar_layout(uint32_t asic_type, uint64_t doorbell_bar_bytes,
                            uint32_t max_assignment, uint64_t page_bytes,
                            struct stela_amd_bar_layout *layout)
{
   if (!layout || asic_type >= CHIP_LAST || page_bytes < SZ_4K || page_bytes > U32_MAX ||
       !is_power_of_2(page_bytes))
      return STELA_AMD_BAR_INVALID;
   const enum amd_asic_type asic = asic_type;
   struct stela_amd_bar_layout result = {.register_bar = register_bar(asic)};
   if (asic < CHIP_BONAIRE) {
      if (doorbell_bar_bytes || max_assignment)
         return STELA_AMD_BAR_INVALID;
      *layout = result;
      return STELA_AMD_BAR_OK;
   }
   const uint64_t paging = asic >= CHIP_VEGA10 ? SZ_4K / sizeof(uint32_t) : 0;
   if (doorbell_bar_bytes / sizeof(uint32_t) > U32_MAX || max_assignment == U32_MAX)
      return STELA_AMD_BAR_UNREPRESENTABLE;
   const uint64_t assigned =
      min(doorbell_bar_bytes / sizeof(uint32_t), (uint64_t)max_assignment + 1);
   if (!assigned || assigned + paging > U32_MAX)
      return STELA_AMD_BAR_UNREPRESENTABLE;
   const uint64_t bytes = ALIGN((assigned + paging) * sizeof(uint32_t), page_bytes) + page_bytes;
   if (bytes > INT_MAX || bytes > doorbell_bar_bytes)
      return STELA_AMD_BAR_UNREPRESENTABLE;
   result.kernel_doorbell_bytes = bytes;
   result.kernel_doorbells = (uint32_t)(bytes / sizeof(uint32_t));
   *layout = result;
   return STELA_AMD_BAR_OK;
}
