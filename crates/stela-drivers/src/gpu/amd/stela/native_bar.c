/* SPDX-License-Identifier: MIT */
#include "native_bar.h"
#include <limits.h>
#include <stddef.h>

_Static_assert(sizeof(struct stela_amd_bar_layout) == 16, "BAR layout ABI");
_Static_assert(offsetof(struct stela_amd_bar_layout, kernel_doorbell_bytes) == 8, "BAR bytes ABI");

enum stela_amd_bar_status
stela_amd_native_register_bar(uint32_t asic_type, uint32_t *bar)
{
   if (!bar || asic_type >= CHIP_LAST)
      return STELA_AMD_BAR_INVALID;
   *bar = amdgpu_native_register_bar((enum amd_asic_type)asic_type);
   return STELA_AMD_BAR_OK;
}

enum stela_amd_bar_status
stela_amd_native_bar_layout(uint32_t asic_type, uint64_t doorbell_bar_bytes,
                            uint32_t max_assignment, uint64_t page_bytes,
                            struct stela_amd_bar_layout *layout)
{
   if (!layout || asic_type >= CHIP_LAST || page_bytes < 4096 ||
       page_bytes > UINT32_MAX || (page_bytes & (page_bytes - 1)))
      return STELA_AMD_BAR_INVALID;
   const enum amd_asic_type asic = asic_type;
   struct stela_amd_bar_layout result = {.register_bar = amdgpu_native_register_bar(asic)};
   if (asic < CHIP_BONAIRE) {
      if (doorbell_bar_bytes || max_assignment)
         return STELA_AMD_BAR_INVALID;
   } else {
      if (doorbell_bar_bytes < 4 || doorbell_bar_bytes / 4 > UINT32_MAX ||
          max_assignment == UINT32_MAX ||
          (asic >= CHIP_VEGA10 && max_assignment + 1 > UINT32_MAX - 0x400))
         return STELA_AMD_BAR_UNREPRESENTABLE;
      const uint32_t count = amdgpu_native_kernel_doorbell_count(asic, doorbell_bar_bytes,
                                                                max_assignment);
      const uint64_t bytes = amdgpu_native_kernel_doorbell_bytes(count, page_bytes);
      /* The original kernel allocator's temporary size is int. Keep that
       * producer's representable domain, and never acquire outside the BAR. */
      if (!count || bytes > INT_MAX || bytes > doorbell_bar_bytes)
         return STELA_AMD_BAR_UNREPRESENTABLE;
      result.kernel_doorbell_bytes = bytes;
      result.kernel_doorbells = bytes / 4;
   }
   *layout = result;
   return STELA_AMD_BAR_OK;
}
