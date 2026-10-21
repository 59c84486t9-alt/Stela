/* SPDX-License-Identifier: MIT */
#include "buffer.h"
#include "amd/common/ac_descriptors.h"
#include "amd/common/ac_gpu_info.h"

#include <string.h>

#define RAW_ADDRESS_BITS 48
#define RAW_ADDRESS_MASK ((UINT64_C(1) << RAW_ADDRESS_BITS) - 1)
#define RAW_ADDRESS_SIGN (UINT64_C(1) << (RAW_ADDRESS_BITS - 1))

static bool
power_of_two(uint64_t value)
{
   return value && !(value & (value - 1));
}

static bool
raw_address(uint64_t address)
{
   return !(address & ~RAW_ADDRESS_MASK) ||
          ((address & ~RAW_ADDRESS_MASK) == ~RAW_ADDRESS_MASK && (address & RAW_ADDRESS_SIGN));
}

static enum stela_amd_buffer_status
validate_device(const struct radeon_info *info)
{
   if (!info)
      return STELA_AMD_BUFFER_INVALID;
   if (info->gfx_level < GFX6 || info->gfx_level >= NUM_GFX_VERSIONS)
      return STELA_AMD_BUFFER_UNSUPPORTED;
   if (info->compiler_info.gfx_level != info->gfx_level || !info->virtual_address_max ||
       !power_of_two(info->virtual_address_alignment) ||
       !power_of_two(info->tcc_cache_line_size))
      return STELA_AMD_BUFFER_DEVICE_INFO_UNAVAILABLE;
   if (!!info->high_va_offset != !!info->high_va_max ||
       (info->high_va_offset && info->high_va_offset >= info->high_va_max))
      return STELA_AMD_BUFFER_INVALID;
   return STELA_AMD_BUFFER_OK;
}

enum stela_amd_buffer_status
stela_amd_query_raw_buffer_facts(const struct radeon_info *info,
                                struct stela_amd_raw_buffer_facts *facts)
{
   enum stela_amd_buffer_status status = validate_device(info);
   if (status != STELA_AMD_BUFFER_OK)
      return status;
   if (!facts)
      return STELA_AMD_BUFFER_INVALID;
   const struct stela_amd_raw_buffer_facts result = {
      .descriptor_dwords = 4,
      .descriptor_address_bits = RAW_ADDRESS_BITS,
      .max_num_records = UINT32_MAX,
      .cache_line_bytes = info->tcc_cache_line_size,
      .allocation_alignment = info->virtual_address_alignment,
      .virtual_address_max = info->virtual_address_max,
      .high_va_offset = info->high_va_offset,
      .high_va_max = info->high_va_max,
      .has_l2_uncached = info->has_l2_uncached,
      .has_smem_oob_access_bug = info->compiler_info.has_smem_oob_access_bug,
      .has_smem_with_null_prt_bug = info->compiler_info.has_smem_with_null_prt_bug,
      .has_desc_resource_level = info->compiler_info.has_desc_resource_level,
   };
   *facts = result;
   return STELA_AMD_BUFFER_OK;
}

static bool
within(uint64_t address, uint64_t bytes, uint64_t start, uint64_t end)
{
   return address >= start && address < end && bytes <= end - address;
}

static bool
allocation_in_vm(const struct radeon_info *info, uint64_t address, uint64_t bytes)
{
   if (within(address, bytes, 0, info->virtual_address_max))
      return true;
   if (within(address, bytes, info->high_va_offset, info->high_va_max))
      return true;
   /* The existing encoder stores 48 address bits. DRM/native allocators may
    * hand an upper-half address to this frontend in zero-extended form. Only
    * accept its canonical counterpart if the actual high VM aperture owns it. */
   if (!(address & ~RAW_ADDRESS_MASK) && (address & RAW_ADDRESS_SIGN))
      return within(address | ~RAW_ADDRESS_MASK, bytes, info->high_va_offset, info->high_va_max);
   return false;
}

enum stela_amd_buffer_status
stela_amd_build_raw_buffer(const struct radeon_info *info,
                           const struct stela_amd_buffer_view *view,
                           uint32_t descriptor[4])
{
   enum stela_amd_buffer_status status = validate_device(info);
   if (status != STELA_AMD_BUFFER_OK)
      return status;
   if (!view || !descriptor || !view->allocation_va || !view->allocation_bytes ||
       !view->range || !power_of_two(view->required_alignment) ||
       (view->allocation_va & (info->virtual_address_alignment - 1)) ||
       view->offset > view->allocation_bytes || view->range > view->allocation_bytes - view->offset ||
       view->offset > UINT64_MAX - view->allocation_va ||
       !allocation_in_vm(info, view->allocation_va, view->allocation_bytes))
      return STELA_AMD_BUFFER_INVALID;
   if (view->range > UINT32_MAX)
      return STELA_AMD_BUFFER_UNSUPPORTED;
   const uint64_t address = view->allocation_va + view->offset;
   if ((address & (view->required_alignment - 1)) || !raw_address(address))
      return STELA_AMD_BUFFER_INVALID;
   /* Do not wrap or truncate the descriptor's 48-bit address interval. */
   const uint64_t low = address & RAW_ADDRESS_MASK;
   if (view->range - 1 > RAW_ADDRESS_MASK - low)
      return STELA_AMD_BUFFER_UNSUPPORTED;
   uint32_t result[4];
   ac_build_raw_buffer_descriptor(info->gfx_level, info->compiler_info.has_desc_resource_level,
                                  address, (uint32_t)view->range, result);
   memcpy(descriptor, result, sizeof(result));
   return STELA_AMD_BUFFER_OK;
}
