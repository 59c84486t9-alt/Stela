/* SPDX-License-Identifier: MIT */
/* Synthetic device/VM facts for hosted descriptor packing; no GPU is opened. */
#include "../stela/buffer.h"
#include "amd/common/ac_gpu_info.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct radeon_info
device(enum amd_gfx_level level, enum radeon_family family, bool graphics)
{
   struct radeon_info info = {
      .gfx_level = level, .family = family, .has_graphics = graphics,
      .virtual_address_max = UINT64_C(0x800000000000),
      .high_va_offset = UINT64_C(0xffff800000000000),
      .high_va_max = UINT64_C(0xffffffffffff0000),
      .virtual_address_alignment = 4096,
      .tcc_cache_line_size = level >= GFX12 ? 256 : level >= GFX9 ? 128 : 64,
      .has_l2_uncached = level >= GFX9,
   };
   ac_fill_compiler_info(&info, NULL, false);
   return info;
}

static struct stela_amd_buffer_view
view(void)
{
   return (struct stela_amd_buffer_view){
      .allocation_va = 0x20000000,
      .allocation_bytes = UINT64_C(0x100001000),
      .offset = 16, .range = 259, .required_alignment = 16,
   };
}

static void
check_descriptor(const uint32_t words[4], uint64_t va, uint32_t bytes, uint32_t word3)
{
   /* Decode address/stride/byte NUM_RECORDS independently of Mesa's encoder. */
   assert(words[0] == (uint32_t)va);
   assert(words[1] == ((va >> 32) & 0xffff));
   assert(words[2] == bytes);
   assert(words[3] == word3);
}

static void
test_targets(void)
{
   const struct {enum amd_gfx_level level; enum radeon_family family; bool graphics, resource;} targets[] = {
      {GFX6, CHIP_TAHITI, true, false}, {GFX7, CHIP_BONAIRE, true, false},
      {GFX8, CHIP_CARRIZO, true, false}, {GFX9, CHIP_RAVEN, true, false},
      {GFX9, CHIP_MI200, false, false}, {GFX9, CHIP_GFX940, false, false},
      {GFX10, CHIP_NAVI10, true, true}, {GFX10_3, CHIP_REMBRANDT, true, true},
      {GFX11, CHIP_NAVI31, true, false}, {GFX11_5, CHIP_STRIX1, true, false},
      {GFX11_5, CHIP_GFX1156, true, true}, {GFX11_7, CHIP_GFX1170, true, false},
      {GFX12, CHIP_GFX1200, true, false}, {GFX12_1, CHIP_GFX1210, true, false},
   };
   for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
      struct radeon_info info = device(targets[i].level, targets[i].family, targets[i].graphics);
      struct stela_amd_raw_buffer_facts facts;
      assert(stela_amd_query_raw_buffer_facts(&info, &facts) == STELA_AMD_BUFFER_OK);
      assert(facts.descriptor_dwords == 4 && facts.descriptor_address_bits == 48 && facts.max_num_records == UINT32_MAX);
      assert(facts.has_desc_resource_level == targets[i].resource);
      assert(facts.has_smem_oob_access_bug == (targets[i].level <= GFX7));
      assert(facts.cache_line_bytes == info.tcc_cache_line_size && facts.allocation_alignment == 4096);
      assert(facts.virtual_address_max == info.virtual_address_max && facts.high_va_offset == info.high_va_offset);
      /* Hardware RAW carrier: identity XYZW=0xfac, legacy FLOAT/32=0x27000;
       * RDNA FORMAT32_FLOAT=22 and OOB_RAW=3, actual resource-level bit as above. */
      uint32_t word3 = targets[i].level < GFX10 ? 0x00027fac : 0x30016fac;
      word3 |= targets[i].resource ? 1u << 24 : 0;
      struct stela_amd_buffer_view request = view();
      uint32_t words[4];
      assert(stela_amd_build_raw_buffer(&info, &request, words) == STELA_AMD_BUFFER_OK);
      check_descriptor(words, request.allocation_va + 16, 259, word3);
      request.offset = 0; request.range = UINT32_MAX;
      assert(stela_amd_build_raw_buffer(&info, &request, words) == STELA_AMD_BUFFER_OK);
      check_descriptor(words, request.allocation_va, UINT32_MAX, word3);
      request.allocation_va = UINT64_C(0xffff900000000000);
      request.allocation_bytes = 4096; request.offset = 4; request.range = 3; request.required_alignment = 4;
      assert(stela_amd_build_raw_buffer(&info, &request, words) == STELA_AMD_BUFFER_OK);
      check_descriptor(words, request.allocation_va + 4, 3, word3);
      request.allocation_va = UINT64_C(0x900000000000);
      assert(stela_amd_build_raw_buffer(&info, &request, words) == STELA_AMD_BUFFER_OK);
      check_descriptor(words, request.allocation_va + 4, 3, word3);
   }
   puts("AMD RAW buffer: 14 generation/device cases passed; descriptor facts only, hardware unverified");
}

static void
refused(const struct radeon_info *info, struct stela_amd_buffer_view request,
        enum stela_amd_buffer_status expected)
{
   uint32_t words[4] = {0xa5a5a5a5, 0x55555555, 0x12121212, 0x12345678};
   uint32_t before[4]; memcpy(before, words, sizeof(words));
   assert(stela_amd_build_raw_buffer(info, &request, words) == expected);
   assert(!memcmp(words, before, sizeof(words)));
}

static void
test_errors(void)
{
   struct radeon_info info = device(GFX11, CHIP_NAVI31, true);
   struct stela_amd_buffer_view request = view();
   request.range = UINT64_C(0x100000000);
   refused(&info, request, STELA_AMD_BUFFER_UNSUPPORTED);
   request = view(); request.range = 0;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); request.offset = request.allocation_bytes;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); request.range = request.allocation_bytes;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); request.offset++;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); request.required_alignment = 3;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); request.allocation_va++;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); request.allocation_va = UINT64_MAX - 4095;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); info.virtual_address_max = request.allocation_va + request.allocation_bytes - 1;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   info = device(GFX11, CHIP_NAVI31, true); info.high_va_offset = 0; info.high_va_max = 0;
   request = view(); request.allocation_va = UINT64_C(0xffff900000000000);
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   info = device(GFX11, CHIP_NAVI31, true); info.virtual_address_max = UINT64_C(1) << 56;
   request = view(); request.allocation_va = UINT64_C(1) << 48;
   refused(&info, request, STELA_AMD_BUFFER_INVALID);
   request = view(); request.allocation_va = UINT64_C(0xfffffffff000);
   request.allocation_bytes = 8192; request.offset = 0; request.range = 8192;
   refused(&info, request, STELA_AMD_BUFFER_UNSUPPORTED);
   info = device(GFX11, CHIP_NAVI31, true); info.tcc_cache_line_size = 0;
   refused(&info, view(), STELA_AMD_BUFFER_DEVICE_INFO_UNAVAILABLE);
   info = device(GFX11, CHIP_NAVI31, true); info.compiler_info.gfx_level = CLASS_UNKNOWN;
   refused(&info, view(), STELA_AMD_BUFFER_DEVICE_INFO_UNAVAILABLE);
   info = device(GFX11, CHIP_NAVI31, true); info.virtual_address_alignment = 0;
   refused(&info, view(), STELA_AMD_BUFFER_DEVICE_INFO_UNAVAILABLE);
   info = device(GFX11, CHIP_NAVI31, true); info.gfx_level = CAYMAN;
   refused(&info, view(), STELA_AMD_BUFFER_UNSUPPORTED);
   info = device(GFX11, CHIP_NAVI31, true); info.high_va_offset = 0;
   refused(&info, view(), STELA_AMD_BUFFER_INVALID);
   info = device(GFX11, CHIP_NAVI31, true); info.gfx_level = CAYMAN;
   struct stela_amd_raw_buffer_facts facts, before;
   memset(&facts, 0xa5, sizeof(facts)); before = facts;
   assert(stela_amd_query_raw_buffer_facts(&info, &facts) == STELA_AMD_BUFFER_UNSUPPORTED);
   assert(!memcmp(&facts, &before, sizeof(facts)));
}

int main(void)
{
   test_targets();
   test_errors();
   return 0;
}
