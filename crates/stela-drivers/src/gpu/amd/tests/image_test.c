/* SPDX-License-Identifier: MIT */
/* Partial captured CPU models plus synthetic VM addresses, never real devices. */
#include "../stela/image.h"
#include "amd/common/ac_descriptors.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_surface.h"
#include "amd/common/amdgpu_devices.h"
#include "amd/common/sid.h"
#include "drm-uapi/drm_fourcc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct radeon_info
fixture(const char *name)
{
   const struct amdgpu_device *dev = NULL;
   for (size_t i = 0; i < num_amdgpu_devices; i++) {
      if (!strcmp(name, amdgpu_devices[i].name))
         dev = &amdgpu_devices[i];
   }
   assert(dev);
   struct radeon_info info = {
      .family = dev->radeon_family, .gfx_level = ac_get_gfx_level(dev->radeon_family),
      .family_id = dev->dev.family, .chip_external_rev = dev->dev.external_rev,
      .gb_addr_config = dev->mmr_regs[2], .has_graphics = true, .has_image_opcodes = true,
      .enabled_rb_mask = dev->dev.enabled_rb_pipes_mask, .max_render_backends = dev->dev.num_rb_pipes,
      .virtual_address_max = UINT64_C(0x800000000000), .virtual_address_alignment = 4096,
      .high_va_offset = UINT64_C(0xffff800000000000), .high_va_max = UINT64_C(0xffffffffffff0000),
      .tcc_cache_line_size = 256,
   };
   if (info.family_id < AMDGPU_FAMILY_AI) {
      for (unsigned tile = 0; tile < 32; tile++) {
         for (unsigned reg = 0; reg < dev->mmr_reg_count; reg++) {
            const uint32_t *triple = &dev->mmr_regs[3 * reg];
            if (triple[0] == 0x2644 + tile)
               info.si_tile_mode_array[tile] = triple[2];
         }
      }
   }
   ac_fill_compiler_info(&info, NULL, false);
   return info;
}

static void
refused(const struct radeon_info *info, struct ac_addrlib *addrlib,
        struct stela_amd_linear_image image, struct stela_amd_buffer_view view,
        enum stela_amd_image_status expected)
{
   uint32_t words[8], before[8];
   memset(words, 0xa5, sizeof(words)); memcpy(before, words, sizeof(words));
   struct stela_amd_image_layout layout, old;
   memset(&layout, 0xa5, sizeof(layout)); old = layout;
   assert(stela_amd_build_linear_image(info, addrlib, &image, &view, words, &layout) == expected);
   assert(!memcmp(words, before, sizeof(words)) && !memcmp(&layout, &old, sizeof(layout)));
}

int main(void)
{
   const char *names[] = {"pitcairn", "bonaire", "polaris12", "vega10", "raven", "navi10", "navi21", "navi31", "phoenix", "strix1", "gfx1201"};
   const uint32_t dimensions[][2] = {{1, 1}, {63, 17}, {64, 16}, {65, 19}, {16384, 1}, {1, 16384}, {16384, 16384}};
   unsigned cases = 0;
   for (unsigned target = 0; target < ARRAY_SIZE(names); target++) {
      struct radeon_info info = fixture(names[target]);
      struct ac_addrlib *addrlib = ac_addrlib_create(&info, NULL);
      assert(addrlib);
      for (unsigned fmt = STELA_AMD_IMAGE_RGBA8_UNORM; fmt <= STELA_AMD_IMAGE_RGBA8_SRGB; fmt++) {
         for (unsigned dim = 0; dim < ARRAY_SIZE(dimensions); dim++) {
            const struct stela_amd_linear_image image = {dimensions[dim][0], dimensions[dim][1], fmt};
            struct stela_amd_image_layout layout;
            assert(stela_amd_query_linear_image_layout(&info, addrlib, &image, &layout) == STELA_AMD_IMAGE_OK);
            assert(layout.row_pitch >= (uint64_t)image.width * 4 && layout.alignment >= 256);
            assert(layout.bytes >= layout.row_pitch * (image.height - 1) + (uint64_t)image.width * 4);
            struct stela_amd_buffer_view view = {
               .allocation_va = UINT64_C(0x200000000), .allocation_bytes = layout.bytes + 8192,
               .offset = 4096, .range = layout.bytes, .required_alignment = 256,
            };
            for (unsigned aperture = 0; aperture < 3; aperture++) {
               view.allocation_va = aperture == 0 ? UINT64_C(0x200000000) :
                                    aperture == 1 ? UINT64_C(0xffff900000000000) : UINT64_C(0x900000000000);
               uint32_t words[8];
               struct stela_amd_image_layout built;
               assert(stela_amd_build_linear_image(&info, addrlib, &image, &view, words, &built) == STELA_AMD_IMAGE_OK);
               assert(!memcmp(&layout, &built, sizeof(layout)));
               const uint64_t address = view.allocation_va + view.offset;
               /* Independent address/extent/type decode; layout stays linear so
                * no tile-swizzle bits share BASE_ADDRESS low bits. */
               assert(words[0] == (uint32_t)(address >> 8));
               assert((words[1] & 0xff) == ((address >> 40) & 0xff));
               assert((words[3] >> 28) == V_008F1C_SQ_RSRC_IMG_2D);
               assert((words[3] & 0xfff) == 0xfac); /* Original identity XYZW. */
               assert(!words[7]);
               if (info.gfx_level < GFX10) {
                  assert((words[2] & 0x3fff) + 1 == image.width);
                  assert(((words[2] >> 14) & 0x3fff) + 1 == image.height);
                  assert(((words[1] >> 20) & 0x3f) == 10); /* IMG_DATA_FORMAT_8_8_8_8. */
                  assert(((words[1] >> 26) & 0xf) ==
                         (fmt == STELA_AMD_IMAGE_RGBA8_UNORM ? 0 : fmt == STELA_AMD_IMAGE_RGBA8_UINT ? 4 : 9));
                  assert(!words[6]);
               } else {
                  assert(((((words[2] & 0x3fff) << 2) | (words[1] >> 30)) + 1) == image.width);
                  assert(((words[2] >> 14) & 0xffff) + 1 == image.height);
                  /* Original GFX10/11 format tables; literal decode independent
                   * of the encoder's register-field macros. */
                  const unsigned expected = info.gfx_level >= GFX11 ?
                     (fmt == STELA_AMD_IMAGE_RGBA8_UNORM ? 42 : fmt == STELA_AMD_IMAGE_RGBA8_UINT ? 46 : 66) :
                     (fmt == STELA_AMD_IMAGE_RGBA8_UNORM ? 56 : fmt == STELA_AMD_IMAGE_RGBA8_UINT ? 60 : 130);
                  assert(((words[1] >> (info.gfx_level >= GFX12 ? 17 : 20)) &
                          (info.gfx_level >= GFX12 ? 0xff : 0x1ff)) == expected);
                  assert(!(words[6] & (3u << 20))); /* No write-compress or compression enable. */
                  assert((words[2] >> 31) == info.compiler_info.has_desc_resource_level);
               }
               cases++;
            }
            view.allocation_va = UINT64_C(0x200000000);
            view.range--; refused(&info, addrlib, image, view, STELA_AMD_IMAGE_INVALID); view.range++;
            view.offset++; refused(&info, addrlib, image, view, STELA_AMD_IMAGE_INVALID); view.offset--;
            view.allocation_bytes = view.offset + view.range - 1;
            refused(&info, addrlib, image, view, STELA_AMD_IMAGE_INVALID);
            view.allocation_bytes++;
            assert(stela_amd_build_linear_image(&info, addrlib, &image, &view, (uint32_t[8]){0}, NULL) == STELA_AMD_IMAGE_OK);
            view.required_alignment = 3; refused(&info, addrlib, image, view, STELA_AMD_IMAGE_INVALID);
         }
      }
      const struct stela_amd_buffer_view view = {UINT64_C(0x200000000), 8192, 0, 8192, 256};
      struct stela_amd_linear_image image = {63, 17, STELA_AMD_IMAGE_RGBA8_UNORM};
      image.width = 0; refused(&info, addrlib, image, view, STELA_AMD_IMAGE_INVALID);
      image.width = 16385; refused(&info, addrlib, image, view, STELA_AMD_IMAGE_UNSUPPORTED);
      image.width = 63; image.format = 0; refused(&info, addrlib, image, view, STELA_AMD_IMAGE_UNSUPPORTED);
      image.format = STELA_AMD_IMAGE_RGBA8_UNORM;
      struct stela_amd_buffer_view invalid = view;
      invalid.allocation_va++; refused(&info, addrlib, image, invalid, STELA_AMD_IMAGE_INVALID);
      invalid = view; invalid.offset = UINT64_MAX;
      refused(&info, addrlib, image, invalid, STELA_AMD_IMAGE_INVALID);
      invalid = view; invalid.required_alignment = 0;
      refused(&info, addrlib, image, invalid, STELA_AMD_IMAGE_INVALID);
      invalid = view; invalid.allocation_va = UINT64_MAX - 4095;
      refused(&info, addrlib, image, invalid, STELA_AMD_IMAGE_INVALID);
      invalid = view; invalid.allocation_va = info.virtual_address_max - 4096;
      refused(&info, addrlib, image, invalid, STELA_AMD_IMAGE_INVALID);
      refused(&info, NULL, image, view, STELA_AMD_IMAGE_INVALID);
      struct stela_amd_image_layout untouched, before;
      memset(&untouched, 0xa5, sizeof(untouched)); before = untouched;
      image.height = UINT32_MAX;
      assert(stela_amd_query_linear_image_layout(&info, addrlib, &image, &untouched) == STELA_AMD_IMAGE_UNSUPPORTED);
      assert(!memcmp(&untouched, &before, sizeof(before)));
      image.height = 17;
      info.has_image_opcodes = false; refused(&info, addrlib, image, view, STELA_AMD_IMAGE_UNSUPPORTED);
      info.has_image_opcodes = true; info.compiler_info.gfx_level = 0;
      refused(&info, addrlib, image, view, STELA_AMD_IMAGE_DEVICE_INFO_UNAVAILABLE);
      ac_addrlib_destroy(addrlib);
   }
   printf("AMD linear sampled image: %u original layout/descriptor cases; CPU models, GPU execution unverified\n", cases);
   return 0;
}
