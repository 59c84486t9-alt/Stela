/* SPDX-License-Identifier: MIT */
/* Retained partial captured-device CPU fixture; never production init. */
#ifndef STELA_AMD_TEST_IMAGE_FIXTURE_H
#define STELA_AMD_TEST_IMAGE_FIXTURE_H
#include "amd/common/ac_gpu_info.h"
#include "amd/common/amdgpu_devices.h"
#include "amd/common/sid.h"
#include <assert.h>
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
      .tcc_cache_line_size = 256,
   };
   /* The original ac_linux_drm.c queries these exact retained register ranges:
    * GB_TILE_MODE0..31=0x2644, MACROTILE_MODE0..15=0x2664, MC_ARB_RAMCFG=0x9d8.
    * Decode the captured fixture values, never make up legacy tiling facts. */
   if (info.gfx_level < GFX9) {
      for (unsigned reg = 0; reg < dev->mmr_reg_count; reg++) {
         const uint32_t *triple = &dev->mmr_regs[3 * reg];
         if (triple[0] >= 0x2644 && triple[0] < 0x2644 + 32)
            info.si_tile_mode_array[triple[0] - 0x2644] = triple[2];
         if (triple[0] >= 0x2664 && triple[0] < 0x2664 + 16)
            info.cik_macrotile_mode_array[triple[0] - 0x2664] = triple[2];
         if (triple[0] == 0x9d8)
            info.mc_arb_ramcfg = triple[2];
      }
      /* Same original CIK_TILE_MODE_COLOR_2D index as ac_fill_tiling_info. */
      info.num_tile_pipes = ac_pipe_config_to_num_pipes(G_009910_PIPE_CONFIG(info.si_tile_mode_array[14]));
   }
   ac_fill_compiler_info(&info, NULL, false);
   return info;
}

#endif
