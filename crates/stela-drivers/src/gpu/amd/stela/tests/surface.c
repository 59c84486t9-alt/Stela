/* SPDX-License-Identifier: MIT */
/* CPU-only Addrlib ABI/layout check using retained captured-device fixtures.
 * These partial models are never initialized GPU devices or production inputs. */
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_surface.h"
#include "amd/common/amdgpu_devices.h"
#include "amd/addrlib/inc/addrinterface.h"
#include "drm-uapi/drm_fourcc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(UINT_32) == 4 && sizeof(UINT_64) == 8, "public Addrlib widths");
_Static_assert(sizeof(BOOL_32) == 4, "public Addrlib bool width");

static const struct amdgpu_device *
fixture(const char *name)
{
   for (size_t i = 0; i < num_amdgpu_devices; i++) {
      if (!strcmp(name, amdgpu_devices[i].name))
         return &amdgpu_devices[i];
   }
   assert(!"missing retained captured-device fixture");
   return NULL;
}

int main(void)
{
   const char *names[] = {"polaris12", "vega10", "raven", "navi10", "navi21", "navi31", "phoenix", "gfx1201"};
   for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
      const struct amdgpu_device *dev = fixture(names[i]);
      /* Same raw AddrCreate inputs read by the original ac_surface_test.h.
       * Other fields are explicitly limited CPU fixtures, not device services. */
      struct radeon_info info = {.family = dev->radeon_family,
         .gfx_level = ac_get_gfx_level(dev->radeon_family), .family_id = dev->dev.family,
         .chip_external_rev = dev->dev.external_rev, .gb_addr_config = dev->mmr_regs[2],
         .has_graphics = true, .has_image_opcodes = true,
         .enabled_rb_mask = dev->dev.enabled_rb_pipes_mask,
         .max_render_backends = dev->dev.num_rb_pipes,
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
      uint64_t max_alignment = 0;
      struct ac_addrlib *addrlib = ac_addrlib_create(&info, &max_alignment);
      assert(addrlib && max_alignment && !(max_alignment & (max_alignment - 1)));
      struct ac_surf_config config = {
         .info = {.width = 63, .height = 17, .depth = 1, .array_size = 1, .levels = 1,
                  .samples = 1, .storage_samples = 1, .num_channels = 4},
         .blk_w = 1, .blk_h = 1, .bpe = 4,
         .surf_flags = RADEON_SURF_DISABLE_DCC,
         .modifier = DRM_FORMAT_MOD_INVALID,
      };
      struct radeon_surf surf;
      assert(!ac_compute_surface(addrlib, &info, &config, RADEON_SURF_MODE_LINEAR_ALIGNED, &surf));
      assert(surf.total_size >= UINT64_C(63) * 17 * 4 && surf.surf_size <= surf.total_size);
      assert(surf.alignment_log2 < 63 && (UINT64_C(1) << surf.alignment_log2) <= max_alignment);
      assert(!surf.meta_offset && !surf.meta_size && !surf.fmask_size);
      assert(ac_surface_get_plane_stride(info.gfx_level, &surf, 0, 0) == 256);
      assert(surf.total_size == UINT64_C(256) * 17);
      /* The retained common coordinate helper is explicitly GFX9+ only. */
      if (info.gfx_level >= GFX9)
         assert(ac_surface_addr_from_coord(addrlib, &info, &surf, &config.info,
                                          0, 62, 16, 0, false) == UINT64_C(256) * 16 + 62 * 4);
      printf("AMD surface fixture %s: size=%llu align=%llu\n", names[i],
             (unsigned long long)surf.total_size, (unsigned long long)(UINT64_C(1) << surf.alignment_log2));
      ac_addrlib_destroy(addrlib);
   }
   printf("AMD public Addrlib ABI: UINT32=%zu UINT64=%zu BOOL32=%zu CREATE_IN=%zu CREATE_OUT=%zu\n",
          sizeof(UINT_32), sizeof(UINT_64), sizeof(BOOL_32), sizeof(ADDR_CREATE_INPUT), sizeof(ADDR_CREATE_OUTPUT));
   puts("AMD hosted surface: 8 retained-fixture layout cases passed; physical mappings unverified");
   return 0;
}
