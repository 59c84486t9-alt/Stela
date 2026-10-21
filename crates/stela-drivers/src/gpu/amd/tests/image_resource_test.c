/* SPDX-License-Identifier: MIT */
/* Retained captured partial CPU models and synthetic VM views only. */
#include "../stela/image_resource.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/amdgpu_devices.h"
#include "amd/common/sid.h"
#include "util/u_math.h"
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

static void
check_view(const struct radeon_info *info, const struct stela_amd_image_resource *resource,
           const struct stela_amd_buffer_view *owner, const struct stela_amd_image_view *view)
{
   const struct stela_amd_image_layout_state *layout = resource->layout;
   const struct stela_amd_image_description *description = &layout->description;
   uint32_t words[8];
   assert(stela_amd_build_image_view(info, resource, owner, view, words) == STELA_AMD_IMAGE_OK);
   unsigned tile_swizzle = layout->surface.tile_swizzle;
   if (info->gfx_level < GFX9 && layout->surface.u.legacy.level[0].mode != RADEON_SURF_MODE_2D)
      tile_swizzle = 0;
   assert(words[0] == ((uint32_t)(resource->address >> 8) | tile_swizzle));
   assert((words[1] & 0xff) == ((resource->address >> 40) & 0xff));
   assert((words[3] & 0xfff) == 0xfac);
   assert((words[3] >> 28) == (description->kind == STELA_AMD_IMAGE_2D ? 9 : 13));
   const unsigned first_level = info->gfx_level >= GFX12 ? (words[1] >> 25) & 31 : (words[3] >> 12) & 15;
   const unsigned last_level = info->gfx_level >= GFX12 ? (words[3] >> 15) & 31 : (words[3] >> 16) & 15;
   assert(first_level == view->first_level && last_level == view->first_level + view->level_count - 1);
   const unsigned last_layer = view->first_layer + view->layer_count - 1;
   if (info->gfx_level < GFX9) {
      assert((words[4] & 0x1fff) == description->layers - 1);
      assert((words[5] & 0x1fff) == view->first_layer && ((words[5] >> 13) & 0x1fff) == last_layer);
      assert(((words[4] >> 13) & 0x3fff) + 1 == layout->surface.u.legacy.level[0].nblk_x);
      assert(((words[3] >> 25) & 1) == (description->levels > 1));
      assert(!words[6]);
   } else if (info->gfx_level == GFX9) {
      assert((words[4] & 0x1fff) == last_layer && (words[5] & 0x1fff) == view->first_layer);
      assert((words[5] >> 28) == description->levels - 1);
      assert(!words[6]);
   } else {
      if (info->gfx_level >= GFX10_3 && layout->surface.u.gfx9.uses_custom_pitch) {
         /* Original non-array linear single-level policy repurposes DEPTH
          * plus PITCH_MSB as pitch, not a layer index. */
         assert((words[4] & (info->gfx_level >= GFX12 ? 0xffff : 0x3fff)) + 1 == layout->surface.u.gfx9.surf_pitch);
      } else {
         assert((words[4] & (info->gfx_level >= GFX12 ? 0x3fff : 0x1fff)) == last_layer);
      }
      assert(((words[4] >> 16) & 0x3fff) == view->first_layer);
      const unsigned max_mip = info->gfx_level >= GFX12 ? (words[1] >> 12) & 31 :
                               info->gfx_level >= GFX11 ? (words[1] >> 16) & 15 : (words[5] >> 4) & 15;
      assert(max_mip == description->levels - 1);
      assert(!(words[6] & (3u << 20)));
   }
   assert(!words[7]);
   if (info->gfx_level < GFX10) {
      assert((words[2] & 0x3fff) + 1 == description->width);
      assert(((words[2] >> 14) & 0x3fff) + 1 == description->height);
   } else {
      assert(((((words[2] & 0x3fff) << 2) | (words[1] >> 30)) + 1) == description->width);
      assert(((words[2] >> 14) & 0xffff) + 1 == description->height);
   }
}

static void
refused_view(const struct radeon_info *info, const struct stela_amd_image_resource *resource,
              const struct stela_amd_buffer_view *owner, struct stela_amd_image_view view,
              enum stela_amd_image_status status)
{
   uint32_t words[8], before[8];
   memset(words, 0xa5, sizeof(words)); memcpy(before, words, sizeof(words));
   assert(stela_amd_build_image_view(info, resource, owner, &view, words) == status);
   assert(!memcmp(words, before, sizeof(words)));
}

static void
refused_layout(const struct radeon_info *info, struct ac_addrlib *addrlib,
                struct stela_amd_image_description description, enum stela_amd_image_status status)
{
   struct stela_amd_image_layout_state layout, before;
   memset(&layout, 0xa5, sizeof(layout)); memcpy(&before, &layout, sizeof(layout));
   assert(stela_amd_prepare_image_layout(info, addrlib, &description, &layout) == status);
   assert(!memcmp(&layout, &before, sizeof(layout)));
}

int main(void)
{
   const char *names[] = {"pitcairn", "bonaire", "polaris12", "vega10", "raven", "navi10", "navi21", "navi31", "phoenix", "strix1", "gfx1201"};
   const unsigned geometries[][4] = {{63,17,6,3}, {257,131,9,5}, {1,1,1,8192}, {16384,1,15,2}, {1,1,1,1}};
   unsigned layouts = 0, views = 0;
   for (unsigned target = 0; target < ARRAY_SIZE(names); target++) {
      struct radeon_info info = fixture(names[target]);
      struct ac_addrlib *addrlib = ac_addrlib_create(&info, NULL);
      assert(addrlib);
      for (unsigned format = STELA_AMD_IMAGE_RGBA8_UNORM; format <= STELA_AMD_IMAGE_RGBA8_SRGB; format++) {
         for (unsigned tiling = STELA_AMD_IMAGE_LINEAR; tiling <= STELA_AMD_IMAGE_TILED; tiling++) {
            for (unsigned kind = STELA_AMD_IMAGE_2D; kind <= STELA_AMD_IMAGE_2D_ARRAY; kind++) {
               for (unsigned geometry = 0; geometry < ARRAY_SIZE(geometries); geometry++) {
                  const unsigned *g = geometries[geometry];
                  const unsigned layers = g[3] == 8192 && info.gfx_level < GFX10 ? 2048 : g[3];
                  struct stela_amd_image_description description = {g[0], g[1], g[2], kind == STELA_AMD_IMAGE_2D ? 1 : layers, format, kind, tiling};
                  struct stela_amd_image_layout_state layout, unchanged;
                  assert(stela_amd_prepare_image_layout(&info, addrlib, &description, &layout) == STELA_AMD_IMAGE_OK);
                  assert(layout.storage.bytes == layout.surface.total_size && layout.surface.total_size == layout.surface.surf_size);
                  assert(layout.storage.row_pitch == (layout.surface.is_linear ? ac_surface_get_plane_stride(info.gfx_level, &layout.surface, 0, 0) : 0));
                  assert(!layout.surface.meta_offset && !layout.surface.cmask_offset && !layout.surface.fmask_offset);
                  memcpy(&unchanged, &layout, sizeof(layout));
                  layouts++;
                  const uint64_t offset = layout.storage.alignment;
                  struct stela_amd_buffer_view owner = {UINT64_C(0x2000000000), align64(layout.storage.bytes + offset, 4096), offset, layout.storage.bytes, 256};
                  struct stela_amd_image_resource resource;
                  assert(stela_amd_bind_image_resource(&layout, &owner, &resource) == STELA_AMD_IMAGE_OK);
                  struct stela_amd_image_resource refused, before;
                  memset(&refused, 0xa5, sizeof(refused)); memcpy(&before, &refused, sizeof(before));
                  const uint64_t allocation_bytes = owner.allocation_bytes;
                  owner.allocation_bytes = owner.offset + owner.range - 1;
                  assert(stela_amd_bind_image_resource(&layout, &owner, &refused) == STELA_AMD_IMAGE_INVALID);
                  assert(!memcmp(&refused, &before, sizeof(refused)));
                  owner.allocation_bytes = allocation_bytes;
                  owner.range--;
                  assert(stela_amd_bind_image_resource(&layout, &owner, &refused) == STELA_AMD_IMAGE_INVALID);
                  assert(!memcmp(&refused, &before, sizeof(refused)));
                  owner.range++;
                  for (unsigned level = 0; level < description.levels; level++) {
                     struct stela_amd_image_view view = {level, description.levels - level, 0, description.layers, kind};
                     check_view(&info, &resource, &owner, &view); views++;
                     view.level_count = 1; view.first_layer = description.layers - 1; view.layer_count = 1;
                     check_view(&info, &resource, &owner, &view); views++;
                     view.first_layer = description.layers / 2; view.layer_count = description.layers - view.first_layer;
                     check_view(&info, &resource, &owner, &view); views++;
                  }
                  assert(!memcmp(&layout, &unchanged, sizeof(layout))); /* Cached surface is never recomputed or mutated. */
                  struct stela_amd_image_view view = {0, 1, 0, 1, kind};
                  struct stela_amd_buffer_view copied_owner = owner;
                  refused_view(&info, &resource, &copied_owner, view, STELA_AMD_IMAGE_INVALID);
                  struct radeon_info copied_device = info;
                  refused_view(&copied_device, &resource, &owner, view, STELA_AMD_IMAGE_INVALID);
                  owner.range--; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID); owner.range++;
                  owner.offset++; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID); owner.offset--;
                  view.first_level = UINT32_MAX; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID);
                  view.first_level = 0; view.level_count = UINT32_MAX; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID);
                  view.level_count = 0; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID);
                  view.level_count = 1; view.first_layer = UINT32_MAX; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID);
                  view.first_layer = 0; view.layer_count = UINT32_MAX; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID);
                  view.layer_count = 0; refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_INVALID);
                  view.layer_count = 1; view.kind = kind == STELA_AMD_IMAGE_2D ? STELA_AMD_IMAGE_2D_ARRAY : STELA_AMD_IMAGE_2D;
                  refused_view(&info, &resource, &owner, view, STELA_AMD_IMAGE_UNSUPPORTED);
               }
            }
         }
      }
      struct stela_amd_image_description invalid = {63,17,6,1,STELA_AMD_IMAGE_RGBA8_UNORM,STELA_AMD_IMAGE_2D,STELA_AMD_IMAGE_LINEAR};
      invalid.levels = 7; refused_layout(&info, addrlib, invalid, STELA_AMD_IMAGE_INVALID);
      invalid.levels = 6; invalid.layers = 2; refused_layout(&info, addrlib, invalid, STELA_AMD_IMAGE_INVALID);
      invalid.kind = STELA_AMD_IMAGE_2D_ARRAY; invalid.layers = info.gfx_level >= GFX10 ? 8193 : 2049;
      refused_layout(&info, addrlib, invalid, STELA_AMD_IMAGE_UNSUPPORTED);
      invalid.layers = 0; refused_layout(&info, addrlib, invalid, STELA_AMD_IMAGE_INVALID);
      invalid.layers = 1; invalid.levels = 0; refused_layout(&info, addrlib, invalid, STELA_AMD_IMAGE_INVALID);
      if (info.gfx_level < GFX9) {
         invalid.levels = 6; invalid.tiling = STELA_AMD_IMAGE_TILED;
         struct radeon_info missing = info; missing.num_tile_pipes = 0;
         refused_layout(&missing, addrlib, invalid, STELA_AMD_IMAGE_DEVICE_INFO_UNAVAILABLE);
      }
      ac_addrlib_destroy(addrlib);
   }
   printf("AMD cached image: %u original layouts, %u bounded mip/array views; CPU-only models, uploads/submission unverified\n", layouts, views);
   return 0;
}
