/*
 * Copyright © 2016 Red Hat.
 * Copyright © 2016 Bas Nieuwenhuizen
 * Copyright © 2015 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 *
 * Sampled RGBA 2D/array state policy derives from pinned Mesa
 * 31e9a6b2e95e30d84bf3177d1f497d063e59b6b2 src/amd/vulkan/radv_image_view.c
 * gfx{6,10}_make_texture_descriptor/radv_image_view_make_descriptor and
 * radv_set_mutable_tex_desc_fields. Array target identity follows the original
 * src/gallium/drivers/radeonsi/si_state.c si_tex_dim policy, including a one-layer
 * array. No frontend API is linked. All original encoding/layout code is reused.
 */
#include "image_resource.h"
#include "amd/common/ac_descriptors.h"
#include "amd/common/ac_formats.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/gfx10_format_table.h"
#include "amd/common/sid.h"
#include "drm-uapi/drm_fourcc.h"

#include <string.h>

static enum stela_amd_image_status
buffer_status(enum stela_amd_buffer_status status)
{
   switch (status) {
   case STELA_AMD_BUFFER_OK: return STELA_AMD_IMAGE_OK;
   case STELA_AMD_BUFFER_INVALID: return STELA_AMD_IMAGE_INVALID;
   case STELA_AMD_BUFFER_UNSUPPORTED: return STELA_AMD_IMAGE_UNSUPPORTED;
   case STELA_AMD_BUFFER_DEVICE_INFO_UNAVAILABLE: return STELA_AMD_IMAGE_DEVICE_INFO_UNAVAILABLE;
   }
   return STELA_AMD_IMAGE_INVALID;
}

static uint32_t
layer_limit(enum amd_gfx_level gfx_level)
{
   uint32_t all = UINT32_MAX;
   struct ac_texture_state representable = {0};
   /* Derive the current original state bitfield limits instead of assuming the
    * newest hardware register width is available through this retained ABI. */
   representable.first_layer = all;
   representable.last_layer = all;
   uint32_t limit = MIN2(representable.first_layer, representable.last_layer) + 1;
   if (gfx_level < GFX9) {
      limit = MIN3(limit, G_008F20_DEPTH(all) + 1, G_008F24_LAST_ARRAY(all) + 1);
      limit = MIN2(limit, G_008F24_BASE_ARRAY(all) + 1);
   } else if (gfx_level == GFX9) {
      limit = MIN3(limit, G_008F20_DEPTH(all) + 1, G_008F24_BASE_ARRAY(all) + 1);
   } else {
      limit = MIN3(limit, (gfx_level >= GFX12 ? G_00A010_DEPTH_GFX12(all) : G_00A010_DEPTH_GFX10(all)) + 1,
                   G_00A010_BASE_ARRAY(all) + 1);
   }
   /* Preserve both original driver policies, which intentionally bound the
    * texture/layered-rendering intersection below some register fields:
    * radv_physical_device.c image_props.max_array_layers and
    * gallium/drivers/radeonsi/gfx/si_gfx_screen.c max_texture_array_layers. */
   limit = MIN2(limit, gfx_level >= GFX10 ? 8192 : 2048);
   return MIN2(limit, UINT16_MAX); /* Original ac_surf_info.array_size. */
}

enum stela_amd_image_status
stela_amd_prepare_image_layout(const struct radeon_info *info, struct ac_addrlib *addrlib,
                               const struct stela_amd_image_description *description,
                               struct stela_amd_image_layout_state *layout)
{
   struct stela_amd_raw_buffer_facts facts;
   enum stela_amd_image_status status = buffer_status(stela_amd_query_raw_buffer_facts(info, &facts));
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   if (!addrlib || !description || !layout || !description->width || !description->height ||
       !description->levels || !description->layers)
      return STELA_AMD_IMAGE_INVALID;
   if (info->family <= CHIP_UNKNOWN || info->family >= CHIP_LAST ||
       ac_get_gfx_level(info->family) != info->gfx_level || !info->family_id)
      return STELA_AMD_IMAGE_DEVICE_INFO_UNAVAILABLE;
   if (!info->has_image_opcodes || description->width > 16384 || description->height > 16384 ||
       description->levels > RADEON_SURF_MAX_LEVELS || description->layers > layer_limit(info->gfx_level))
      return STELA_AMD_IMAGE_UNSUPPORTED;
   if ((unsigned)description->kind > STELA_AMD_IMAGE_2D_ARRAY ||
       (unsigned)description->tiling > STELA_AMD_IMAGE_TILED ||
       (unsigned)description->cpu_transfer > STELA_AMD_IMAGE_CPU_COPY)
      return STELA_AMD_IMAGE_UNSUPPORTED;
   if (description->kind == STELA_AMD_IMAGE_2D && description->layers != 1)
      return STELA_AMD_IMAGE_INVALID;
   if (description->levels > util_logbase2(MAX2(description->width, description->height)) + 1)
      return STELA_AMD_IMAGE_INVALID;
   /* Original legacy CMASK computation requires actual queried pipe geometry.
    * Its informational single-sample size does not allocate/enable CMASK. */
   if (description->tiling == STELA_AMD_IMAGE_TILED && info->gfx_level < GFX9 &&
       info->num_tile_pipes != 2 && info->num_tile_pipes != 4 &&
       info->num_tile_pipes != 8 && info->num_tile_pipes != 16)
      return STELA_AMD_IMAGE_DEVICE_INFO_UNAVAILABLE;

   struct stela_amd_image_layout_state result = {.device = info, .addrlib = addrlib, .description = *description};
   switch (description->format) {
   case STELA_AMD_IMAGE_RGBA8_UNORM: result.format = PIPE_FORMAT_R8G8B8A8_UNORM; break;
   case STELA_AMD_IMAGE_RGBA8_UINT: result.format = PIPE_FORMAT_R8G8B8A8_UINT; break;
   case STELA_AMD_IMAGE_RGBA8_SRGB: result.format = PIPE_FORMAT_R8G8B8A8_SRGB; break;
   default: return STELA_AMD_IMAGE_UNSUPPORTED;
   }
   if (info->gfx_level >= GFX10) {
      const struct gfx10_format *fmt = &ac_get_gfx10_format_table(info->gfx_level)[result.format];
      if (!fmt->img_format || fmt->buffers_only)
         return STELA_AMD_IMAGE_UNSUPPORTED;
   } else {
      const struct util_format_description *desc = util_format_description(result.format);
      if (ac_translate_tex_dataformat(info, desc, util_format_get_first_non_void_channel(result.format)) == ~0u)
         return STELA_AMD_IMAGE_UNSUPPORTED;
   }
   result.config = (struct ac_surf_config) {
      .info = {.width = description->width, .height = description->height, .depth = 1,
               .array_size = description->layers, .levels = description->levels,
               .samples = 1, .storage_samples = 1, .num_channels = 4},
      .is_array = description->kind == STELA_AMD_IMAGE_2D_ARRAY,
      .blk_w = 1, .blk_h = 1, .bpe = 4,
      .surf_flags = RADEON_SURF_DISABLE_DCC | RADEON_SURF_NO_RENDER_TARGET,
      .modifier = DRM_FORMAT_MOD_INVALID,
   };
   /* Original radv_image.c HOST_TRANSFER creation policy. In particular this
    * prevents randomized tile-swizzle and original unsupported GFX11 256KiB
    * copy layouts. It grants no mapping/access/visibility rights. */
   if (description->cpu_transfer == STELA_AMD_IMAGE_CPU_COPY)
      result.config.surf_flags |= RADEON_SURF_HOST_TRANSFER | RADEON_SURF_NO_FMASK |
                                  RADEON_SURF_NO_HTILE | RADEON_SURF_DISABLE_DCC;
   struct radeon_surf *surf = &result.surface;
   if (ac_compute_surface(addrlib, info, &result.config,
                          description->tiling == STELA_AMD_IMAGE_LINEAR ? RADEON_SURF_MODE_LINEAR_ALIGNED :
                                                                        RADEON_SURF_MODE_2D,
                          surf))
      return STELA_AMD_IMAGE_LAYOUT_FAILED;
   if (!surf->total_size || surf->total_size != surf->surf_size || surf->alignment_log2 >= 63 ||
       surf->meta_size || surf->meta_offset || surf->display_dcc_offset || surf->cmask_offset ||
       surf->fmask_size || surf->fmask_offset || surf->has_stencil ||
       (info->gfx_level >= GFX12 && surf->u.gfx9.gfx12_enable_dcc))
      return STELA_AMD_IMAGE_UNSUPPORTED;
   if (description->tiling == STELA_AMD_IMAGE_LINEAR && !surf->is_linear)
      return STELA_AMD_IMAGE_LAYOUT_FAILED;
   if (info->gfx_level < GFX9) {
      uint64_t previous_end = 0;
      for (unsigned level = 0; level < description->levels; level++) {
         const struct legacy_surf_level *mip = &surf->u.legacy.level[level];
         const uint64_t start = (uint64_t)mip->offset_256B * 256;
         const uint64_t size = (uint64_t)mip->slice_size_dw * 4 * description->layers;
         /* Original legacy offsets/slice-size fields are narrower than the
          * overall size. Refuse any wrapped/overlapping/unrepresentable tail. */
         if (!size || start < previous_end || start > surf->surf_size || size > surf->surf_size - start)
            return STELA_AMD_IMAGE_UNSUPPORTED;
         previous_end = start + size;
      }
   }
   uint64_t stride = 0;
   if (surf->is_linear) {
      stride = ac_surface_get_plane_stride(info->gfx_level, surf, 0, 0);
      if (stride < (uint64_t)description->width * 4 ||
          description->height - 1 > (UINT64_MAX - (uint64_t)description->width * 4) / stride ||
          surf->total_size < stride * (description->height - 1) + (uint64_t)description->width * 4)
         return STELA_AMD_IMAGE_LAYOUT_FAILED;
   }
   result.storage = (struct stela_amd_image_layout) {
      .bytes = surf->total_size, .alignment = MAX2(UINT64_C(256), UINT64_C(1) << surf->alignment_log2),
      .row_pitch = stride,
   };
   *layout = result;
   return STELA_AMD_IMAGE_OK;
}

static bool
same_view(const struct stela_amd_buffer_view *a, const struct stela_amd_buffer_view *b)
{
   return a->allocation_va == b->allocation_va && a->allocation_bytes == b->allocation_bytes &&
          a->offset == b->offset && a->range == b->range && a->required_alignment == b->required_alignment;
}

enum stela_amd_image_status
stela_amd_bind_image_resource(const struct stela_amd_image_layout_state *layout,
                              const struct stela_amd_buffer_view *owner_view,
                              struct stela_amd_image_resource *resource)
{
   if (!layout || !layout->device || !owner_view || !resource || !layout->storage.bytes ||
       owner_view->range < layout->storage.bytes || !owner_view->required_alignment ||
       (owner_view->required_alignment & (owner_view->required_alignment - 1)))
      return STELA_AMD_IMAGE_INVALID;
   struct stela_amd_buffer_view aligned = *owner_view;
   aligned.required_alignment = MAX2(aligned.required_alignment, layout->storage.alignment);
   uint64_t address;
   enum stela_amd_image_status status = buffer_status(stela_amd_buffer_view_address(layout->device, &aligned, &address));
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   *resource = (struct stela_amd_image_resource) {
      .device = layout->device, .layout = layout, .owner_view = owner_view,
      .bound_view = *owner_view, .address = address,
   };
   return STELA_AMD_IMAGE_OK;
}

enum stela_amd_image_status
stela_amd_validate_image_resource(const struct radeon_info *info,
                                  const struct stela_amd_image_resource *resource,
                                  const struct stela_amd_buffer_view *owner_view)
{
   if (!info || !resource || !resource->layout || !owner_view ||
       resource->device != info || resource->layout->device != info || resource->owner_view != owner_view ||
       !same_view(&resource->bound_view, owner_view))
      return STELA_AMD_IMAGE_INVALID;
   struct stela_amd_image_resource checked;
   enum stela_amd_image_status status = stela_amd_bind_image_resource(resource->layout, owner_view, &checked);
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   return checked.address == resource->address ? STELA_AMD_IMAGE_OK : STELA_AMD_IMAGE_INVALID;
}

enum stela_amd_image_status
stela_amd_build_image_view(const struct radeon_info *info,
                           const struct stela_amd_image_resource *resource,
                           const struct stela_amd_buffer_view *owner_view,
                           const struct stela_amd_image_view *view,
                           uint32_t descriptor[8])
{
   if (!view || !descriptor)
      return STELA_AMD_IMAGE_INVALID;
   enum stela_amd_image_status status = stela_amd_validate_image_resource(info, resource, owner_view);
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   const struct stela_amd_image_layout_state *layout = resource->layout;
   const struct stela_amd_image_description *description = &layout->description;
   if (!view->level_count || view->first_level >= description->levels ||
       view->level_count > description->levels - view->first_level ||
       !view->layer_count || view->first_layer >= description->layers ||
       view->layer_count > description->layers - view->first_layer)
      return STELA_AMD_IMAGE_INVALID;
   if (view->kind != description->kind)
      return STELA_AMD_IMAGE_UNSUPPORTED;
   const uint32_t last_layer = view->first_layer + view->layer_count - 1;
   const struct radeon_surf *surf = &layout->surface;
   const struct ac_texture_state texture = {
      .surf = surf, .format = layout->format, .img_format = layout->format,
      .width = description->width, .height = description->height,
      .depth = info->gfx_level >= GFX10 ? last_layer : description->layers,
      .type = description->kind == STELA_AMD_IMAGE_2D_ARRAY ? V_008F1C_SQ_RSRC_IMG_2D_ARRAY : V_008F1C_SQ_RSRC_IMG_2D,
      .swizzle = {PIPE_SWIZZLE_X, PIPE_SWIZZLE_Y, PIPE_SWIZZLE_Z, PIPE_SWIZZLE_W},
      .num_samples = 1, .num_storage_samples = 1,
      .first_level = view->first_level, .last_level = view->first_level + view->level_count - 1,
      .num_levels = description->levels, .first_layer = view->first_layer, .last_layer = last_layer,
      .aniso_single_level = true,
   };
   const struct ac_mutable_tex_state mutable = {
      .surf = surf, .va = resource->address,
      /* Sampled uncompressed RGBA views keep original mip0 address/pitch on
       * GFX6-8. BASE_LEVEL selects the requested mip; don't minify/rebase it as
       * original storage/compressed/depth-view special cases would require. */
      .gfx6 = {.base_level_info = &surf->u.legacy.level[0], .block_width = 1},
   };
   uint32_t words[8];
   ac_build_texture_descriptor(info, &texture, words);
   ac_set_mutable_tex_desc_fields(info, &mutable, words);
   memcpy(descriptor, words, sizeof(words));
   return STELA_AMD_IMAGE_OK;
}
