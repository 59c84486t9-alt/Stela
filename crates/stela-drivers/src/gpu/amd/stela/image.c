/*
 * Copyright © 2016 Red Hat.
 * Copyright © 2016 Bas Nieuwenhuizen
 * Copyright © 2015 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 *
 * Single-2D texture state policy derives from the retained RADV image-view
 * consumer. Device, ownership and bounded-input checks are Stela integration.
 */
#include "image.h"
#include "amd/common/ac_descriptors.h"
#include "amd/common/ac_formats.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_surface.h"
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

static enum stela_amd_image_status
compute_layout(const struct radeon_info *info, struct ac_addrlib *addrlib,
                const struct stela_amd_linear_image *image, struct radeon_surf *surf,
                struct stela_amd_image_layout *layout, enum pipe_format *format)
{
   struct stela_amd_raw_buffer_facts facts;
   enum stela_amd_image_status status = buffer_status(stela_amd_query_raw_buffer_facts(info, &facts));
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   if (!addrlib || !image || !image->width || !image->height)
      return STELA_AMD_IMAGE_INVALID;
   if (info->family <= CHIP_UNKNOWN || info->family >= CHIP_LAST ||
       ac_get_gfx_level(info->family) != info->gfx_level || !info->family_id)
      return STELA_AMD_IMAGE_DEVICE_INFO_UNAVAILABLE;
   if (!info->has_image_opcodes || image->width > 16384 || image->height > 16384)
      return STELA_AMD_IMAGE_UNSUPPORTED;
   switch (image->format) {
   case STELA_AMD_IMAGE_RGBA8_UNORM: *format = PIPE_FORMAT_R8G8B8A8_UNORM; break;
   case STELA_AMD_IMAGE_RGBA8_UINT: *format = PIPE_FORMAT_R8G8B8A8_UINT; break;
   case STELA_AMD_IMAGE_RGBA8_SRGB: *format = PIPE_FORMAT_R8G8B8A8_SRGB; break;
   default: return STELA_AMD_IMAGE_UNSUPPORTED;
   }
   if (info->gfx_level >= GFX10) {
      const struct gfx10_format *fmt = &ac_get_gfx10_format_table(info->gfx_level)[*format];
      if (!fmt->img_format || fmt->buffers_only)
         return STELA_AMD_IMAGE_UNSUPPORTED;
   } else {
      const struct util_format_description *desc = util_format_description(*format);
      if (ac_translate_tex_dataformat(info, desc, util_format_get_first_non_void_channel(*format)) == ~0u)
         return STELA_AMD_IMAGE_UNSUPPORTED;
   }
   const struct ac_surf_config config = {
      .info = {.width = image->width, .height = image->height, .depth = 1, .array_size = 1,
               .levels = 1, .samples = 1, .storage_samples = 1, .num_channels = 4},
      .blk_w = 1, .blk_h = 1, .bpe = 4,
      .surf_flags = RADEON_SURF_DISABLE_DCC | RADEON_SURF_NO_RENDER_TARGET,
      .modifier = DRM_FORMAT_MOD_INVALID,
   };
   if (ac_compute_surface(addrlib, info, &config, RADEON_SURF_MODE_LINEAR_ALIGNED, surf))
      return STELA_AMD_IMAGE_LAYOUT_FAILED;
   if (!surf->total_size || surf->alignment_log2 >= 63 || !surf->is_linear ||
       surf->meta_size || surf->meta_offset || surf->cmask_size || surf->cmask_offset ||
       surf->fmask_size || surf->fmask_offset || surf->has_stencil ||
       (info->gfx_level >= GFX12 && surf->u.gfx9.gfx12_enable_dcc))
      return STELA_AMD_IMAGE_UNSUPPORTED;
   const uint64_t stride = ac_surface_get_plane_stride(info->gfx_level, surf, 0, 0);
   if (stride < (uint64_t)image->width * 4 ||
       image->height - 1 > (UINT64_MAX - (uint64_t)image->width * 4) / stride ||
       surf->total_size < stride * (image->height - 1) + (uint64_t)image->width * 4)
      return STELA_AMD_IMAGE_LAYOUT_FAILED;
   *layout = (struct stela_amd_image_layout) {
      .bytes = surf->total_size,
      .alignment = MAX2(UINT64_C(256), UINT64_C(1) << surf->alignment_log2),
      .row_pitch = stride,
   };
   return STELA_AMD_IMAGE_OK;
}

enum stela_amd_image_status
stela_amd_query_linear_image_layout(const struct radeon_info *info, struct ac_addrlib *addrlib,
                                   const struct stela_amd_linear_image *image,
                                   struct stela_amd_image_layout *layout)
{
   if (!layout)
      return STELA_AMD_IMAGE_INVALID;
   struct radeon_surf surf;
   struct stela_amd_image_layout result;
   enum pipe_format format;
   const enum stela_amd_image_status status = compute_layout(info, addrlib, image, &surf, &result, &format);
   if (status == STELA_AMD_IMAGE_OK)
      *layout = result;
   return status;
}

enum stela_amd_image_status
stela_amd_build_linear_image(const struct radeon_info *info, struct ac_addrlib *addrlib,
                             const struct stela_amd_linear_image *image,
                             const struct stela_amd_buffer_view *view,
                             uint32_t descriptor[8], struct stela_amd_image_layout *layout)
{
   if (!view || !descriptor)
      return STELA_AMD_IMAGE_INVALID;
   struct radeon_surf surf;
   struct stela_amd_image_layout result;
   enum pipe_format format;
   enum stela_amd_image_status status = compute_layout(info, addrlib, image, &surf, &result, &format);
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   if (view->range < result.bytes)
      return STELA_AMD_IMAGE_INVALID;
   struct stela_amd_buffer_view aligned = *view;
   /* Validate the caller's alignment before combining with the layout's. */
   if (!aligned.required_alignment || (aligned.required_alignment & (aligned.required_alignment - 1)))
      return STELA_AMD_IMAGE_INVALID;
   aligned.required_alignment = MAX2(aligned.required_alignment, result.alignment);
   uint64_t address;
   status = buffer_status(stela_amd_buffer_view_address(info, &aligned, &address));
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   /* The retained RADV single-layer 2D state uses last-layer (0) for GFX10+
    * and total depth (1) for GFX6-9. No frontend API is linked or translated.
    * Reference: Mesa31e9a6b2e95e30d84bf3177d1f497d063e59b6b2,
    * src/amd/vulkan/radv_image_view.c gfx{6,10}_make_texture_descriptor and
    * radv_set_mutable_tex_desc_fields. Actual encoders remain unchanged. */
   const struct ac_texture_state texture = {
      .surf = &surf, .format = format, .img_format = format,
      .width = image->width, .height = image->height, .depth = info->gfx_level >= GFX10 ? 0 : 1,
      .type = V_008F1C_SQ_RSRC_IMG_2D,
      .swizzle = {PIPE_SWIZZLE_X, PIPE_SWIZZLE_Y, PIPE_SWIZZLE_Z, PIPE_SWIZZLE_W},
      .num_samples = 1, .num_storage_samples = 1, .num_levels = 1,
      .aniso_single_level = true, /* Current slice requires non-anisotropic sampling. */
   };
   const struct ac_mutable_tex_state mutable = {
      .surf = &surf, .va = address,
      .gfx6 = {.base_level_info = &surf.u.legacy.level[0], .block_width = 1},
   };
   uint32_t words[8];
   ac_build_texture_descriptor(info, &texture, words);
   ac_set_mutable_tex_desc_fields(info, &mutable, words);
   memcpy(descriptor, words, sizeof(words));
   if (layout)
      *layout = result;
   return STELA_AMD_IMAGE_OK;
}
