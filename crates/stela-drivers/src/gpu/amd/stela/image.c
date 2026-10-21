/* SPDX-License-Identifier: MIT */
#include "image_resource.h"

static enum stela_amd_image_status
prepare_linear(const struct radeon_info *info, struct ac_addrlib *addrlib,
                const struct stela_amd_linear_image *image,
                struct stela_amd_image_layout_state *layout)
{
   if (!image)
      return stela_amd_prepare_image_layout(info, addrlib, NULL, layout);
   const struct stela_amd_image_description description = {
      .width = image->width, .height = image->height, .levels = 1, .layers = 1,
      .format = image->format, .kind = STELA_AMD_IMAGE_2D, .tiling = STELA_AMD_IMAGE_LINEAR,
   };
   return stela_amd_prepare_image_layout(info, addrlib, &description, layout);
}

enum stela_amd_image_status
stela_amd_query_linear_image_layout(const struct radeon_info *info, struct ac_addrlib *addrlib,
                                   const struct stela_amd_linear_image *image,
                                   struct stela_amd_image_layout *layout)
{
   if (!layout)
      return STELA_AMD_IMAGE_INVALID;
   struct stela_amd_image_layout_state prepared;
   const enum stela_amd_image_status status = prepare_linear(info, addrlib, image, &prepared);
   if (status == STELA_AMD_IMAGE_OK)
      *layout = prepared.storage;
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
   struct stela_amd_image_layout_state prepared;
   enum stela_amd_image_status status = prepare_linear(info, addrlib, image, &prepared);
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   struct stela_amd_image_resource resource;
   status = stela_amd_bind_image_resource(&prepared, view, &resource);
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   const struct stela_amd_image_view image_view = {.level_count = 1, .layer_count = 1, .kind = STELA_AMD_IMAGE_2D};
   status = stela_amd_build_image_view(info, &resource, view, &image_view, descriptor);
   if (status == STELA_AMD_IMAGE_OK && layout)
      *layout = prepared.storage;
   return status;
}
