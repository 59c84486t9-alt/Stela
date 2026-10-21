/*
 * Copyright © 2022 Collabora Ltd. and Red Hat Inc.
 * SPDX-License-Identifier: MIT
 */
#include "nvk_sampler.h"

#include "nvk_device.h"
#include "nvk_entrypoints.h"
#include "nvk_physical_device.h"

#include "vk_format.h"
#include "vk_sampler.h"

#include "util/bitpack_helpers.h"
#include "util/format/format_utils.h"
#include "util/format_srgb.h"

#include "cla097.h"
#include "clb197.h"
#include "cl9097tex.h"
#include "cla097tex.h"
#include "clb197tex.h"
#include "drf.h"

static struct nvk_sampler_header
nvk_sampler_get_header(const struct nvk_physical_device *pdev,
                       const struct vk_sampler_state *state)
{
   const struct nil_sampler_state values = {
      .address_mode_u = state->address_mode_u,
      .address_mode_v = state->address_mode_v,
      .address_mode_w = state->address_mode_w,
      .compare_enable = state->compare_enable,
      .compare_op = state->compare_op,
      .anisotropy_enable = state->anisotropy_enable,
      .max_anisotropy = state->max_anisotropy,
      .mag_filter = state->mag_filter,
      .min_filter = state->min_filter,
      .mipmap_mode = state->mipmap_mode,
      .flags = state->flags,
      .reduction_mode = state->reduction_mode,
      .mip_lod_bias = state->mip_lod_bias,
      .unnormalized_coordinates = state->unnormalized_coordinates,
      .min_lod = state->min_lod,
      .max_lod = state->max_lod,
      .border_color_value = state->border_color_value,
      .image_view_is_srgb = state->image_view_is_srgb,
      .border_color = state->border_color,
      .border_color_component_mapping = state->border_color_component_mapping,
   };
   return nil_sampler_pack(&pdev->info, &values);
}

struct nvk_sampler_header
nvk_txf_sampler_header(const struct nvk_physical_device *pdev)
{
   const struct vk_sampler_state sampler_state = {
      .mag_filter = VK_FILTER_NEAREST,
      .min_filter = VK_FILTER_NEAREST,
      .mipmap_mode = VK_SAMPLER_MIPMAP_MODE_NEAREST,
      .address_mode_u = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER,
      .address_mode_v = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER,
      .address_mode_w = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER,
      .border_color = VK_BORDER_COLOR_INT_TRANSPARENT_BLACK,
      .min_lod = 0.0,
      .max_lod = 16.0,
      .unnormalized_coordinates = true,
   };

   return nvk_sampler_get_header(pdev, &sampler_state);
}

VKAPI_ATTR VkResult VKAPI_CALL
nvk_CreateSampler(VkDevice device,
                  const VkSamplerCreateInfo *pCreateInfo,
                  const VkAllocationCallbacks *pAllocator,
                  VkSampler *pSampler)
{
   VK_FROM_HANDLE(nvk_device, dev, device);
   const struct nvk_physical_device *pdev = nvk_device_physical(dev);
   struct nvk_sampler *sampler;
   VkResult result;

   const VkOpaqueCaptureDescriptorDataCreateInfoEXT *cap_info =
      vk_find_struct_const(pCreateInfo->pNext,
                           OPAQUE_CAPTURE_DESCRIPTOR_DATA_CREATE_INFO_EXT);
   struct nvk_sampler_capture cap = {};
   if (cap_info != NULL)
      memcpy(&cap, cap_info->opaqueCaptureDescriptorData, sizeof(cap));

   sampler = vk_sampler_create(&dev->vk, pCreateInfo,
                               pAllocator, sizeof(*sampler));
   if (!sampler)
      return vk_error(dev, VK_ERROR_OUT_OF_HOST_MEMORY);

   struct vk_sampler_state state;
   vk_sampler_state_init(&state, pCreateInfo);

   {
      sampler->plane_count = 1;
      if (dev->nvkmd) {
         const struct nvk_sampler_header samp =
            nvk_sampler_get_header(pdev, &state);

         uint32_t desc_index = 0;
         if (cap_info != NULL) {
            desc_index = cap.planes[0].desc_index;
            result = nvk_descriptor_table_insert(dev, &dev->samplers,
                                                 desc_index, &samp, sizeof(samp));
         } else {
            result = nvk_descriptor_table_add(dev, &dev->samplers,
                                              &samp, sizeof(samp), &desc_index);
         }
         if (result != VK_SUCCESS) {
            vk_sampler_destroy(&dev->vk, pAllocator, &sampler->vk);
            return result;
         }

         sampler->planes[0].desc_index = desc_index;
      }
   }

   /* In order to support CONVERSION_SEPARATE_RECONSTRUCTION_FILTER_BIT, we
    * need multiple sampler planes: at minimum we will need one for luminance
    * (the default), and one for chroma.  Each sampler plane needs its own
    * sampler table entry.  However, sampler table entries are very rare on
    * NVIDIA; we only have 4096 entries for the whole VkDevice, and each plane
    * would burn one of those. So we make sure to allocate only the minimum
    * amount that we actually need (i.e., either 1 or 2), and then just copy
    * the last sampler plane out as far as we need to fill the number of image
    * planes.
    */

   if (state.has_ycbcr_conversion) {
      const VkFilter chroma_filter = state.ycbcr_conversion.chroma_filter;
      if (state.mag_filter != state.ycbcr_conversion.chroma_filter ||
          state.min_filter != state.ycbcr_conversion.chroma_filter) {
         struct vk_sampler_state chroma_state = state;
         chroma_state.mag_filter = chroma_filter;
         chroma_state.min_filter = chroma_filter;

         sampler->plane_count = 2;
         if (dev->nvkmd) {
            const struct nvk_sampler_header samp =
               nvk_sampler_get_header(pdev, &chroma_state);

            uint32_t desc_index = 0;
            if (cap_info != NULL) {
               desc_index = cap.planes[1].desc_index;
               result = nvk_descriptor_table_insert(dev, &dev->samplers,
                                                    desc_index,
                                                    &samp, sizeof(samp));
            } else {
               result = nvk_descriptor_table_add(dev, &dev->samplers,
                                                 &samp, sizeof(samp),
                                                 &desc_index);
            }
            if (result != VK_SUCCESS) {
               nvk_descriptor_table_remove(dev, &dev->samplers,
                                           sampler->planes[0].desc_index);
               vk_sampler_destroy(&dev->vk, pAllocator, &sampler->vk);
               return result;
            }

            sampler->planes[1].desc_index = desc_index;
         }
      }
   }

   *pSampler = nvk_sampler_to_handle(sampler);

   return VK_SUCCESS;
}

VKAPI_ATTR void VKAPI_CALL
nvk_DestroySampler(VkDevice device,
                   VkSampler _sampler,
                   const VkAllocationCallbacks *pAllocator)
{
   VK_FROM_HANDLE(nvk_device, dev, device);
   VK_FROM_HANDLE(nvk_sampler, sampler, _sampler);

   if (!sampler)
      return;

   if (dev->nvkmd) {
      for (uint8_t plane = 0; plane < sampler->plane_count; plane++) {
         nvk_descriptor_table_remove(dev, &dev->samplers,
                                     sampler->planes[plane].desc_index);
      }

   }
   vk_sampler_destroy(&dev->vk, pAllocator, &sampler->vk);
}

VKAPI_ATTR VkResult VKAPI_CALL
nvk_GetSamplerOpaqueCaptureDescriptorDataEXT(
    VkDevice _device,
    const VkSamplerCaptureDescriptorDataInfoEXT *pInfo,
    void *pData)
{
   VK_FROM_HANDLE(nvk_sampler, sampler, pInfo->sampler);

   struct nvk_sampler_capture cap = {};
   for (uint8_t p = 0; p < sampler->plane_count; p++)
      cap.planes[p].desc_index = sampler->planes[p].desc_index;

   memcpy(pData, &cap, sizeof(cap));

   return VK_SUCCESS;
}
