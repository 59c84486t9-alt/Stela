/*
 * Copyright © 2023 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include "intel_device_info.h"
#include "i915/intel_device_info.h"
#include "util/bitscan.h"
#include "drm-uapi/i915_drm.h"

void
intel_device_info_i915_update_from_topology(struct intel_device_info *devinfo,
                     const struct drm_i915_query_topology_info *topology)
{
   intel_device_info_topology_reset_masks(devinfo);

   assert(topology->max_slices > 0);
   assert(topology->max_subslices > 0);
   assert(topology->max_eus_per_subslice > 0);

   devinfo->subslice_slice_stride = topology->subslice_stride;

   devinfo->eu_subslice_stride = DIV_ROUND_UP(topology->max_eus_per_subslice, 8);
   devinfo->eu_slice_stride = topology->max_subslices * devinfo->eu_subslice_stride;

   assert(sizeof(devinfo->slice_masks) >= DIV_ROUND_UP(topology->max_slices, 8));
   memcpy(&devinfo->slice_masks, topology->data, DIV_ROUND_UP(topology->max_slices, 8));
   devinfo->max_slices = topology->max_slices;
   devinfo->max_subslices_per_slice = topology->max_subslices;
   devinfo->max_eus_per_subslice = topology->max_eus_per_subslice;

   uint32_t subslice_mask_len =
      topology->max_slices * topology->subslice_stride;
   assert(sizeof(devinfo->subslice_masks) >= subslice_mask_len);
   memcpy(devinfo->subslice_masks, &topology->data[topology->subslice_offset],
          subslice_mask_len);

   uint32_t eu_mask_len =
      topology->eu_stride * topology->max_subslices * topology->max_slices;
   assert(sizeof(devinfo->eu_masks) >= eu_mask_len);
   memcpy(devinfo->eu_masks, &topology->data[topology->eu_offset], eu_mask_len);

   /* Now that all the masks are in place, update the counts. */
   intel_device_info_topology_update_counts(devinfo);
   intel_device_info_update_pixel_pipes(devinfo, devinfo->subslice_masks);
   intel_device_info_update_l3_banks(devinfo);
}

/* Generate detailed mask from the I915_PARAM_SLICE_MASK,
 * I915_PARAM_SUBSLICE_MASK & I915_PARAM_EU_TOTAL getparam.
 */
bool
intel_device_info_i915_update_from_masks(struct intel_device_info *devinfo, uint32_t slice_mask,
                       uint32_t subslice_mask, uint32_t n_eus)
{
   struct drm_i915_query_topology_info *topology;

   assert((slice_mask & 0xff) == slice_mask);

   size_t data_length = 100;

   topology = calloc(1, sizeof(*topology) + data_length);
   if (!topology)
      return false;

   topology->max_slices = util_last_bit(slice_mask);
   topology->max_subslices = util_last_bit(subslice_mask);

   topology->subslice_offset = DIV_ROUND_UP(topology->max_slices, 8);
   topology->subslice_stride = DIV_ROUND_UP(topology->max_subslices, 8);

   uint32_t n_subslices = __builtin_popcount(slice_mask) *
      __builtin_popcount(subslice_mask);
   uint32_t max_eus_per_subslice = DIV_ROUND_UP(n_eus, n_subslices);
   uint32_t eu_mask = (1U << max_eus_per_subslice) - 1;

   topology->max_eus_per_subslice = max_eus_per_subslice;
   topology->eu_offset = topology->subslice_offset +
      topology->max_slices * DIV_ROUND_UP(topology->max_subslices, 8);
   topology->eu_stride = DIV_ROUND_UP(max_eus_per_subslice, 8);

   /* Set slice mask in topology */
   for (int b = 0; b < topology->subslice_offset; b++)
      topology->data[b] = (slice_mask >> (b * 8)) & 0xff;

   for (int s = 0; s < topology->max_slices; s++) {

      /* Set subslice mask in topology */
      for (int b = 0; b < topology->subslice_stride; b++) {
         int subslice_offset = topology->subslice_offset +
            s * topology->subslice_stride + b;

         topology->data[subslice_offset] = (subslice_mask >> (b * 8)) & 0xff;
      }

      /* Set eu mask in topology */
      for (int ss = 0; ss < topology->max_subslices; ss++) {
         for (int b = 0; b < topology->eu_stride; b++) {
            int eu_offset = topology->eu_offset +
               (s * topology->max_subslices + ss) * topology->eu_stride + b;

            topology->data[eu_offset] = (eu_mask >> (b * 8)) & 0xff;
         }
      }
   }

   intel_device_info_i915_update_from_topology(devinfo, topology);
   free(topology);

   return true;
}
