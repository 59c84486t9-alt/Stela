/*
 * Copyright © 2011 Red Hat All Rights Reserved.
 * Copyright © 2017 Advanced Micro Devices, Inc.
 * Copyright © 2025 Valve Corporation
 *
 * SPDX-License-Identifier: MIT
 *
 * Original ac_surface CPU-copy/metadata inputs and RADV host-copy policy are
 * retained from Mesa31e9a6b2e95e30d84bf3177d1f497d063e59b6b2. Bounds, ownership
 * contracts and staging-window requirements are Stela integration. No tiler,
 * allocator, synchronization operation or original hardware algorithm is added.
 */
#include "image_copy.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/addrlib/inc/addrinterface.h"
#include "util/u_math.h"

#include <limits.h>
#include <string.h>

static bool
add64(uint64_t a, uint64_t b, uint64_t *result)
{
   if (b > UINT64_MAX - a)
      return false;
   *result = a + b;
   return true;
}

static bool
mul64(uint64_t a, uint64_t b, uint64_t *result)
{
   if (a && b > UINT64_MAX / a)
      return false;
   *result = a * b;
   return true;
}

/* Query the SAME original surface inputs used inside the retained copy helper.
 * This supplies actual mip-tail coordinates for safe host-pointer rebasing;
 * deriving them from logical dimensions would invent a tiling algorithm. */
static enum stela_amd_image_status
tiled_prefix(const struct stela_amd_image_layout_state *layout,
              const struct stela_amd_image_copy_region *region, uint64_t *prefix)
{
   const struct radeon_surf *surf = &layout->surface;
   uint32_t tail_x, tail_y, tail_z;
   const ADDR_HANDLE handle = ac_addrlib_get_handle(layout->addrlib);
   if (layout->device->gfx_level >= GFX12) {
      ADDR3_COMPUTE_SURFACE_INFO_INPUT input = {
         .size = sizeof(input), .swizzleMode = surf->u.gfx9.swizzle_mode,
         .resourceType = (AddrResourceType)surf->u.gfx9.resource_type,
         .format = ADDR_FMT_32, .bpp = 32,
         .width = layout->config.info.width, .height = layout->config.info.height,
         .numSlices = layout->config.info.array_size, .numMipLevels = layout->config.info.levels,
         .numSamples = 1,
      };
      ADDR3_MIP_INFO mips[RADEON_SURF_MAX_LEVELS] = {0};
      ADDR3_COMPUTE_SURFACE_INFO_OUTPUT output = {.size = sizeof(output), .pMipInfo = mips};
      if (Addr3ComputeSurfaceInfo(handle, &input, &output) != ADDR_OK || output.surfSize != surf->surf_size)
         return STELA_AMD_IMAGE_LAYOUT_FAILED;
      if (output.blockExtent.depth != 1)
         return STELA_AMD_IMAGE_UNSUPPORTED;
      tail_x = mips[region->level].mipTailCoordX;
      tail_y = mips[region->level].mipTailCoordY;
      tail_z = mips[region->level].mipTailCoordZ;
   } else {
      ADDR2_COMPUTE_SURFACE_INFO_INPUT input = {
         .size = sizeof(input), .flags = {.color = 1}, .swizzleMode = surf->u.gfx9.swizzle_mode,
         .resourceType = (AddrResourceType)surf->u.gfx9.resource_type,
         .format = ADDR_FMT_32, .bpp = 32,
         .width = layout->config.info.width, .height = layout->config.info.height,
         .numSlices = layout->config.info.array_size, .numMipLevels = layout->config.info.levels,
         .numSamples = 1,
      };
      ADDR2_MIP_INFO mips[RADEON_SURF_MAX_LEVELS] = {0};
      ADDR2_COMPUTE_SURFACE_INFO_OUTPUT output = {.size = sizeof(output), .pMipInfo = mips};
      if (Addr2ComputeSurfaceInfo(handle, &input, &output) != ADDR_OK || output.surfSize != surf->surf_size)
         return STELA_AMD_IMAGE_LAYOUT_FAILED;
      if (output.blockSlices != 1)
         return STELA_AMD_IMAGE_UNSUPPORTED;
      tail_x = mips[region->level].mipTailCoordX;
      tail_y = mips[region->level].mipTailCoordY;
      tail_z = mips[region->level].mipTailCoordZ;
   }
   /* Original rawOrigin, x*4, and origin+extent arithmetic uses UINT_32 even
    * though the public pitches are UINT_64. Validate before those operations. */
   const uint64_t x = (uint64_t)region->x + tail_x;
   const uint64_t y = (uint64_t)region->y + tail_y;
   const uint64_t z = (uint64_t)region->first_layer + tail_z;
   if (x > UINT32_MAX / 4 || region->width > UINT32_MAX / 4 - x ||
       y > UINT32_MAX - region->height || z > UINT32_MAX - region->layer_count)
      return STELA_AMD_IMAGE_UNSUPPORTED;
   *prefix = x * 4;
   return STELA_AMD_IMAGE_OK;
}

static bool
linear_layer(const struct stela_amd_image_layout_state *layout, unsigned level, unsigned layer,
               uint64_t *base, uint64_t *stride)
{
   const struct radeon_surf *surf = &layout->surface;
   *stride = ac_surface_get_plane_stride(layout->device->gfx_level, surf, 0, level);
   uint64_t layer_offset;
   if (layout->device->gfx_level >= GFX9) {
      if (!mul64(layer, surf->u.gfx9.surf_slice_size, &layer_offset) ||
          !add64(layer_offset, surf->u.gfx9.surf_offset, base) ||
          !add64(*base, surf->u.gfx9.offset[level], base))
         return false;
   } else {
      const struct legacy_surf_level *mip = &surf->u.legacy.level[level];
      if (mip->mode != RADEON_SURF_MODE_LINEAR_ALIGNED ||
          !mul64(layer, (uint64_t)mip->slice_size_dw * 4, &layer_offset) ||
          !add64(layer_offset, (uint64_t)mip->offset_256B * 256, base))
         return false;
   }
   return true;
}

static bool
linear_region(const struct stela_amd_image_layout_state *layout,
                const struct stela_amd_image_copy_region *region, unsigned layer,
                uint64_t *start, uint64_t *stride)
{
   uint64_t row, tail;
   if (!linear_layer(layout, region->level, layer, start, stride) ||
       *stride < (uint64_t)u_minify(layout->description.width, region->level) * 4 ||
       !mul64(region->y, *stride, &row) || !add64(*start, row, start) ||
       !add64(*start, (uint64_t)region->x * 4, start) ||
       !mul64(region->height - 1, *stride, &tail) ||
       !add64(tail, (uint64_t)region->width * 4, &tail))
      return false;
   return *start <= layout->storage.bytes && tail <= layout->storage.bytes - *start;
}

enum stela_amd_image_status
stela_amd_query_image_copy(const struct radeon_info *info, struct ac_addrlib *addrlib,
                            const struct stela_amd_image_resource *resource,
                            const struct stela_amd_buffer_view *owner_view,
                            const struct stela_amd_image_copy_region *region,
                            uint64_t row_pitch, uint64_t slice_pitch,
                            struct stela_amd_image_copy_requirements *requirements)
{
   enum stela_amd_image_status status = stela_amd_validate_image_resource(info, resource, owner_view);
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   const struct stela_amd_image_layout_state *layout = resource->layout;
   const struct stela_amd_image_description *description = &layout->description;
   if (!addrlib || addrlib != layout->addrlib || !region || !requirements ||
       region->level >= description->levels || !region->layer_count ||
       region->first_layer >= description->layers || region->layer_count > description->layers - region->first_layer ||
       !region->width || !region->height)
      return STELA_AMD_IMAGE_INVALID;
   const uint32_t width = u_minify(description->width, region->level);
   const uint32_t height = u_minify(description->height, region->level);
   if (region->x >= width || region->width > width - region->x ||
       region->y >= height || region->height > height - region->y)
      return STELA_AMD_IMAGE_INVALID;
   uint64_t rows, envelope, copied;
   if (row_pitch < (uint64_t)region->width * 4 || row_pitch > SIZE_MAX || slice_pitch > SIZE_MAX ||
       !mul64(row_pitch, region->height, &rows) || slice_pitch < rows ||
       !mul64(slice_pitch, region->layer_count, &envelope) ||
       !mul64((uint64_t)region->width * 4, region->height, &copied) ||
       !mul64(copied, region->layer_count, &copied))
      return STELA_AMD_IMAGE_INVALID;
   struct stela_amd_image_copy_requirements result = {.host_envelope = envelope, .copied_bytes = copied};
   if (layout->surface.is_linear) {
      /* Monotonic positive row spans prove every row in every layer fits,
       * without forming a pointer or writing before all layers pass. */
      for (unsigned i = 0; i < region->layer_count; i++) {
         uint64_t start, stride;
         if (!linear_region(layout, region, region->first_layer + i, &start, &stride))
            return STELA_AMD_IMAGE_LAYOUT_FAILED;
      }
   } else {
      if (info->gfx_level < GFX10 || layout->storage.bytes > UINT32_MAX)
         return STELA_AMD_IMAGE_UNSUPPORTED;
      if (!(layout->config.surf_flags & RADEON_SURF_HOST_TRANSFER) || layout->surface.tile_swizzle)
         return STELA_AMD_IMAGE_UNSUPPORTED;
      status = tiled_prefix(layout, region, &result.host_prefix);
      if (status != STELA_AMD_IMAGE_OK)
         return status;
      /* Original hybrid edge handling can advance x/y pointers before a
       * remaining empty loop, then advance slices after the last iteration.
       * Bound evaluated pointers, not only dereferenced/touched bytes, across
       * generic and existing SIMD variants. One extra slice plus a row width
       * conservatively contains those original increments for thin 2D. */
      if (!add64(envelope, slice_pitch, &result.host_envelope) ||
          !add64(result.host_envelope, (uint64_t)region->width * 4, &result.host_envelope))
         return STELA_AMD_IMAGE_INVALID;
   }
   if (result.host_envelope > SIZE_MAX || result.host_prefix > SIZE_MAX ||
       result.host_envelope > PTRDIFF_MAX || result.host_prefix > PTRDIFF_MAX)
      return STELA_AMD_IMAGE_INVALID;
   *requirements = result;
   return STELA_AMD_IMAGE_OK;
}

static bool
window(const void *ptr, uint64_t bytes, uintptr_t *start, uintptr_t *end)
{
   *start = (uintptr_t)ptr;
   if (!ptr || !bytes || bytes > SIZE_MAX || bytes > PTRDIFF_MAX || bytes > UINTPTR_MAX - *start)
      return false;
   *end = *start + (uintptr_t)bytes;
   return true;
}

static enum stela_amd_image_status
copy_image(const struct radeon_info *info, struct ac_addrlib *addrlib,
            const struct stela_amd_image_resource *resource, const struct stela_amd_buffer_view *owner_view,
            void *surface_ptr, uint64_t surface_bytes, const struct stela_amd_image_copy_region *region,
            void *host_base, uint64_t host_bytes, uint64_t host_offset,
            uint64_t row_pitch, uint64_t slice_pitch, bool to_surface)
{
   struct stela_amd_image_copy_requirements requirements;
   enum stela_amd_image_status status = stela_amd_query_image_copy(info, addrlib, resource, owner_view,
                                                                  region, row_pitch, slice_pitch, &requirements);
   if (status != STELA_AMD_IMAGE_OK)
      return status;
   const struct stela_amd_image_layout_state *layout = resource->layout;
   uintptr_t surface_start, surface_end, host_start, host_end;
   if (surface_bytes < layout->storage.bytes || surface_bytes > owner_view->range ||
       !window(surface_ptr, surface_bytes, &surface_start, &surface_end) ||
       !window(host_base, host_bytes, &host_start, &host_end) ||
       (surface_start < host_end && host_start < surface_end) ||
       host_offset < requirements.host_prefix || host_offset > host_bytes ||
       requirements.host_envelope > host_bytes - host_offset)
      return STELA_AMD_IMAGE_INVALID;
   char *host = (char *)host_base + (size_t)host_offset;
   if (layout->surface.is_linear) {
      for (unsigned i = 0; i < region->layer_count; i++) {
         uint64_t start = 0, stride = 0;
         /* All layers/spans passed above with immutable cached state. */
         const bool valid = linear_region(layout, region, region->first_layer + i, &start, &stride);
         if (!valid)
            UNREACHABLE("immutable preflighted image layout changed during copy");
         for (unsigned row = 0; row < region->height; row++) {
            char *surface_row = (char *)surface_ptr + (size_t)(start + row * stride);
            char *host_row = host + (size_t)(i * slice_pitch + row * row_pitch);
            if (to_surface)
               memcpy(surface_row, host_row, region->width * 4);
            else
               memcpy(host_row, surface_row, region->width * 4);
         }
      }
      return STELA_AMD_IMAGE_OK;
   }
   const struct ac_surface_copy_region copy = {
      .surf_ptr = surface_ptr, .host_ptr = host,
      .offset = {.x = region->x, .y = region->y},
      .extent = {.width = region->width, .height = region->height, .depth = 1},
      .level = region->level, .base_layer = region->first_layer, .num_layers = region->layer_count,
      .mem_row_pitch = row_pitch, .mem_slice_pitch = slice_pitch,
   };
   const bool copied = to_surface ? ac_surface_copy_mem_to_surface(addrlib, info, &layout->surface, &layout->config.info, &copy) :
                                    ac_surface_copy_surface_to_mem(addrlib, info, &layout->surface, &layout->config.info, &copy);
   return copied ? STELA_AMD_IMAGE_OK : STELA_AMD_IMAGE_COPY_FAILED;
}

enum stela_amd_image_status
stela_amd_copy_image_from_cpu(const struct radeon_info *info, struct ac_addrlib *addrlib,
                              const struct stela_amd_image_resource *resource,
                              const struct stela_amd_buffer_view *owner_view,
                              void *surface_ptr, uint64_t surface_bytes,
                              const struct stela_amd_image_copy_region *region,
                              const void *host_base, uint64_t host_bytes, uint64_t host_offset,
                              uint64_t row_pitch, uint64_t slice_pitch)
{
   return copy_image(info, addrlib, resource, owner_view, surface_ptr, surface_bytes, region,
                      (void *)host_base, host_bytes, host_offset, row_pitch, slice_pitch, true);
}

enum stela_amd_image_status
stela_amd_copy_image_to_cpu(const struct radeon_info *info, struct ac_addrlib *addrlib,
                            const struct stela_amd_image_resource *resource,
                            const struct stela_amd_buffer_view *owner_view,
                            const void *surface_ptr, uint64_t surface_bytes,
                            const struct stela_amd_image_copy_region *region,
                            void *host_base, uint64_t host_bytes, uint64_t host_offset,
                            uint64_t row_pitch, uint64_t slice_pitch)
{
   return copy_image(info, addrlib, resource, owner_view, (void *)surface_ptr, surface_bytes, region,
                      host_base, host_bytes, host_offset, row_pitch, slice_pitch, false);
}
