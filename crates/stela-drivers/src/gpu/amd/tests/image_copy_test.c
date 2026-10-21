/* SPDX-License-Identifier: MIT */
/* CPU allocation/model checks only; no GPU mapping, upload or cache service. */
#include "../stela/image_copy.h"
#include "image_fixture.h"
#include "util/u_math.h"
#include <stdio.h>
#include <stdlib.h>

static uint64_t
coordinate(struct ac_addrlib *addrlib, const struct radeon_info *info,
            const struct stela_amd_image_layout_state *layout,
            unsigned level, unsigned x, unsigned y, unsigned layer)
{
   if (info->gfx_level >= GFX9)
      return ac_surface_addr_from_coord(addrlib, info, &layout->surface, &layout->config.info,
                                        level, x, y, layer, false);
   assert(layout->surface.is_linear);
   const struct legacy_surf_level *mip = &layout->surface.u.legacy.level[level];
   return (uint64_t)mip->offset_256B * 256 + (uint64_t)layer * mip->slice_size_dw * 4 +
          ((uint64_t)y * mip->nblk_x + x) * 4;
}

static void
atomic_failure(const struct radeon_info *info, struct ac_addrlib *addrlib,
                const struct stela_amd_image_resource *resource,
                const struct stela_amd_buffer_view *owner,
                char *surface, uint64_t surface_bytes, const struct stela_amd_image_copy_region *region,
                char *host, uint64_t host_bytes, uint64_t host_offset,
                uint64_t row_pitch, uint64_t slice_pitch, enum stela_amd_image_status expected)
{
   char *surface_before = malloc(resource->layout->storage.bytes);
   char *host_before = malloc(host_bytes);
   assert(surface_before && host_before);
   memcpy(surface_before, surface, resource->layout->storage.bytes); memcpy(host_before, host, host_bytes);
   assert(stela_amd_copy_image_from_cpu(info, addrlib, resource, owner, surface, surface_bytes,
                                        region, host, host_bytes, host_offset, row_pitch, slice_pitch) == expected);
   assert(!memcmp(surface, surface_before, resource->layout->storage.bytes) && !memcmp(host, host_before, host_bytes));
   assert(stela_amd_copy_image_to_cpu(info, addrlib, resource, owner, surface, surface_bytes,
                                      region, host, host_bytes, host_offset, row_pitch, slice_pitch) == expected);
   assert(!memcmp(surface, surface_before, resource->layout->storage.bytes) && !memcmp(host, host_before, host_bytes));
   free(surface_before); free(host_before);
}

static void
copy_case(const struct radeon_info *info, struct ac_addrlib *addrlib,
           const struct stela_amd_image_resource *resource, struct stela_amd_buffer_view *owner,
           char *surface, char *expected_surface, const struct stela_amd_image_copy_region *region,
           unsigned serial)
{
   const struct stela_amd_image_layout_state *layout = resource->layout;
   const uint64_t row_pitch = (uint64_t)region->width * 4 + 12;
   const uint64_t slice_pitch = row_pitch * region->height + 20;
   struct stela_amd_image_copy_requirements requirements;
   assert(stela_amd_query_image_copy(info, addrlib, resource, owner, region, row_pitch, slice_pitch, &requirements) == STELA_AMD_IMAGE_OK);
   assert(requirements.copied_bytes == (uint64_t)region->width * region->height * region->layer_count * 4);
   /* Exact declared and allocated minimum: no hidden prefix/suffix allocation
    * may conceal an underestimated original rebasing/increment requirement. */
   const uint64_t offset = requirements.host_prefix;
   const uint64_t bytes = offset + requirements.host_envelope;
   char *host = malloc(bytes), *host_before = malloc(bytes), *readback = malloc(bytes), *expected_readback = malloc(bytes);
   assert(host && host_before && readback && expected_readback);
   memset(host, 0xac, bytes); memset(readback, 0xa5, bytes); memset(expected_readback, 0xa5, bytes);
   for (unsigned layer = 0; layer < region->layer_count; layer++) {
      for (unsigned y = 0; y < region->height; y++) {
         for (unsigned x = 0; x < region->width; x++) {
            const uint32_t value = 0x60000000u ^ (serial << 20) ^ (layer << 16) ^ (y << 8) ^ x;
            const uint64_t host_offset = offset + layer * slice_pitch + y * row_pitch + x * 4;
            const uint64_t image_offset = coordinate(addrlib, info, layout, region->level,
               region->x + x, region->y + y, region->first_layer + layer);
            assert(image_offset <= layout->storage.bytes && 4 <= layout->storage.bytes - image_offset);
            memcpy(host + host_offset, &value, 4);
            memcpy(expected_surface + image_offset, &value, 4);
            memcpy(expected_readback + host_offset, &value, 4);
         }
      }
   }
   memcpy(host_before, host, bytes);
   assert(stela_amd_copy_image_from_cpu(info, addrlib, resource, owner, surface, layout->storage.bytes,
                                        region, host, bytes, offset, row_pitch, slice_pitch) == STELA_AMD_IMAGE_OK);
   if (memcmp(surface, expected_surface, layout->storage.bytes)) {
      uint64_t mismatch = 0;
      while (surface[mismatch] == expected_surface[mismatch]) mismatch++;
      fprintf(stderr, "copy mismatch family=%u gfx=%u tiling=%u actual-linear=%u kind=%u level=%u offset=%llu actual=%02x expected=%02x\n",
              info->family, info->gfx_level, layout->description.tiling, layout->surface.is_linear,
              layout->description.kind, region->level, (unsigned long long)mismatch,
              (unsigned char)surface[mismatch], (unsigned char)expected_surface[mismatch]);
      assert(!"original coordinate and copy disagree");
   }
   assert(!memcmp(host, host_before, bytes));
   assert(stela_amd_copy_image_to_cpu(info, addrlib, resource, owner, surface, layout->storage.bytes,
                                      region, readback, bytes, offset, row_pitch, slice_pitch) == STELA_AMD_IMAGE_OK);
   assert(!memcmp(readback, expected_readback, bytes));
   assert(!memcmp(surface, expected_surface, layout->storage.bytes));

   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes - 1, region,
                    host, bytes, offset, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, region,
                    host, offset + requirements.host_envelope - 1, offset, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   if (requirements.host_prefix)
      atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, region,
                       host, bytes, requirements.host_prefix - 1, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, region,
                    host, bytes, UINT64_MAX, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, region,
                    host, bytes, offset, 1, slice_pitch, STELA_AMD_IMAGE_INVALID);
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, region,
                    host, bytes, offset, row_pitch, 0, STELA_AMD_IMAGE_INVALID);
   struct stela_amd_image_copy_region invalid = *region;
   invalid.level = UINT32_MAX;
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, &invalid,
                    host, bytes, offset, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   invalid = *region; invalid.x = UINT32_MAX;
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, &invalid,
                    host, bytes, offset, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   invalid = *region; invalid.layer_count = UINT32_MAX;
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, &invalid,
                    host, bytes, offset, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   invalid = *region; invalid.width = 0;
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, &invalid,
                    host, bytes, offset, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   /* One-row nonzero-origin overflow: the huge otherwise-unused slice/row
    * increments still must be bounded before original helper arithmetic. */
   invalid = *region; invalid.height = 1;
   atomic_failure(info, addrlib, resource, owner, surface, layout->storage.bytes, &invalid,
                    host, bytes, offset, UINT64_C(1) << 63, UINT64_C(1) << 63, STELA_AMD_IMAGE_INVALID);
   struct stela_amd_buffer_view copied_owner = *owner;
   atomic_failure(info, addrlib, resource, &copied_owner, surface, layout->storage.bytes, region,
                    host, bytes, offset, row_pitch, slice_pitch, STELA_AMD_IMAGE_INVALID);
   /* Exact alias and address-wrap inputs are rejected without dereferencing. */
   assert(stela_amd_copy_image_from_cpu(info, addrlib, resource, owner, surface, layout->storage.bytes,
      region, surface, layout->storage.bytes, offset, row_pitch, slice_pitch) == STELA_AMD_IMAGE_INVALID);
   assert(!memcmp(surface, expected_surface, layout->storage.bytes));
   assert(stela_amd_copy_image_to_cpu(info, addrlib, resource, owner, surface, layout->storage.bytes,
      region, (void *)(UINTPTR_MAX - 3), bytes, offset, row_pitch, slice_pitch) == STELA_AMD_IMAGE_INVALID);
   assert(!memcmp(surface, expected_surface, layout->storage.bytes));
   free(host); free(host_before); free(readback); free(expected_readback);
}

int main(void)
{
   const char *names[] = {"pitcairn", "bonaire", "polaris12", "vega10", "raven", "navi10", "navi21", "navi31", "phoenix", "strix1", "gfx1201"};
   const unsigned geometries[][3] = {{63,35,6}, {1,1,1}, {65,33,1}, {256,256,1}};
   unsigned copied = 0, refused = 0;
   for (unsigned target = 0; target < ARRAY_SIZE(names); target++) {
      struct radeon_info info = fixture(names[target]);
      struct ac_addrlib *addrlib = ac_addrlib_create(&info, NULL);
      struct ac_addrlib *other_addrlib = ac_addrlib_create(&info, NULL);
      assert(addrlib && other_addrlib);
      for (unsigned format = STELA_AMD_IMAGE_RGBA8_UNORM; format <= STELA_AMD_IMAGE_RGBA8_SRGB; format++) {
         for (unsigned tiling = STELA_AMD_IMAGE_LINEAR; tiling <= STELA_AMD_IMAGE_TILED; tiling++) {
            for (unsigned kind = STELA_AMD_IMAGE_2D; kind <= STELA_AMD_IMAGE_2D_ARRAY; kind++) {
               const unsigned layers = kind == STELA_AMD_IMAGE_2D ? 1 : 4;
               for (unsigned geometry = 0; geometry < ARRAY_SIZE(geometries); geometry++) {
                  const unsigned *g = geometries[geometry];
                  const struct stela_amd_image_description description = {g[0],g[1],g[2],layers,format,kind,tiling,STELA_AMD_IMAGE_CPU_COPY};
                  struct stela_amd_image_layout_state layout;
                  assert(stela_amd_prepare_image_layout(&info, addrlib, &description, &layout) == STELA_AMD_IMAGE_OK);
                  assert(layout.config.surf_flags & RADEON_SURF_HOST_TRANSFER);
                  assert(!layout.surface.tile_swizzle && !layout.surface.meta_offset && !layout.surface.cmask_offset);
                  const uint64_t offset = layout.storage.alignment;
                  struct stela_amd_buffer_view owner = {UINT64_C(0x2000000000), align64(layout.storage.bytes + offset, 4096), offset, layout.storage.bytes, 256};
                  struct stela_amd_image_resource resource;
                  assert(stela_amd_bind_image_resource(&layout, &owner, &resource) == STELA_AMD_IMAGE_OK);
                  char *allocation = malloc(layout.storage.bytes + 128), *expected = malloc(layout.storage.bytes);
                  assert(allocation && expected);
                  memset(allocation, 0xcd, layout.storage.bytes + 128); memset(expected, 0xcd, layout.storage.bytes);
                  char *surface = allocation + 64;
                  struct stela_amd_image_copy_region regions[3] = {0};
                  for (unsigned r = 0; r < 3; r++) {
                     const unsigned level = r == 0 ? 0 : r == 1 ? MIN2(2, g[2] - 1) : g[2] - 1;
                     const unsigned width = u_minify(g[0], level), height = u_minify(g[1], level);
                     const unsigned x = r == 0 ? MIN2(3, width - 1) : r == 1 ? MIN2(1, width - 1) : width - 1;
                     const unsigned y = r == 0 ? MIN2(2, height - 1) : r == 1 ? MIN2(1, height - 1) : height - 1;
                     regions[r] = (struct stela_amd_image_copy_region) {
                        .level = level, .first_layer = r == 0 && layers > 1 ? 1 : r == 2 ? layers - 1 : 0,
                        .layer_count = r == 0 && layers > 1 ? 2 : r == 1 ? layers : 1,
                        .x = x, .y = y, .width = MIN2(r == 0 ? 13 : r == 1 ? 5 : 1, width - x),
                        .height = MIN2(r == 0 ? 7 : r == 1 ? 3 : 1, height - y),
                     };
                  }
                  for (unsigned i = 0; i < ARRAY_SIZE(regions); i++) {
                     const struct stela_amd_image_copy_region *region = &regions[i];
                     if (!layout.surface.is_linear && info.gfx_level < GFX10) {
                        atomic_failure(&info, addrlib, &resource, &owner, surface, layout.storage.bytes,
                                          region, expected, layout.storage.bytes, 0, region->width * 4,
                                          region->width * region->height * 4, STELA_AMD_IMAGE_UNSUPPORTED);
                        refused++;
                     } else {
                        copy_case(&info, addrlib, &resource, &owner, surface, expected, region, i + 1);
                        copied++;
                     }
                     for (unsigned guard = 0; guard < 64; guard++)
                        assert((unsigned char)allocation[guard] == 0xcd &&
                               (unsigned char)allocation[64 + layout.storage.bytes + guard] == 0xcd);
                  }
                  struct stela_amd_image_copy_requirements untouched, before;
                  memset(&untouched, 0xa5, sizeof(untouched)); before = untouched;
                  assert(stela_amd_query_image_copy(&info, other_addrlib, &resource, &owner, &regions[0],
                                                     64, 1024, &untouched) == STELA_AMD_IMAGE_INVALID);
                  assert(!memcmp(&untouched, &before, sizeof(before)));
                  /* The default GPU-only layout is not a CPU-transfer promise,
                   * even if its original swizzle counter happens to return zero. */
                  if (tiling == STELA_AMD_IMAGE_TILED) {
                     struct stela_amd_image_description gpu_only = description;
                     gpu_only.cpu_transfer = STELA_AMD_IMAGE_GPU_ONLY;
                     struct stela_amd_image_layout_state gpu_layout;
                     assert(stela_amd_prepare_image_layout(&info, addrlib, &gpu_only, &gpu_layout) == STELA_AMD_IMAGE_OK);
                     if (!gpu_layout.surface.is_linear) {
                        struct stela_amd_buffer_view gpu_owner = {UINT64_C(0x2000000000), align64(gpu_layout.storage.bytes, 4096), 0, gpu_layout.storage.bytes, 256};
                        struct stela_amd_image_resource gpu_resource;
                        assert(stela_amd_bind_image_resource(&gpu_layout, &gpu_owner, &gpu_resource) == STELA_AMD_IMAGE_OK);
                        assert(stela_amd_query_image_copy(&info, addrlib, &gpu_resource, &gpu_owner, &regions[0],
                                                           64, 1024, &untouched) == STELA_AMD_IMAGE_UNSUPPORTED);
                        assert(!memcmp(&untouched, &before, sizeof(before)));
                     }
                  }
                  free(allocation); free(expected);
               }
            }
         }
      }
      if (info.gfx_level >= GFX10) {
         /* Original descriptors still admit this layout; only retained CPU
          * copy is limited by its internal u32-shift addressing. No huge CPU
          * allocation or successful-looking GPU mapping is constructed. */
         const struct stela_amd_image_description big = {16384,16384,1,8,STELA_AMD_IMAGE_RGBA8_UNORM,
            STELA_AMD_IMAGE_2D_ARRAY,STELA_AMD_IMAGE_TILED,STELA_AMD_IMAGE_CPU_COPY};
         struct stela_amd_image_layout_state big_layout;
         assert(stela_amd_prepare_image_layout(&info, addrlib, &big, &big_layout) == STELA_AMD_IMAGE_OK);
         assert(big_layout.storage.bytes > UINT32_MAX);
         struct stela_amd_buffer_view big_owner = {UINT64_C(0x2000000000), big_layout.storage.bytes, 0, big_layout.storage.bytes, 256};
         struct stela_amd_image_resource big_resource;
         assert(stela_amd_bind_image_resource(&big_layout, &big_owner, &big_resource) == STELA_AMD_IMAGE_OK);
         const struct stela_amd_image_view view = {0,1,0,8,STELA_AMD_IMAGE_2D_ARRAY};
         uint32_t descriptor[8];
         assert(stela_amd_build_image_view(&info, &big_resource, &big_owner, &view, descriptor) == STELA_AMD_IMAGE_OK);
         const struct stela_amd_image_copy_region region = {0,0,1,1,0,1,1};
         struct stela_amd_image_copy_requirements requirements;
         assert(stela_amd_query_image_copy(&info, addrlib, &big_resource, &big_owner, &region,4,4,&requirements) == STELA_AMD_IMAGE_UNSUPPORTED);
      }
      ac_addrlib_destroy(addrlib); ac_addrlib_destroy(other_addrlib);
   }
   printf("AMD CPU image copy: %u upload/readback pairs, %u explicit legacy tiled refusals; CPU models only\n", copied, refused);
   return 0;
}
