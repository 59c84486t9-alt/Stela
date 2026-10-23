/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_IMAGE_COPY_H
#define STELA_AMD_IMAGE_COPY_H

#include "image_resource.h"

#ifdef __cplusplus
extern "C" {
#endif

struct stela_amd_image_copy_region {
   uint32_t level;
   uint32_t first_layer;
   uint32_t layer_count;
   uint32_t x;
   uint32_t y;
   uint32_t width;
   uint32_t height;
};

struct stela_amd_image_copy_requirements {
   /* Original tiled copy code may form a host pointer before its region's
    * first byte, including mip-tail X coordinates, without dereferencing it.
    * The real allocation must include this prefix, not just numeric VA space. */
   uint64_t host_prefix;
   /* Required suffix after the region origin, including conservative original
    * SIMD pointer increments even after the last copied row/layer. Untouched
    * prefix/padding/suffix bytes are never transfer payload. */
   uint64_t host_envelope;
   uint64_t copied_bytes;
};

/* Nonempty rectangle, one mip, one or more array layers. Pitches are bytes:
 * row_pitch >= width*4, slice_pitch >= row_pitch*height. The requirements query
 * performs the same geometry/arithmetic/original-metadata validation as copying.
 * It allocates nothing and modifies no image/host memory. */
enum stela_amd_image_status
stela_amd_query_image_copy(const struct radeon_info *info, struct ac_addrlib *addrlib,
                            const struct stela_amd_image_resource *resource,
                            const struct stela_amd_buffer_view *owner_view,
                            const struct stela_amd_image_copy_region *region,
                            uint64_t row_pitch, uint64_t slice_pitch,
                            struct stela_amd_image_copy_requirements *requirements);

/* These are CPU memory copies, never GPU upload completion or synchronization.
 * The real owner must hold canonical CPU mapping/access and reservation leases,
 * exclude GPU access through the entire call, and keep all cached device/layout/
 * owner state and the exact creation Addrlib alive and immutable. surface_ptr
 * must begin at the actual CPU mapping of resource->address (owner view offset),
 * covering the full original padded surface; surface_bytes must fit that view.
 * host_base/host_bytes must describe one real, appropriately readable/writable
 * allocation, including prefix/envelope, with host_offset at the region origin.
 * Declared host and surface CPU windows must be disjoint. Numeric bounds and
 * identity checks cannot establish those mapping/permission/lifetime duties.
 *
 * Before readback the real owner must wait for GPU completion and establish CPU
 * visibility. After a CPU write it must publish data through actual DMA/cache/VM
 * services before GPU access. No boolean, callback stub, fence or fake flush is
 * supplied here. Ordinary inputs lacking required padding need real shared-
 * service staging owned by the frontend; no allocation is invented here.
 *
 * Actual linear layouts use original per-mip/layer offsets/pitches and memcpy.
 * Nonlinear layouts require creation-time CPU_COPY/HOST_TRANSFER, with actual
 * zero tile-swizzle and no aux allocation, and use unchanged original helpers on GFX10+ only,
 * currently with <=UINT32_MAX total storage because retained swizzler offsets
 * contain u32 shifts. This is a CPU-helper restriction, not a GPU image limit.
 * All validation and original layout/copy errors precede writes in the pinned
 * supported helper paths; no rollback, GPU publication or submission is implied.
 */
enum stela_amd_image_status
stela_amd_copy_image_from_cpu(const struct radeon_info *info, struct ac_addrlib *addrlib,
                              const struct stela_amd_image_resource *resource,
                              const struct stela_amd_buffer_view *owner_view,
                              void *surface_ptr, uint64_t surface_bytes,
                              const struct stela_amd_image_copy_region *region,
                              const void *host_base, uint64_t host_bytes, uint64_t host_offset,
                              uint64_t row_pitch, uint64_t slice_pitch);

enum stela_amd_image_status
stela_amd_copy_image_to_cpu(const struct radeon_info *info, struct ac_addrlib *addrlib,
                            const struct stela_amd_image_resource *resource,
                            const struct stela_amd_buffer_view *owner_view,
                            const void *surface_ptr, uint64_t surface_bytes,
                            const struct stela_amd_image_copy_region *region,
                            void *host_base, uint64_t host_bytes, uint64_t host_offset,
                            uint64_t row_pitch, uint64_t slice_pitch);

#ifdef __cplusplus
}
#endif
#endif
