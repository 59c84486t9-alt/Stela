/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_IMAGE_RESOURCE_H
#define STELA_AMD_IMAGE_RESOURCE_H

#include "image.h"
#include "amd/common/ac_surface.h"

#ifdef __cplusplus
extern "C" {
#endif

enum stela_amd_image_kind {
   STELA_AMD_IMAGE_2D,
   STELA_AMD_IMAGE_2D_ARRAY,
};

enum stela_amd_image_tiling {
   STELA_AMD_IMAGE_LINEAR,
   STELA_AMD_IMAGE_TILED,
};

struct stela_amd_image_description {
   uint32_t width;
   uint32_t height;
   uint32_t levels;
   uint32_t layers;
   enum stela_amd_image_format format;
   enum stela_amd_image_kind kind;
   enum stela_amd_image_tiling tiling;
};

struct stela_amd_image_view {
   uint32_t first_level;
   uint32_t level_count;
   uint32_t first_layer;
   uint32_t layer_count;
   enum stela_amd_image_kind kind;
};

/* Internal same-process frontend objects, not a guest/wire ABI. Caller storage
 * avoids a new allocator. Use only constructor outputs: never forge, mutate,
 * rebind or relocate these objects, the borrowed device facts, or owner view
 * while bound resources/views/GPU work retain them. Device reset/requery and
 * allocation/VM rebinding require retirement and reconstruction by the owner.
 * Fields expose the original layout for original driver consumers, not as a
 * public promise that arbitrary caller-built radeon_surf values are valid.
 *
 * The actual same-device Addrlib/info and access/visibility/reservation/lifetime
 * requirements in image.h apply. This cache never owns an allocation, VM, fence
 * or GPU device. Potential single-sample CMASK size may be reported by original
 * GFX6-9 layout code but no aux offset/storage is bound or enabled here. */
struct stela_amd_image_layout_state {
   const struct radeon_info *device;
   struct stela_amd_image_description description;
   struct ac_surf_config config;
   struct radeon_surf surface;
   enum pipe_format format;
   struct stela_amd_image_layout storage;
};

struct stela_amd_image_resource {
   const struct radeon_info *device;
   const struct stela_amd_image_layout_state *layout;
   /* Stable address of the actual owner's retained view, not an arbitrary
    * identity token or substitute for its allocation/residency lifetime. */
   const struct stela_amd_buffer_view *owner_view;
   struct stela_amd_buffer_view bound_view;
   uint64_t address;
};

/* Creation computes the original full padded mip/array layout once. row_pitch
 * is zero for tiled storage, where a linear CPU stride would be misleading.
 * The original policy may degrade a requested tiled small image to linear/1D
 * tiling; surface.is_linear records the actual result. */
enum stela_amd_image_status
stela_amd_prepare_image_layout(const struct radeon_info *info, struct ac_addrlib *addrlib,
                               const struct stela_amd_image_description *description,
                               struct stela_amd_image_layout_state *layout);

/* Binding validates full original storage/padding against the real owner's
 * retained view. Keep layout/device/owner-view immutable and alive through all
 * resulting views and GPU completion, with compression/PTE.D disabled. */
enum stela_amd_image_status
stela_amd_bind_image_resource(const struct stela_amd_image_layout_state *layout,
                              const struct stela_amd_buffer_view *owner_view,
                              struct stela_amd_image_resource *resource);

/* State creation uses the cached original layout; no layout/allocator call is
 * made here. The actual device and owner-view identity and its retained bounds
 * must still match binding. View kind currently must match resource kind;
 * cross-kind reinterpretation is explicitly unsupported. Non-anisotropic
 * sampled-view encoding only: no format/filter/Metal feature qualification and
 * no upload/submission implication. Outputs are unchanged on every error. */
enum stela_amd_image_status
stela_amd_build_image_view(const struct radeon_info *info,
                           const struct stela_amd_image_resource *resource,
                           const struct stela_amd_buffer_view *owner_view,
                           const struct stela_amd_image_view *view,
                           uint32_t descriptor[8]);

#ifdef __cplusplus
}
#endif
#endif
