/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_IMAGE_H
#define STELA_AMD_IMAGE_H

#include "buffer.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ac_addrlib;
struct radeon_info;

enum stela_amd_image_status {
   STELA_AMD_IMAGE_OK,
   STELA_AMD_IMAGE_INVALID,
   STELA_AMD_IMAGE_UNSUPPORTED,
   STELA_AMD_IMAGE_DEVICE_INFO_UNAVAILABLE,
   STELA_AMD_IMAGE_LAYOUT_FAILED,
   STELA_AMD_IMAGE_COPY_FAILED,
};

/* Hosted internal enums, not Metal numeric values or a guest ABI. */
enum stela_amd_image_format {
   STELA_AMD_IMAGE_RGBA8_UNORM = 1,
   STELA_AMD_IMAGE_RGBA8_UINT,
   STELA_AMD_IMAGE_RGBA8_SRGB,
};

struct stela_amd_linear_image {
   uint32_t width;
   uint32_t height;
   enum stela_amd_image_format format;
};

struct stela_amd_image_layout {
   uint64_t bytes;
   uint64_t alignment;
   uint64_t row_pitch;
};

/* Resource-creation operations, never a per-dispatch/per-frame path. info must
 * contain actual initialized device/VM/compiler facts. addrlib must be a live
 * original ac_addrlib_create instance created from that SAME device information;
 * both remain exclusively valid through the call. Neither API initializes a GPU.
 *
 * Current bounded slice: single-level, single-layer, single-sample linear 2D,
 * identity swizzle, non-anisotropic sampled-view encoding. Matching pipeline
 * sampler/filter/type validation is a separate frontend requirement; these
 * packing APIs report no filtering capability. Dimensions above 16384 are
 * explicitly outside this adapter's implemented policy, not a hardware/Metal limit.
 * No aux storage/compression/PTE.D, imported surface, format reinterpretation,
 * storage/render access, arrays or mipmaps are accepted or implied. */
enum stela_amd_image_status
stela_amd_query_linear_image_layout(const struct radeon_info *info, struct ac_addrlib *addrlib,
                                   const struct stela_amd_linear_image *image,
                                   struct stela_amd_image_layout *layout);

/* The real owner must provide a reservation-protected, sample-readable mapping
 * on the SAME GPU VM/device, with compression/PTE.D disabled, initialized texel
 * contents, and correct visibility/cache synchronization. Keep the allocation,
 * mappings, access rights and residency through GPU completion. GPU VA is never
 * inferred from a CPU pointer, physical address or domain IOVA here.
 *
 * The original layout is recomputed at state creation and the complete storage
 * tail must fit the owner's view. This avoids trusting a caller-built surf or
 * stale layout from another device. Successful packing establishes no hardware
 * texture execution or Metal feature support. All outputs stay unchanged on any
 * failure; layout may be NULL when only the descriptor is needed. */
enum stela_amd_image_status
stela_amd_build_linear_image(const struct radeon_info *info, struct ac_addrlib *addrlib,
                             const struct stela_amd_linear_image *image,
                             const struct stela_amd_buffer_view *view,
                             uint32_t descriptor[8], struct stela_amd_image_layout *layout);

#ifdef __cplusplus
}
#endif
#endif
