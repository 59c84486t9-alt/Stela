/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_HOSTED_SAMPLER_H
#define STELA_NVIDIA_HOSTED_SAMPLER_H

#include "image.h"
#include "vulkan/vulkan_core.h"

/* Vulkan sampler values; no Vulkan object, frontend or runtime is used. */
struct stela_nvidia_sampler_state {
    VkSamplerCreateFlags flags;
    VkFilter mag_filter;
    VkFilter min_filter;
    VkSamplerMipmapMode mipmap_mode;
    VkSamplerAddressMode address_mode_u;
    VkSamplerAddressMode address_mode_v;
    VkSamplerAddressMode address_mode_w;
    float mip_lod_bias;
    float max_anisotropy;
    VkCompareOp compare_op;
    float min_lod;
    float max_lod;
    VkBorderColor border_color;
    bool anisotropy_enable;
    bool compare_enable;
    bool unnormalized_coordinates;
    bool image_view_is_srgb;
    VkClearColorValue border_color_value;
    VkComponentMapping border_color_component_mapping;
    VkSamplerReductionMode reduction_mode;
};

/* The 32-byte TEXSAMP sampler header. */
struct stela_nvidia_sampler_header {
    uint32_t bits[8];
};

struct stela_nvidia_sampler {
    const struct nv_device_info *device;
    const void *image_owner;
    struct stela_nvidia_sampler_header header;
};

/* Hosted internal same-process value encoder, packing TEXSAMP fields as NVK
 * does. The image/device/owner lifetime and immutable metadata contract is
 * exactly image.h. No CPU pointers may cross a translated guest/native ABI.
 *
 * Initial subset: normalized color sampling; nearest/linear
 * min/mag/mip filters and five address modes; anisotropy 1..16; standard
 * transparent-black/opaque-black/opaque-white float or integer borders; identity
 * mapping and weighted-average reduction. Actual paired image format must
 * support filtering for any linear filter or anisotropy. Integer images use
 * nearest-only filtering and matching integer 0/1 border payloads. Custom border,
 * compare/depth, unnormalized, special flags and reduction paths are refused.
 * No Metal feature/family support is advertised by this helper.
 *
 * All numeric fields must be finite. LOD clamps are 0..4095/256, bias is
 * -16..4095/256 and minLOD<=maxLOD; their 8-fraction-bit packing and the
 * anisotropy quantization are NVK's. Disabled anisotropy uses max_anisotropy=1 exactly
 * as the Vulkan runtime's value producer. Border payload and sRGB metadata
 * must match the selected standard border and the actual paired image format,
 * including its floating-point versus signed/unsigned integer numeric type.
 *
 * Return 0, -22 invalid input or -95 unsupported path, leaving output unchanged
 * on failure. The resulting bytes do not allocate/upload a sampler or establish
 * table residency. The owner retains this device/image lifetime and actual
 * descriptor table backing until real completion, maintains matching shader,
 * image-view/sampler/table indices, upload/cache ordering and removal handling.
 * Bind only to the validated image format and honor its image-view/mip limits.
 */
int stela_nvidia_sampler_encode(const struct stela_nvidia_image *,
                            const struct stela_nvidia_sampler_state *, struct stela_nvidia_sampler *);
#endif
