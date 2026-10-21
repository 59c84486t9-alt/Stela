/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_HOSTED_SAMPLER_H
#define STELA_NVIDIA_HOSTED_SAMPLER_H

#include "image.h"
#include "nouveau/nil/nil_sampler.h"

struct stela_nv_sampler {
    const struct nv_device_info *device;
    const void *image_owner;
    struct nvk_sampler_header header;
};

/* Hosted internal same-process value encoder, with original NVK packing and
 * retained enum/color declarations. No Vulkan object/frontend/runtime library
 * is used. The image/device/owner lifetime and immutable metadata contract is
 * exactly image.h. No CPU pointers may cross a translated guest/native ABI.
 *
 * Initial subset: normalized color sampling; original nearest/linear
 * min/mag/mip filters and five address modes; anisotropy 1..16; standard
 * transparent-black/opaque-black/opaque-white float or integer borders; identity
 * mapping and weighted-average reduction. Actual paired image format must
 * support filtering for any linear filter or anisotropy. Integer images use
 * nearest-only filtering and matching integer 0/1 border payloads. Custom border,
 * compare/depth, unnormalized, special flags and reduction paths are refused.
 * No Metal feature/family support is advertised by this helper.
 *
 * All numeric fields must be finite. LOD clamps are 0..4095/256, bias is
 * -16..4095/256 and minLOD<=maxLOD; original 8-fraction-bit packing/anisotropy
 * quantization is preserved. Disabled anisotropy uses max_anisotropy=1 exactly
 * as the original runtime value producer. Border payload and sRGB metadata
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
int stela_nv_sampler_encode(const struct stela_nv_image *,
                            const struct nil_sampler_state *, struct stela_nv_sampler *);
#endif
