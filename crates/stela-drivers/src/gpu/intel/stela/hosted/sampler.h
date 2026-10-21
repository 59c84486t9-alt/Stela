/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_SAMPLER_H
#define STELA_INTEL_HOSTED_SAMPLER_H
#include "image.h"
#include "pipe/p_state.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    STELA_INTEL_SAMPLER_STATE_DWORDS = 4,
    STELA_INTEL_SAMPLER_TABLE_ALIGNMENT = 32,
};

/* Hosted creation/view-pairing boundary. Borrow actual initialized ISL and the
 * immutable color2D image description from image.h. ISL validates that exact
 * physical format's sampling/filtering capability. No CPU profile determines
 * sampler support. Existing pipe_sampler_state is a plain value description;
 * no Gallium/Vulkan object, context, allocator or lifecycle is constructed.
 *
 * Initial Gen8+ policy: normalized coordinates, nearest/linear min/mag,
 * none/nearest/linear mip, repeat/mirror-repeat/clamp-edge/mirror-clamp-edge,
 * weighted reduction and no anisotropy, comparison, cube or border. Any linear
 * min/mag/mip filtering requires the actual format's ISL filtering capability. Finite,
 * ordered LOD bounds and finite bias use original Iris clamps and original
 * XML fixed-point packing, including its no-mip/min-LOD policy. Border values
 * and compare_func have no effect while their modes are disabled; border
 * pointer remains zero and no border allocation is implied. Unknown padding
 * flags and unsupported behavior are refused, never silently approximated.
 *
 * Returns 16 encoded bytes, -22 invalid metadata/alignment, -28 insufficient
 * capacity, -95 unavailable physical format/generation/policy. Errors leave
 * output unchanged. CPU output must be u32 aligned. The owner retains exact
 * image/sampler pairing, uploads actual contiguous sampler tables at >=32-byte
 * alignment (bindless slots may require a larger stride), and owns mappings,
 * state bases, cache visibility, hazards, submission and completion. These
 * bytes alone do not enable sampler resources in the compute/graphics plan or
 * establish Metal image execution/features. Gen7 and Gen35 shader holds stay.
 */
int stela_intel_sampler_state(const struct isl_device *,
                              const struct stela_intel_image_desc *,
                              const struct pipe_sampler_state *, void *, size_t);

#ifdef __cplusplus
}
#endif
#endif
