/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_IMAGE_H
#define STELA_INTEL_HOSTED_IMAGE_H

#include "surface.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Hosted creation-time adapter. ISL pointers/layouts stay in this process;
 * only checked state bytes and owned mapping references cross to execution.
 * This is not a Metal feature/family declaration or a shader-image ABI.
 */
enum stela_intel_image_backing {
    STELA_INTEL_IMAGE_UNCOMPRESSED = 1,
};

struct stela_intel_image_desc {
    enum isl_surf_dim dim;
    enum isl_format format;
    uint32_t width, height, depth, levels, array_len, samples;
    /* TEXTURE, STORAGE and/or RENDER_TARGET only. The adapter adds the actual
     * ISL DISABLE_AUX policy, for the entire lifetime of this resource. */
    isl_surf_usage_flags_t usage;
    isl_tiling_flags_t tiling_flags;
    uint32_t min_alignment_B, row_pitch_B;
    uint32_t storage_access; /* Exact READ/WRITE mask, zero without STORAGE. */
    enum stela_intel_image_backing backing;
};

struct stela_intel_image_view {
    /* Exactly one of the creation roles; same physical format and identity
     * channel mapping. Storage/render views address one mip level. */
    isl_surf_usage_flags_t usage;
    uint32_t base_level, levels, base_array_layer, array_len;
    uint32_t access;
};

struct stela_intel_image_mapping {
    uint64_t gpu_base; /* Actual selected-VM allocation mapping, not a CPU VA. */
    uint64_t mapped_bytes; /* Whole pinned/reachable span. */
    uint64_t allocation_bytes; /* Owned allocation span, including ISL padding. */
    uint64_t image_offset;
    uint32_t address_bits; /* Actual VM width: 32, 48 or 57. */
    uint32_t available_access;
    enum stela_intel_image_backing backing;
    bool external; /* Original initialized-device internal/external MOCS. */
};

/* Initial supported policy: Gen7+ single-sample uncompressed color 2D images,
 * arrays and mip chains, without aux, cube or format reinterpretation. Exact
 * physical-format capabilities come from original ISL. Storage never silently
 * lowers unsupported typed reads/writes to a different format or shader ABI.
 *
 * The owner initializes the real ISL device/cache policy, allocates at least
 * surf.size_B with surf.alignment_B, and uses this exact tiling/layout. All ISL
 * sampler overfetch padding belongs to the allocation. Sampled creation needs
 * dev->requires_padding=true; the alternative fault-safe scratch-page VM
 * policy is unavailable until its real owner contract is supplied. ISL's
 * initialization default alone does not establish that mapping. In particular Xe2+
 * backing must have compression disabled in its allocation/PAT policy from
 * creation onward; AUX_NONE alone cannot repair compressed backing. No fast
 * clears, compressed imports or later aux enablement are valid on this path.
 * The owner enforces rights, pinning, residency, DMA visibility, image hazards,
 * state placement alignment (dev->ss.align), submission and completion. State
 * bytes do not enforce read-only rights or qualify image shader execution.
 *
 * Recomputed layout is a creation/view-construction boundary, not per draw or
 * dispatch. A future owner may retain the resulting immutable layout/device.
 * No initialized device/layout may be inferred from a guest CPU profile.
 * Returns 0 for layout; positive encoded bytes for state; -22 invalid input,
 * -28 insufficient output, -95 unsupported policy/physical format/layout.
 * Errors leave outputs untouched. State output must be u32 aligned.
 */
int stela_intel_image_layout(const struct isl_device *,
                             const struct stela_intel_image_desc *, struct isl_surf *);
int stela_intel_image_state(const struct isl_device *,
                            const struct stela_intel_image_desc *,
                            const struct stela_intel_image_view *,
                            const struct stela_intel_image_mapping *,
                            void *state, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
