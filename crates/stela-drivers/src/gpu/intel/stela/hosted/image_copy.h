/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_HOSTED_IMAGE_COPY_H
#define STELA_INTEL_HOSTED_IMAGE_COPY_H
#include "image.h"

#ifdef __cplusplus
extern "C" {
#endif

enum stela_intel_cpu_copy_mapping {
    STELA_INTEL_CPU_COPY_RAW_WB = 1,
};
enum stela_intel_cpu_copy_swizzle {
    STELA_INTEL_CPU_COPY_NO_BIT6 = 1,
    STELA_INTEL_CPU_COPY_BIT6 = 2, /* Unavailable until exact owner semantics. */
};
enum stela_intel_image_copy_direction {
    STELA_INTEL_IMAGE_UPLOAD = 1,
    STELA_INTEL_IMAGE_READBACK = 2,
};

struct stela_intel_image_rectangle {
    uint32_t level, layer, x, y, width, height;
};

/* Actual local-process CPU allocation, not a guest pointer, GPU VA, IOVA or
 * opaque transport handle. The owner establishes and retains this real raw WB
 * mapping. allocation_bytes includes only storage genuinely owned in this C
 * allocation object (including its real guard reservation), not adjacency to
 * another mapping. mapped_bytes must cover it all. offset identifies the image
 * base or the first byte of the linear rectangle. access is actual CPU rights.
 */
struct stela_intel_cpu_copy_span {
    void *base;
    uint64_t mapped_bytes, allocation_bytes, offset;
    uint32_t access;
    enum stela_intel_cpu_copy_mapping mapping;
};

struct stela_intel_image_copy_requirements {
    uint64_t image_bytes; /* Exact original ISL size_B, including padding. */
    uint64_t image_cpu_span; /* Tiled helpers need one extra owned guard tile. */
    uint64_t linear_prefix; /* Real bytes required before rectangle pointer. */
    uint64_t linear_suffix; /* Required span after it, including last increment. */
    uint32_t row_bytes;
    enum isl_tiling tiling;
};

/* Creation/copy preparation, no allocation. Initial actual color2D image
 * policy from image.h, single mip/layer, positive rectangle and positive linear
 * pitch >= row_bytes, <=INT32_MAX (Y0/Tile4 <=INT32_MAX/4 for original signed
 * four-row arithmetic). Linear/X/Y0/Tile4 only. Unknown/bit6-swizzled
 * raw mappings, standard-Y and Tile64 refuse; no conversion or staging fallback.
 *
 * For tiled copies the unchanged helper forms pointers before the linear
 * rectangle and increments beyond its last row. The query bounds those formed
 * pointers: prefix=(global_x_bytes % tile_width)+
 * (global_y % tile_height)*linear_pitch; suffix=height*linear_pitch+row_bytes.
 * Its Y0 zero-length tail copies can also form tiled pointers past size_B, so
 * image_cpu_span includes one extra tile of actual same-allocation guard.
 * Only rectangle bytes are accessed; guards/prefix/padding stay untouched.
 * Linear copies need neither extra guard nor prefix and use exact row bounds.
 *
 * Owner must allocate/provide these real spans. Ordinary Metal CPU input that
 * lacks them needs an actual shared-owner staging allocation; this adapter
 * never invents prefix storage or casts a pointer into another address space.
 */
int stela_intel_image_copy_query(const struct isl_device *,
                                const struct stela_intel_image_desc *,
                                const struct stela_intel_image_rectangle *,
                                uint32_t linear_pitch,
                                struct stela_intel_image_copy_requirements *);

/* Synchronous CPU memory copy only, never GPU completion. The caller must hold
 * real exclusive/quiescent CPU ownership, without concurrent GPU/CPU access,
 * and perform the actual shared-owner acquire/cache visibility before reads.
 * Upload writes need owner publication and texture/cache hazards before GPU
 * use afterward. No cache/IRQ/wait/sync implementation is supplied here.
 *
 * Image backing is uncompressed for its entire lifetime; mapping must be raw
 * tiled bytes, not a detiled GTT view or MMIO/WC/UC memory. All raw-layout, WB,
 * swizzle, rights and ownership facts come from the actual mapping owner.
 * CPU allocation ranges must be disjoint, including unknown physical aliases.
 * Span/rectangle metadata is snapshotted before copying. Errors leave both
 * allocations unchanged. Returns 0 after actual CPU copy, -22 invalid metadata,
 * pointer/span/rights/overlap, -95 unsupported mapping/image/tiling policy.
 */
int stela_intel_image_copy(const struct isl_device *,
                           const struct stela_intel_image_desc *,
                           const struct stela_intel_image_rectangle *,
                           uint32_t linear_pitch,
                           const struct stela_intel_cpu_copy_span *image,
                           const struct stela_intel_cpu_copy_span *linear,
                           enum stela_intel_cpu_copy_swizzle,
                           enum stela_intel_image_copy_direction);

#ifdef __cplusplus
}
#endif
#endif
