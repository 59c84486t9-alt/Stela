/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_HOSTED_COPY_H
#define STELA_NVIDIA_HOSTED_COPY_H

#include "image.h"

enum stela_nv_cpu_access {
    STELA_NV_CPU_READ = 1,
    STELA_NV_CPU_WRITE = 2,
};

struct stela_nv_image_cpu_view {
    const struct nv_device_info *device;
    const void *owner;
    void *pointer;
    size_t bytes;
    size_t image_offset;
    uint32_t access;
};

struct stela_nv_linear_image {
    void *pointer; /* First byte of this rectangle, not the whole image */
    size_t bytes;
    size_t row_stride;
};

struct stela_nv_image_region {
    uint32_t level, layer;
    uint32_t x, y, width, height; /* Pixels in the selected mip level */
};

/* Hosted original NIL CPU copy, one mip/layer rectangle per call. The image
 * subset/device/owner/immutable lifetime contract is exactly image.h. Views
 * must describe actual reachable pinned CPU mappings with the declared rights;
 * CPU pointers cannot be cast from GPU VA/PA/IOVA. Retain the actual mapping
 * owner for the call. A pointer/span here neither creates nor pins a mapping.
 *
 * The owner establishes quiescent CPU ownership and correct cache attributes,
 * waits for actual device work and performs the real cache/DMA transitions
 * before/after calling. This helper neither synchronizes nor reports completion
 * and must not run in IRQ context. No MMIO/VRAM aliases or cache conversion are
 * provided. The linear pointer is readable for upload, writable for download.
 * Keep the mapping, image, metadata and linear memory exclusively borrowed and
 * serialized; neither may overlap metadata or the other buffer's backing.
 *
 * All validation precedes the first write. Full rounded NIL image backing,
 * original mip/layer bounds, exact linear row span, address overflow, rights
 * and disjoint CPU spans are checked. Invalid inputs return -22 (or image.h's
 * -95 unsupported input) with all buffer bytes unchanged. Success returns 0
 * after copying exactly the requested rectangle, leaving padding/other pixels
 * and other subresources untouched. Source bytes are never changed.
 */
int stela_nv_image_upload(const struct stela_nv_image *,
                          const struct stela_nv_image_cpu_view *,
                          const struct stela_nv_image_region *,
                          const struct stela_nv_linear_image *);
int stela_nv_image_download(const struct stela_nv_image *,
                            const struct stela_nv_image_cpu_view *,
                            const struct stela_nv_image_region *,
                            const struct stela_nv_linear_image *);
#endif
