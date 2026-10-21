/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_HOSTED_IMAGE_H
#define STELA_NVIDIA_HOSTED_IMAGE_H

#include "nouveau/nil/nil.h"

/* Hosted resource formation using original NIL. libnil currently uses Rust std;
 * this interface must not be linked into the freestanding physical backend.
 * Native process pointers below never cross the translated guest/native ABI.
 */
enum stela_nv_image_usage {
    STELA_NV_IMAGE_TEXTURE = 1,
    STELA_NV_IMAGE_STORAGE = 2,
};

struct stela_nv_image_request {
    enum pipe_format format;
    uint32_t width, height, layers, levels;
    uint32_t usage;
};

struct stela_nv_image {
    /* Read-only after successful init. Caller owns this storage, the actual
     * device facts and a distinct owner key for this resource lifetime. Keep
     * them alive and immutable through all calls. Serialize mutation/teardown.
     * Neither a PCI tuple nor a reused allocation address is a lifetime key.
     */
    const struct nv_device_info *device;
    const void *owner;
    struct stela_nv_image_request request;
    uint16_t cls_eng3d;
    enum nv_device_type device_type;
    /* Original layout metadata for the memory owner: size includes tile/mip
     * padding, align_B and pte_kind must be honored by the real GPU VM mapper.
     * This is not a tightly packed CPU image, CPU VA, PA, or DMA IOVA.
     */
    struct nil_image layout;
};

struct stela_nv_image_binding {
    const struct nv_device_info *device;
    const void *owner;
    uint64_t gpu_base;
    uint64_t mapped_bytes; /* Reachable backing, including every padded byte */
    uint64_t image_offset;
    uint32_t address_bits; /* Actual unsigned GPU VM width, at most 48 here */
    uint32_t available_usage;
    uint8_t pte_kind; /* Actual uncompressed GPU mapping kind */
};

struct stela_nv_image_view {
    uint32_t base_level, levels, base_layer, layers;
    enum pipe_swizzle swizzle[4];
    uint32_t usage; /* Exactly TEXTURE or STORAGE */
    bool array;
    bool filtered; /* Reject integer filtering using original NIL capability */
    float min_lod_clamp;
};

/* Bounded 2D/2D-array block-linear uncompressed color images, single sample,
 * identity format views, Maxwell through Ada. Hardware format facts come from
 * NIL; this does not advertise Metal feature/family support. Sparse, external
 * modifiers, planar/depth/stencil/MSAA/compressed paths need their real owners.
 * Limits are encoder ceilings, further reduced by the actual runtime device.
 * Returns 0, -22 invalid input or -95 unsupported device/format. On failure the
 * output remains unchanged. No GPU allocation, residency or submission occurs.
 */
int stela_nv_image_init(const struct nv_device_info *, const void *owner,
                        const struct stela_nv_image_request *, struct stela_nv_image *);

/* Rebuilds the original layout from the validated request; mutable caller NIL
 * fields can never reach its assert-bearing descriptor encoder. Binding must
 * belong to the same device/resource lifetime, have the original PTE kind, and
 * cover the entire rounded NIL image, even for a smaller mip/layer view. Rights
 * here validate the owner's contract; a TIC cannot enforce read-only access.
 *
 * The owner retains actual backing/GPU VM mappings until all descriptor users
 * retire with real device completion, and owns upload/table/cache ordering and
 * sampler/shader ABI. Copy only state bytes plus retained resource references
 * across the native boundary; CPU pointers are not handles for another CPU ABI.
 */
int stela_nv_image_descriptor(const struct stela_nv_image *,
                              const struct stela_nv_image_binding *,
                              const struct stela_nv_image_view *, struct nil_descriptor *);
#endif
