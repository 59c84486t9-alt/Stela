/* SPDX-License-Identifier: MIT */
/* Select the vendor's native kernel-interface declarations, not core nvport
 * implementation dependencies. The API declarations in nv.h require NVRM. */
#ifndef NVRM
#define NVRM
#endif
#ifndef NV_KERNEL_INTERFACE_LAYER
#define NV_KERNEL_INTERFACE_LAYER
#endif
#include "nv.h"
#include "mapping.h"

/* These are the original vendor declarations. The native RAM view token
 * replaces Linux's vmap bookkeeping and independently owns the actual CPU pin.
 */
void *NV_API_CALL nv_alloc_kernel_mapping(nv_state_t *nv, void *allocation,
                                         NvU64 page_index, NvU32 page_offset,
                                         NvU64 bytes, void **private)
{
    (void)nv;
    if (private == NULL)
        return NULL;
    *private = NULL;
    if (allocation == NULL)
        return NULL;
    return stela_nvidia_map_ram(allocation, page_index, page_offset, bytes, private);
}

void NV_API_CALL nv_free_kernel_mapping(nv_state_t *nv, void *allocation,
                                       void *address, void *private)
{
    /* The unique view token owns the mapping. Its parent may already be gone;
     * never dereference these original API arguments during view release. */
    (void)nv;
    (void)allocation;
    (void)address;
    stela_nvidia_unmap_ram(private);
}
