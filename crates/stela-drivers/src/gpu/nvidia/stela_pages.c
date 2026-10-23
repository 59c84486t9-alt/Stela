/* SPDX-License-Identifier: MIT */
#include "stela_services.h"

NV_STATUS stela_nvidia_bind_memory(nv_state_t *nv, void *services,
                                   NvU32 domain, NvU8 bus, NvU8 slot, NvU8 function)
{
    if (nv == NULL || services == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    if (nv->os_state != NULL || nv->dma_dev != NULL || nv->niso_dma_dev != NULL)
        return NV_ERR_INVALID_STATE;
    if (nv->pci_info.domain != domain || nv->pci_info.bus != bus ||
        nv->pci_info.slot != slot || nv->pci_info.function != function)
        return NV_ERR_INVALID_ARGUMENT;
    nv->os_state = services;
    nv->dma_dev = (nv_dma_device_t *)services;
    return NV_OK;
}

NV_STATUS stela_nvidia_unbind_memory(nv_state_t *nv, void *services)
{
    if (nv == NULL || services == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    if (nv->os_state != services || nv->dma_dev != (nv_dma_device_t *)services)
        return NV_ERR_INVALID_STATE;
    nv->os_state = NULL;
    nv->dma_dev = NULL;
    return NV_OK;
}

void stela_nvidia_state_layout(NvU64 *bytes, NvU64 *alignment)
{
    *bytes = sizeof(nv_state_t);
    *alignment = _Alignof(nv_state_t);
}

NvBool NV_API_CALL nv_requires_dma_remap(nv_state_t *nv)
{
    return nv != NULL && nv->os_state != NULL &&
           nv->dma_dev == (nv_dma_device_t *)nv->os_state;
}

NV_STATUS NV_API_CALL nv_alloc_pages(nv_state_t *nv, NvU32 count, NvU64 size,
                                     NvBool contiguous, NvU32 cache, NvBool zeroed,
                                     NvBool unencrypted, NvS32 node, NvU64 *ptes,
                                     void **private)
{
    if (private == NULL || ptes == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    /* No global/deviceless allocator and no physical-to-DMA fallback. */
    if (!nv_requires_dma_remap(nv))
        return NV_ERR_NOT_SUPPORTED;
    return stela_nvidia_alloc_pages(nv->os_state, nv, count, size, contiguous,
                                    cache, zeroed, unencrypted, node,
                                    nv->force_dma32_alloc, ptes, private);
}

NV_STATUS NV_API_CALL nv_free_pages(nv_state_t *nv, NvU32 count, NvBool contiguous,
                                    NvU32 cache, void *private)
{
    if (private == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    return stela_nvidia_free_pages(nv, count, contiguous, cache, private);
}

NV_STATUS NV_API_CALL nv_dma_map_alloc(nv_dma_device_t *device, NvU64 count,
                                       NvU64 *addresses, NvBool contiguous,
                                       NvBool read_only, void **private)
{
    if (private == NULL)
        return NV_ERR_NOT_SUPPORTED;
    if (*private == NULL || addresses == NULL || device == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    /* Rust validates device equality against retained allocation provenance;
     * never dereference an arbitrary C dma_dev value as platform state. */
    return stela_nvidia_dma_map(device, count, addresses, contiguous, read_only, private);
}

NV_STATUS NV_API_CALL nv_dma_unmap_alloc(nv_dma_device_t *device, NvU64 count,
                                         NvU64 *addresses, void **private)
{
    if (private == NULL)
        return NV_ERR_NOT_SUPPORTED;
    if (*private == NULL || addresses == NULL || device == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    /* The owned token supplies the true mapping; this original address array
     * is not trusted to select a different domain or removal target. */
    return stela_nvidia_dma_unmap(device, count, private);
}
