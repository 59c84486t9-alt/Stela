/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include "os-interface.h"
#include "stela_memory.h"

/* Match the original RM declarations and status values. Invalid/overflowing
 * native layouts and exhausted shared heaps cannot produce a usable pointer.
 */
NV_STATUS NV_API_CALL os_alloc_mem(void **out, NvU64 bytes)
{
    if (out == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *out = NULL;
    switch (stela_nvidia_alloc(bytes, out))
    {
    case STELA_NVIDIA_ALLOC_SUCCESS:
        return NV_OK;
    case STELA_NVIDIA_ALLOC_INVALID_SIZE:
        return NV_ERR_INVALID_ARGUMENT;
    case STELA_NVIDIA_ALLOC_OUT_OF_MEMORY:
        return NV_ERR_NO_MEMORY;
    default:
        return NV_ERR_GENERIC;
    }
}

void NV_API_CALL os_free_mem(void *pointer)
{
    stela_nvidia_free(pointer);
}
