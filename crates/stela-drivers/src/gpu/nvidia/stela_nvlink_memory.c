/* SPDX-License-Identifier: MIT */
/* nvlink_malloc and nvlink_free, as nvlink_os.h declares them, over Stela's
 * checked global-heap boundary (stela_memory.h). They have no atomic mode. */
#include <stddef.h>
#include "nvlink_os.h"
#include "stela_memory.h"

void *nvlink_malloc(NvLength size)
{
    void *pointer = NULL;
    if (stela_nvidia_alloc(size, &pointer) != STELA_NVIDIA_ALLOC_SUCCESS)
        return NULL;
    return pointer;
}

void nvlink_free(void *pointer)
{
    stela_nvidia_free(pointer);
}

_Static_assert(sizeof(NvLength) == sizeof(NvU64), "native allocation length");
