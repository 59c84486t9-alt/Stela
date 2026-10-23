/* SPDX-License-Identifier: MIT */
/* nvkms_alloc and nvkms_free, as nvidia-modeset-os-interface.h declares them,
 * over Stela's checked global-heap boundary (memory.h). A nonzero zero flag
 * clears the allocation; the heap keeps its own layout, so free needs no size.
 * There is no atomic or timer-context allocation. */
#include "nvidia-modeset-os-interface.h"
#include "memory.h"

void *nvkms_alloc(size_t size, NvBool zero)
{
    void *pointer = NULL;
    if (stela_nvidia_alloc(size, &pointer) != STELA_NVIDIA_ALLOC_SUCCESS)
        return NULL;
    if (zero)
        nvkms_memset(pointer, 0, size);
    return pointer;
}

void nvkms_free(void *pointer, size_t size)
{
    (void)size;
    stela_nvidia_free(pointer);
}

_Static_assert(sizeof(size_t) == sizeof(NvU64), "native allocation length");
_Static_assert(sizeof(NvBool) == 1, "NvBool is one byte");
