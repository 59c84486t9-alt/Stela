/* SPDX-License-Identifier: MIT */
/* NVKMS's CPU primitives, as nvidia-modeset-os-interface.h declares them, over
 * the shared C runtime with size_t lengths. */
#include "stela_primitives.h"
#include "nvidia-modeset-os-interface.h"

void *nvkms_memset(void *ptr, NvU8 c, size_t size)
{
    return memset(ptr, c, size);
}

void *nvkms_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}

void *nvkms_memmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}

int nvkms_memcmp(const void *s1, const void *s2, size_t n)
{
    return memcmp(s1, s2, n);
}

size_t nvkms_strlen(const char *s)
{
    return strlen(s);
}
