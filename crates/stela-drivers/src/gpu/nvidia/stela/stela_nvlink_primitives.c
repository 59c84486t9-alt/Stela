/* SPDX-License-Identifier: MIT */
/* NVLink's CPU primitives, as nvlink_os.h declares them, over the shared C
 * runtime with 64-bit NvLength lengths. */
#include "stela_primitives.h"
#include "nvlink_os.h"

NvLength nvlink_strlen(const char *s)
{
    return strlen(s);
}

void *nvlink_memset(void *dest, int value, NvLength size)
{
    return memset(dest, value, size);
}

void *nvlink_memcpy(void *dest, const void *src, NvLength size)
{
    return memcpy(dest, src, size);
}
