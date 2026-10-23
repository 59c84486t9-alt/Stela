/* SPDX-License-Identifier: MIT */
/* NVSwitch's CPU primitives, as export_nvswitch.h declares them, over the
 * shared C runtime with 64-bit NvLength lengths. */
#include "stela_primitives.h"
#include "export_nvswitch.h"

NvLength nvswitch_os_strlen(const char *str)
{
    return strlen(str);
}

void *nvswitch_os_memset(void *dest, int value, NvLength size)
{
    return memset(dest, value, size);
}

void *nvswitch_os_memcpy(void *dest, const void *src, NvLength size)
{
    return memcpy(dest, src, size);
}
