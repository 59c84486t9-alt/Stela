/* SPDX-License-Identifier: MIT */
/* RM's CPU primitives, as os-interface.h declares them, over the shared C
 * runtime. Lengths keep RM's NvU32 width. */
#include "os-interface.h"
#include "stela_primitives.h"

NvU32 NV_API_CALL os_string_length(const char *str)
{
    return (NvU32)strlen(str);
}

void *NV_API_CALL os_mem_copy(void *dst, const void *src, NvU32 length)
{
    return memcpy(dst, src, length);
}

void *NV_API_CALL os_mem_set(void *dst, NvU8 c, NvU32 length)
{
    return memset(dst, (int)c, length);
}

NvS32 NV_API_CALL os_mem_cmp(const NvU8 *buf0, const NvU8 *buf1, NvU32 length)
{
    return memcmp(buf0, buf1, length);
}
