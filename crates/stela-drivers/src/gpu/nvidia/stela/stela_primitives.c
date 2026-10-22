/*
 * SPDX-FileCopyrightText: Copyright (c) 1999-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Original native-x86/default primitive bodies from kernel-open/nvidia/
 * os-interface.c at 1a82fbfda8f321b056eb3568850f9316c5e465c5.
 * Architecture-specific Linux/device-memory and size-optimized fallback branches
 * are not selected by this native x86-64 Stela build. The shared runtime owns
 * the actual algorithms; no new libc, address inference or provider shim.
 */
#include "os-interface.h"
#include "stela_primitives.h"

NvU32 NV_API_CALL os_string_length(
    const char* str
)
{
    return strlen(str);
}

void *NV_API_CALL os_mem_copy(
    void       *dst,
    const void *src,
    NvU32       length
)
{
    return memcpy(dst, src, length);
}

void* NV_API_CALL os_mem_set(
    void  *dst,
    NvU8   c,
    NvU32  length
)
{
    return memset(dst, (int)c, length);
}

NvS32 NV_API_CALL os_mem_cmp(
    const NvU8 *buf0,
    const NvU8* buf1,
    NvU32 length
)
{
    return memcmp(buf0, buf1, length);
}
