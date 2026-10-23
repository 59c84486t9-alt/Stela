/*
 * SPDX-FileCopyrightText: Copyright (c) 2016-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* Unchanged ordinary CPU primitive signatures/bodies from official
 * kernel-open/nvidia/linux_nvswitch.c at
 * 1a82fbfda8f321b056eb3568850f9316c5e465c5. The shared native runtime
 * owns these standard functions; no NvU32 length intermediate is introduced.
 */
#include "stela_primitives.h"
#include "export_nvswitch.h"

NvLength
nvswitch_os_strlen
(
    const char *str
)
{
    return strlen(str);
}

void *
nvswitch_os_memset
(
    void *dest,
    int value,
    NvLength size
)
{
     return memset(dest, value, size);
}

void *
nvswitch_os_memcpy
(
    void *dest,
    const void *src,
    NvLength size
)
{
    return memcpy(dest, src, size);
}
