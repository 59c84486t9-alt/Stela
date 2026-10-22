/*
 * SPDX-FileCopyrightText: Copyright (c) 2015-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
/*
 * Native CPU metadata boundary for original nvlink_malloc/nvlink_free at
 * official pin 1a82fbfda8f321b056eb3568850f9316c5e465c5. The original Linux
 * backend is kmalloc(size, GFP_KERNEL)/kfree(ptr). Only that backend changes:
 * Stela's existing checked common-heap adapter owns both allocation and free.
 * These functions have no atomic-request mode. See NVLINK_MEMORY.md.
 */
#include <stddef.h>
#include "nvlink_os.h"
#include "memory.h"

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
