/*
 * SPDX-FileCopyrightText: Copyright (c) 2015-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
 * Original nvkms_alloc/free CPU metadata boundary at official NVIDIA pin
 * 1a82fbfda8f321b056eb3568850f9316c5e465c5. Replace only the Linux
 * kmalloc(GFP_KERNEL)/vmalloc/kfree/vfree backend with the existing checked
 * common heap. No atomic request, context detection or timer service exists
 * here. The original nonzero-zero flag and sized-free caller contract remain.
 */
#include "nvidia-modeset-os-interface.h"
#include "memory.h"

void *nvkms_alloc(size_t size, NvBool zero)
{
    void *pointer = NULL;
    if (stela_nvidia_alloc(size, &pointer) != STELA_NVIDIA_ALLOC_SUCCESS)
        return NULL;
    if (zero && (pointer != NULL))
        nvkms_memset(pointer, 0, size);
    return pointer;
}

void nvkms_free(void *pointer, size_t size)
{
    /* The original caller supplies the exact allocation size. The common
     * backend retains its own exact Layout; it needs no page-size dispatch.
     */
    (void)size;
    stela_nvidia_free(pointer);
}

_Static_assert(sizeof(size_t) == sizeof(NvU64), "native allocation length");
_Static_assert(sizeof(NvBool) == 1, "original zero flag width");
