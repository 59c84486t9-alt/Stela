/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2008, 2022 Advanced Micro Devices, Inc.
 * Copyright 2008 Red Hat Inc.
 * Copyright 2009 Jerome Glisse.
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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Dave Airlie
 *          Alex Deucher
 *          Jerome Glisse
 */
#ifndef STELA_AMD_NATIVE_BAR_H
#define STELA_AMD_NATIVE_BAR_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include <drm/amd_asic_type.h>

/* Pure policies shared with original amdgpu_device/doorbell consumers.
 * Callers retain original ASIC classification and actual doorbell assignment.
 * Native entry preflights arithmetic before using the original expressions.
 */
static inline unsigned
amdgpu_native_register_bar(enum amd_asic_type asic_type)
{
   return asic_type >= CHIP_BONAIRE ? 5 : 2;
}

static inline uint32_t
amdgpu_native_kernel_doorbell_count(enum amd_asic_type asic_type,
                                   uint64_t bar_bytes, uint32_t max_assignment)
{
   uint32_t count = (uint32_t)(bar_bytes / sizeof(uint32_t));
   count = count < max_assignment + 1 ? count : max_assignment + 1;
   if (!count)
      return 0;
   /*
    * For Vega, reserve and map two pages on doorbell BAR since SDMA
    * paging queue doorbell use the second page. The
    * AMDGPU_DOORBELL64_MAX_ASSIGNMENT definition assumes all the
    * doorbells are in the first page. So with paging queue enabled,
    * the max num_kernel_doorbells should + 1 page (0x400 in dword)
    */
   if (asic_type >= CHIP_VEGA10)
      count += 0x400;
   return count;
}

static inline uint64_t
amdgpu_native_kernel_doorbell_storage_bytes(uint32_t count, uint64_t page_bytes)
{
   return ((uint64_t)count * sizeof(uint32_t) + page_bytes - 1) & ~(page_bytes - 1);
}

static inline uint64_t
amdgpu_native_kernel_doorbell_bytes(uint32_t count, uint64_t page_bytes)
{
   uint64_t size = amdgpu_native_kernel_doorbell_storage_bytes(count, page_bytes);
   /* Original extra page for MES kernel usages (ring test). */
   size += page_bytes;
   return size;
}

#ifndef __KERNEL__
enum stela_amd_bar_status {
   STELA_AMD_BAR_OK,
   STELA_AMD_BAR_INVALID,
   STELA_AMD_BAR_UNREPRESENTABLE,
};

struct stela_amd_bar_layout {
   uint32_t register_bar;
   uint32_t kernel_doorbells; /* Actual original post-allocation DWORD extent. */
   uint64_t kernel_doorbell_bytes;
};

/* Facts come from the original matched PCI function/ASIC and initialized
 * doorbell-index owner; never Mesa family or display inventory inference.
 * SI passes zero doorbell facts. CIK+ supplies its actual BAR and assignment.
 * Output is unchanged on error. This query reserves/maps/writes nothing.
 */
enum stela_amd_bar_status
stela_amd_native_register_bar(uint32_t asic_type, uint32_t *bar);

enum stela_amd_bar_status
stela_amd_native_bar_layout(uint32_t asic_type, uint64_t doorbell_bar_bytes,
                            uint32_t max_assignment, uint64_t page_bytes,
                            struct stela_amd_bar_layout *layout);
#endif
#endif
