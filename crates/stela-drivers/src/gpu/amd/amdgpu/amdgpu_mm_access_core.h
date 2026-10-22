/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2008 Advanced Micro Devices, Inc.
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

#ifndef AMDGPU_MM_ACCESS_CORE_H
#define AMDGPU_MM_ACCESS_CORE_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif
/* Callers include the original BIF register definitions. No default hardware
 * access, lock, lifetime, allocator or synthetic device context is supplied.
 * Original Linux wrapper retains drm_dev_enter and IRQ-safe MM-index locking;
 * the native owner must provide genuine equivalent exclusion before entry.
 */
struct amdgpu_mm_access_ops {
	uint32_t (*read32)(void *, uint32_t);
	void (*write32)(void *, uint32_t, uint32_t);
};
/* Preserve the original signed loff_t/unsigned last comparison and conversion;
 * the native entry preflights the complete nonnegative signed range. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
static inline void amdgpu_mm_access_core(const struct amdgpu_mm_access_ops *ops,
		void *context, int64_t pos, uint32_t *data, size_t size, bool write)
{
	uint32_t hi = ~0, tmp = 0;
	uint64_t last;
	for (last = pos + size; pos < last; pos += 4) {
		tmp = pos >> 31;

		ops->write32(context, mmMM_INDEX, ((uint32_t)pos) | 0x80000000);
		if (tmp != hi) {
			ops->write32(context, mmMM_INDEX_HI, tmp);
			hi = tmp;
		}
		if (write)
			ops->write32(context, mmMM_DATA, *data++);
		else
			*data++ = ops->read32(context, mmMM_DATA);
	}

}
#pragma GCC diagnostic pop
#endif
