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

/* Frozen exact original amdgpu_device_mm_access at Linux
 * 8d3ae59288f1e7d58d76558a6ee96d533bc5019f. Test-only MMIO/lifetime bindings.
 * Function body SHA256 b05945ca92b5878eb8bedc88dd18a62bfd45ffd953c1597e1bfe1570b48e8f91.
 */
void amdgpu_device_mm_access(struct amdgpu_device *adev, loff_t pos,
			     void *buf, size_t size, bool write)
{
	unsigned long flags;
	uint32_t hi = ~0, tmp = 0;
	uint32_t *data = buf;
	uint64_t last;
	int idx;

	if (!drm_dev_enter(adev_to_drm(adev), &idx))
		return;

	if (!IS_ALIGNED(pos, 4) || !IS_ALIGNED(size, 4)) {
		dev_err(adev->dev, "unaligned pos/size (pos=0x%llx, size=0x%zx)\n",
			pos, size);
		drm_dev_exit(idx);
		return;
	}

	spin_lock_irqsave(&adev->mmio_idx_lock, flags);
	for (last = pos + size; pos < last; pos += 4) {
		tmp = pos >> 31;

		WREG32_NO_KIQ(mmMM_INDEX, ((uint32_t)pos) | 0x80000000);
		if (tmp != hi) {
			WREG32_NO_KIQ(mmMM_INDEX_HI, tmp);
			hi = tmp;
		}
		if (write)
			WREG32_NO_KIQ(mmMM_DATA, *data++);
		else
			*data++ = RREG32_NO_KIQ(mmMM_DATA);
	}

	spin_unlock_irqrestore(&adev->mmio_idx_lock, flags);
	drm_dev_exit(idx);
}
