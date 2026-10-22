/*
 * Copyright 2018-2024 Advanced Micro Devices, Inc. All rights reserved.
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
 */

/* Frozen original Linux8d3ae592 TMR query, CPU-only service model. */
static int amdgpu_discovery_get_tmr_info(struct amdgpu_device *adev,
					 bool *is_tmr_in_sysmem)
{
	u64 vram_size, tmr_offset, tmr_size;
	u32 msg, tmr_offset_lo, tmr_offset_hi;
	int i, ret;

	if (!amdgpu_sriov_vf(adev)) {
		/* It can take up to two second for IFWI init to complete on some dGPUs,
		 * but generally it should be in the 60-100ms range.  Normally this starts
		 * as soon as the device gets power so by the time the OS loads this has long
		 * completed.  However, when a card is hotplugged via e.g., USB4, we need to
		 * wait for this to complete.  Once the C2PMSG is updated, we can
		 * continue.
		 */

		for (i = 0; i < 2000; i++) {
			msg = RREG32(mmMP0_SMN_C2PMSG_33);
			if (msg & 0x80000000)
				break;
			msleep(1);
		}
	}

	vram_size = RREG32(mmRCC_CONFIG_MEMSIZE);
	if (vram_size == U32_MAX)
		return -ENXIO;
	else if (!vram_size)
		*is_tmr_in_sysmem = true;
	else
		*is_tmr_in_sysmem = false;

	/* init the default tmr size and offset */
	adev->discovery.size = DISCOVERY_TMR_SIZE;
	if (vram_size)
		adev->discovery.offset = (vram_size << 20) - DISCOVERY_TMR_OFFSET;

	if (amdgpu_sriov_vf(adev)) {
		if (adev->virt.is_dynamic_crit_regn_enabled) {
			adev->discovery.offset =
				adev->virt.crit_regn_tbl[AMD_SRIOV_MSG_IPD_TABLE_ID].offset;
			adev->discovery.size =
				adev->virt.crit_regn_tbl[AMD_SRIOV_MSG_IPD_TABLE_ID].size_kb << 10;
			if (!adev->discovery.size)
				return -EINVAL;
		} else {
			goto out;
		}
	} else {
		if (adev->discovery.offset) {
			u32 signature;

			/* If VRAM holds a valid discovery signature at the default
			 * discovery offset, use it as-is.
			 */
			amdgpu_device_vram_access(adev, adev->discovery.offset,
						  &signature, sizeof(signature),
						  false);
			if (le32_to_cpu(signature) == BINARY_SIGNATURE)
				goto out;
		}

		tmr_size = RREG32(mmDRIVER_SCRATCH_2);
		if (tmr_size) {
			/* It's preferred to transition to PSP mailbox reg interface
			 * for both bare-metal and passthrough if available */
			adev->discovery.size = (u32)tmr_size;
			tmr_offset_lo = RREG32(mmDRIVER_SCRATCH_0);
			tmr_offset_hi = RREG32(mmDRIVER_SCRATCH_1);
			adev->discovery.offset = ((u64)le32_to_cpu(tmr_offset_hi) << 32 |
						  le32_to_cpu(tmr_offset_lo));
		} else if (!vram_size) {
			/* fall back to apci approach to query tmr offset if vram_size is 0 */
			ret = amdgpu_acpi_get_tmr_info(adev, &tmr_offset, &tmr_size);
			if (ret)
				return ret;
			adev->discovery.size = DISCOVERY_TMR_SIZE;
			adev->discovery.offset = tmr_offset + tmr_size - DISCOVERY_TMR_OFFSET;
		}
	}
out:
	adev->discovery.bin = kzalloc(adev->discovery.size, GFP_KERNEL);
	if (!adev->discovery.bin)
		return -ENOMEM;
	adev->discovery.debugfs_blob.data = adev->discovery.bin;
	adev->discovery.debugfs_blob.size = adev->discovery.size;

	return 0;
}

