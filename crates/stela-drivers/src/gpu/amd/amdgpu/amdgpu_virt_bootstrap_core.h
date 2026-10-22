/*
 * Copyright 2016 Advanced Micro Devices, Inc.
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

#ifndef AMDGPU_VIRT_BOOTSTRAP_CORE_H
#define AMDGPU_VIRT_BOOTSTRAP_CORE_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <drm/amd_asic_type.h>
#else
#include <stdint.h>
#include <stdbool.h>
#include "../../common/linux/include/drm/amd_asic_type.h"
#endif
/* all asic after AI use this offset */
#define mmRCC_IOV_FUNC_IDENTIFIER 0xDE5
/* tonga/fiji use this offset */
#define mmBIF_IOV_FUNC_IDENTIFIER 0x1503
/* Exact original selector only; no SR-IOV/PF capability or host-mode claim. */
static inline bool amdgpu_virt_bootstrap_iov_register(enum amd_asic_type asic_type,
                                                    uint32_t *reg)
{
	switch (asic_type) {
	case CHIP_TONGA:
	case CHIP_FIJI:
		*reg = mmBIF_IOV_FUNC_IDENTIFIER;
		return true;
	case CHIP_VEGA10:
	case CHIP_VEGA20:
	case CHIP_NAVI10:
	case CHIP_NAVI12:
	case CHIP_SIENNA_CICHLID:
	case CHIP_ARCTURUS:
	case CHIP_ALDEBARAN:
	case CHIP_IP_DISCOVERY:
		*reg = mmRCC_IOV_FUNC_IDENTIFIER;
		return true;
	default: /* other chip doesn't support SRIOV */
		return false;
	}

}
#endif
