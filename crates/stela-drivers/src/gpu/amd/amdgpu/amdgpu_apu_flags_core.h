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

#ifndef AMDGPU_APU_FLAGS_CORE_H
#define AMDGPU_APU_FLAGS_CORE_H
#include "../../common/linux/include/drm/amd_asic_type.h"
#include "../include/amd_chip_flags.h"
static inline unsigned long amdgpu_initial_apu_flags(unsigned long flags,
		enum amd_asic_type asic_type, unsigned short device, unsigned long apu_flags)
{
	if (!(flags & AMD_IS_APU) ||
	    asic_type < CHIP_RAVEN)
		return apu_flags;

	switch (asic_type) {
	case CHIP_RAVEN:
		if (device == 0x15dd)
			apu_flags |= AMD_APU_IS_RAVEN;
		if (device == 0x15d8)
			apu_flags |= AMD_APU_IS_PICASSO;
		break;
	case CHIP_RENOIR:
		if ((device == 0x1636) ||
		    (device == 0x164c))
			apu_flags |= AMD_APU_IS_RENOIR;
		else
			apu_flags |= AMD_APU_IS_GREEN_SARDINE;
		break;
	case CHIP_VANGOGH:
		apu_flags |= AMD_APU_IS_VANGOGH;
		break;
	case CHIP_YELLOW_CARP:
		break;
	case CHIP_CYAN_SKILLFISH:
		if ((device == 0x13FE) ||
		    (device == 0x143F))
			apu_flags |= AMD_APU_IS_CYAN_SKILLFISH2;
		break;
	default:
		break;
	}

	return apu_flags;
}
#endif
