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

#ifndef AMDGPU_DISCOVERY_SOURCE_CORE_H
#define AMDGPU_DISCOVERY_SOURCE_CORE_H
#include "../../common/linux/include/drm/amd_asic_type.h"
#include "../include/amd_chip_flags.h"
/* Exact original early-init case groups; SI/CIK build admission is separate. */
enum amdgpu_initial_ip_path {
	AMDGPU_INITIAL_IP_DISCOVERY,
	AMDGPU_INITIAL_IP_SI,
	AMDGPU_INITIAL_IP_CIK,
	AMDGPU_INITIAL_IP_VI,
};
static inline enum amdgpu_initial_ip_path amdgpu_initial_ip_path(enum amd_asic_type asic_type)
{
	switch (asic_type) {
	case CHIP_VERDE:
	case CHIP_TAHITI:
	case CHIP_PITCAIRN:
	case CHIP_OLAND:
	case CHIP_HAINAN:
		return AMDGPU_INITIAL_IP_SI;
	case CHIP_BONAIRE:
	case CHIP_HAWAII:
	case CHIP_KAVERI:
	case CHIP_KABINI:
	case CHIP_MULLINS:
		return AMDGPU_INITIAL_IP_CIK;
	case CHIP_TOPAZ:
	case CHIP_TONGA:
	case CHIP_FIJI:
	case CHIP_POLARIS10:
	case CHIP_POLARIS11:
	case CHIP_POLARIS12:
	case CHIP_VEGAM:
	case CHIP_CARRIZO:
	case CHIP_STONEY:
		return AMDGPU_INITIAL_IP_VI;
	default:
		return AMDGPU_INITIAL_IP_DISCOVERY;
	}
}
/* The original switch has these static arms and one default dynamic arm. */
static inline enum amd_asic_type amdgpu_discovery_static_asic(enum amd_asic_type asic_type)
{
	switch (asic_type) {
	case CHIP_VEGA10:
	case CHIP_VEGA12:
	case CHIP_RAVEN:
	case CHIP_VEGA20:
	case CHIP_ARCTURUS:
	case CHIP_ALDEBARAN:
	case CHIP_CYAN_SKILLFISH:
		return asic_type;
	default:
		return CHIP_LAST;
	}
}
static inline int amdgpu_discovery_cyan_skillfish2(unsigned long apu_flags)
{
	return (apu_flags & AMD_APU_IS_CYAN_SKILLFISH2) != 0;
}
static inline const char *amdgpu_discovery_fw_name(enum amd_asic_type asic_type,
		unsigned long apu_flags, int discovery_option)
{
	if (discovery_option == 2) {
		return "amdgpu/ip_discovery.bin";
	}

	switch (asic_type) {
	case CHIP_VEGA10:
		return "amdgpu/vega10_ip_discovery.bin";
	case CHIP_VEGA12:
		return "amdgpu/vega12_ip_discovery.bin";
	case CHIP_RAVEN:
		if (apu_flags & AMD_APU_IS_RAVEN2)
			return "amdgpu/raven2_ip_discovery.bin";
		else if (apu_flags & AMD_APU_IS_PICASSO)
			return "amdgpu/picasso_ip_discovery.bin";
		else
			return "amdgpu/raven_ip_discovery.bin";
	case CHIP_VEGA20:
		return "amdgpu/vega20_ip_discovery.bin";
	case CHIP_ARCTURUS:
		return "amdgpu/arcturus_ip_discovery.bin";
	case CHIP_ALDEBARAN:
		return "amdgpu/aldebaran_ip_discovery.bin";
	default:
		return NULL;
	}
}
#endif
