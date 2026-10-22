/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_GMC_H
#define STELA_AMDGPU_GMC_H
#include <linux/types.h>
/* Copyright 2018 Advanced Micro Devices, Inc.; from amdgpu_gmc.h. */
struct amdgpu_gmc_memrange {
	uint64_t base_address;
	uint64_t limit_address;
	uint32_t flags;
	int nid_mask;
};
struct amdgpu_device;
/* A service the sources call, which each adapter defines. */
static void amdgpu_gmc_prepare_nps_mode_change(struct amdgpu_device *adev);
#endif
