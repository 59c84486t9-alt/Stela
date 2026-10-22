/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_DPM_H
#define STELA_AMDGPU_DPM_H
#include <linux/bits.h>
#include <linux/types.h>
#include "kgd_pp_interface.h"
struct amdgpu_device;

/* Copyright 2014 Advanced Micro Devices, Inc.; from amdgpu_dpm.h. */
enum amdgpu_runpm_mode {
	AMDGPU_RUNPM_NONE,
	AMDGPU_RUNPM_PX,
	AMDGPU_RUNPM_BOCO,
	AMDGPU_RUNPM_BACO,
	AMDGPU_RUNPM_BAMACO,
};

#define SMU_DEBUG_POOL_USE_VRAM		BIT(1)

/* The power state unchanged sources read; Stela manages no power states. */
struct amdgpu_pm {
	enum amdgpu_runpm_mode rpm_mode;
	uint32_t smu_debug_mask;
};
/* A service the sources call, which each adapter defines. */
static enum amd_dpm_forced_level amdgpu_dpm_get_performance_level(struct amdgpu_device *adev);
#endif
