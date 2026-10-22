/* SPDX-License-Identifier: MIT */
#ifndef STELA_KGD_PP_INTERFACE_H
#define STELA_KGD_PP_INTERFACE_H
#include "amdgpu_ip.h"
/* Copyright 2017 Advanced Micro Devices, Inc.; from kgd_pp_interface.h. */
enum amd_dpm_forced_level {
	AMD_DPM_FORCED_LEVEL_AUTO = 0x1,
	AMD_DPM_FORCED_LEVEL_MANUAL = 0x2,
	AMD_DPM_FORCED_LEVEL_LOW = 0x4,
	AMD_DPM_FORCED_LEVEL_HIGH = 0x8,
	AMD_DPM_FORCED_LEVEL_PROFILE_STANDARD = 0x10,
	AMD_DPM_FORCED_LEVEL_PROFILE_MIN_SCLK = 0x20,
	AMD_DPM_FORCED_LEVEL_PROFILE_MIN_MCLK = 0x40,
	AMD_DPM_FORCED_LEVEL_PROFILE_PEAK = 0x80,
	AMD_DPM_FORCED_LEVEL_PROFILE_EXIT = 0x100,
	AMD_DPM_FORCED_LEVEL_PERF_DETERMINISM = 0x200,
};

enum pp_mp1_state {
	PP_MP1_STATE_NONE,
	PP_MP1_STATE_SHUTDOWN,
	PP_MP1_STATE_UNLOAD,
	PP_MP1_STATE_RESET,
	PP_MP1_STATE_FLR,
};

extern const struct amdgpu_ip_block_version pp_smu_ip_block;
extern const struct amdgpu_ip_block_version smu_v11_0_ip_block;
extern const struct amdgpu_ip_block_version smu_v12_0_ip_block;
extern const struct amdgpu_ip_block_version smu_v13_0_ip_block;
extern const struct amdgpu_ip_block_version smu_v14_0_ip_block;
extern const struct amdgpu_ip_block_version smu_v15_0_ip_block;
#endif
