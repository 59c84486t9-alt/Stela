/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_UCODE_H
#define STELA_AMDGPU_UCODE_H
/* Copyright 2012 Advanced Micro Devices, Inc.; from amdgpu_ucode.h. */
enum amdgpu_firmware_load_type {
	AMDGPU_FW_LOAD_DIRECT = 0,
	AMDGPU_FW_LOAD_PSP,
	AMDGPU_FW_LOAD_SMU,
	AMDGPU_FW_LOAD_RLC_BACKDOOR_AUTO,
};

/* The firmware state unchanged sources read. */
struct amdgpu_firmware {
	enum amdgpu_firmware_load_type load_type;
};
#endif
