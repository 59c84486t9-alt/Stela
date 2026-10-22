/*
 * Copyright 2025 Advanced Micro Devices, Inc.
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

#ifndef __AMDGPU_IP_H__
#define __AMDGPU_IP_H__

#include "amd_shared.h"
#include "amdgpu_ip_limits.h"

struct amdgpu_device;

#include "amdgpu_ip_types.h"

struct amdgpu_ip_map_info {
	/* Map of logical to actual dev instances/mask */
	uint32_t dev_inst[MAX_HWIP][HWIP_MAX_INSTANCE];
	int8_t (*logical_to_dev_inst)(struct amdgpu_device *adev,
				      enum amd_hw_ip_block_type block,
				      int8_t inst);
	uint32_t (*logical_to_dev_mask)(struct amdgpu_device *adev,
					enum amd_hw_ip_block_type block,
					uint32_t mask);
};

#define AMDGPU_MAX_IP_NUM AMD_IP_BLOCK_TYPE_NUM

struct amdgpu_ip_block_status {
	bool valid;
	bool sw;
	bool hw;
	bool late_initialized;
	bool hang;
};

struct amdgpu_ip_block_version {
	const enum amd_ip_block_type type;
	const u32 major;
	const u32 minor;
	const u32 rev;
	const struct amd_ip_funcs *funcs;
};

struct amdgpu_ip_block {
	struct amdgpu_ip_block_status status;
	const struct amdgpu_ip_block_version *version;
	struct amdgpu_device *adev;
};

void amdgpu_ip_map_init(struct amdgpu_device *adev);

int amdgpu_ip_block_suspend(struct amdgpu_ip_block *ip_block);
int amdgpu_ip_block_resume(struct amdgpu_ip_block *ip_block);

struct amdgpu_ip_block *
amdgpu_device_ip_get_ip_block(struct amdgpu_device *adev,
			      enum amd_ip_block_type type);

int amdgpu_device_ip_block_version_cmp(struct amdgpu_device *adev,
				       enum amd_ip_block_type type, u32 major,
				       u32 minor);

int amdgpu_device_ip_block_add(
	struct amdgpu_device *adev,
	const struct amdgpu_ip_block_version *ip_block_version);

int amdgpu_device_ip_set_clockgating_state(struct amdgpu_device *adev,
					   enum amd_ip_block_type block_type,
					   enum amd_clockgating_state state);
int amdgpu_device_ip_set_powergating_state(struct amdgpu_device *adev,
					   enum amd_ip_block_type block_type,
					   enum amd_powergating_state state);
void amdgpu_device_ip_get_clockgating_state(struct amdgpu_device *adev,
					    u64 *flags);
int amdgpu_device_ip_wait_for_idle(struct amdgpu_device *adev,
				   enum amd_ip_block_type block_type);
bool amdgpu_device_ip_is_hw(struct amdgpu_device *adev,
			    enum amd_ip_block_type block_type);
bool amdgpu_device_ip_is_valid(struct amdgpu_device *adev,
			       enum amd_ip_block_type block_type);

#endif /* __AMDGPU_IP_H__ */
