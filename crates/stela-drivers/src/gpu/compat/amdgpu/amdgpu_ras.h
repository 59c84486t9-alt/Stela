/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_RAS_H
#define STELA_AMDGPU_RAS_H
#include <linux/types.h>
struct amdgpu_device;
/* Services the sources call, which each adapter defines. */
static void amdgpu_ras_query_boot_status(struct amdgpu_device *adev, u32 num_instances);
static bool amdgpu_ras_intr_triggered(void);
#endif
