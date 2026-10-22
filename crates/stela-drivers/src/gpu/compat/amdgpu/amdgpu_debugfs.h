/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_DEBUGFS_H
#define STELA_AMDGPU_DEBUGFS_H
struct amdgpu_device;
/* A service the sources call, which each adapter defines. */
static int amdgpu_debugfs_init(struct amdgpu_device *adev);
#endif
