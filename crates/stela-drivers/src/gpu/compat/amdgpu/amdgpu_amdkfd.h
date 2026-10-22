/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_AMDKFD_H
#define STELA_AMDGPU_AMDKFD_H
struct amdgpu_device;
/* Services the sources call, which each adapter defines. */
static int amdgpu_amdkfd_init(void);
static void amdgpu_amdkfd_fini(void);
static int amdgpu_amdkfd_drm_client_create(struct amdgpu_device *adev);
#endif
