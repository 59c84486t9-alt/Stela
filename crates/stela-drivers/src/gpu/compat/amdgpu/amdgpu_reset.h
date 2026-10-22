/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_RESET_H
#define STELA_AMDGPU_RESET_H
struct amdgpu_reset_domain;
/* Services the sources call, which each adapter defines. */
static void amdgpu_device_lock_reset_domain(struct amdgpu_reset_domain *reset_domain);
static void amdgpu_device_unlock_reset_domain(struct amdgpu_reset_domain *reset_domain);
#endif
