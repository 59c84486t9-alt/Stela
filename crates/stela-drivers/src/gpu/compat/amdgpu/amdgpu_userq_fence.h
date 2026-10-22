/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_USERQ_FENCE_H
#define STELA_AMDGPU_USERQ_FENCE_H
struct drm_device;
struct drm_file;
/* Services the sources call, which each adapter defines. */
static int amdgpu_userq_signal_ioctl(struct drm_device *dev, void *data,
				     struct drm_file *filp);
static int amdgpu_userq_wait_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
#endif
