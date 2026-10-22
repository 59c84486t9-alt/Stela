/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_SCHED_H
#define STELA_AMDGPU_SCHED_H
struct drm_device;
struct drm_file;
/* A service the sources call, which each adapter defines. */
static int amdgpu_sched_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
#endif
