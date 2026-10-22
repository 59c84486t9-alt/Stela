/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_GEM_H
#define STELA_AMDGPU_GEM_H
#include <linux/types.h>
struct drm_device;
struct drm_file;
struct drm_mode_create_dumb;
/* Services the sources call, which each adapter defines. */
static int amdgpu_mode_dumb_create(struct drm_file *file_priv, struct drm_device *dev,
				   struct drm_mode_create_dumb *args);
static int amdgpu_mode_dumb_mmap(struct drm_file *filp, struct drm_device *dev,
				 uint32_t handle, uint64_t *offset_p);
static int amdgpu_gem_create_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_gem_userptr_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_gem_mmap_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_gem_wait_idle_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_gem_va_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_gem_op_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_gem_metadata_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_gem_list_handles_ioctl(struct drm_device *dev, void *data,
					 struct drm_file *filp);
#endif
