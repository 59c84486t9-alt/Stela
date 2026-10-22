/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_CTX_H
#define STELA_AMDGPU_CTX_H
#include <linux/types.h>
struct amdgpu_ctx;
struct dma_fence;
struct drm_device;
struct drm_file;
/* Stela creates no submission contexts; the type names a file's manager. */
struct amdgpu_ctx_mgr {
};
/* Services the sources call, which each adapter defines. */
static long amdgpu_ctx_mgr_entity_flush(struct amdgpu_ctx_mgr *mgr, long timeout);
static int amdgpu_ctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
#endif
