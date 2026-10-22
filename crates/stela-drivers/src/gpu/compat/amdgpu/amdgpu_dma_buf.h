/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_DMA_BUF_H
#define STELA_AMDGPU_DMA_BUF_H
struct dma_buf;
struct drm_device;
struct drm_gem_object;
/* A service the sources call, which each adapter defines. */
static struct drm_gem_object *amdgpu_gem_prime_import(struct drm_device *dev,
						      struct dma_buf *dma_buf);
#endif
