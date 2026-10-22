/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_MANAGED_H
#define STELA_DRM_MANAGED_H
struct drm_device;
typedef void (*drmres_release_t)(struct drm_device *dev, void *res);
/* Defined by each translation unit that registers a release action. */
static int drmm_add_action_or_reset(struct drm_device *dev, drmres_release_t action,
				    void *data);
#endif
