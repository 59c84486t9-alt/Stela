/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_MODESET_LOCK_H
#define STELA_DRM_MODESET_LOCK_H
#include <linux/mutex.h>
struct drm_modeset_acquire_ctx;
/* A KMS object lock, which a source that takes one declares as a service. */
struct drm_modeset_lock {
	struct mutex mutex;
};
static int drm_modeset_lock(struct drm_modeset_lock *lock,
			    struct drm_modeset_acquire_ctx *ctx);
static void drm_modeset_unlock(struct drm_modeset_lock *lock);
#endif
