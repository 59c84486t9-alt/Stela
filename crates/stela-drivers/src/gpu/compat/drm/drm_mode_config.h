/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_MODE_CONFIG_H
#define STELA_DRM_MODE_CONFIG_H
#include <linux/mutex.h>
#include <linux/types.h>
#include <drm/drm_modeset_lock.h>
/* The mode configuration members unchanged sources name; Stela builds no
 * KMS state. */
struct drm_mode_config {
	struct mutex mutex;
	struct drm_modeset_lock connection_mutex;
	struct list_head connector_list;
	struct list_head crtc_list;
};
#endif
