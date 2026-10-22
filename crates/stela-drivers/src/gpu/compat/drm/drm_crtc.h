/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_CRTC_H
#define STELA_DRM_CRTC_H
#include <linux/list.h>
#include <drm/drm_device.h>
#include <drm/drm_modeset_lock.h>
/* The CRTC state unchanged sources read; Stela builds no KMS state. */
struct drm_crtc_state {
	bool active;
};
struct drm_crtc {
	struct list_head head;
	struct drm_modeset_lock mutex;
	struct drm_crtc_state *state;
};

/* Copyright © 2006 Keith Packard, © 2007-2008 Dave Airlie and © 2007-2008
 * Intel Corporation; from drm_crtc.h. */
#define drm_for_each_crtc(crtc, dev) \
	list_for_each_entry(crtc, &(dev)->mode_config.crtc_list, head)
#endif
