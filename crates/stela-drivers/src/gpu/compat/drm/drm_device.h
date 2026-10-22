/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_DEVICE_H
#define STELA_DRM_DEVICE_H
#include <linux/types.h>
#include <drm/drm_mode_config.h>
struct device;

/* Copyright 1999 Precision Insight, Inc. and 2000 VA Linux Systems, Inc.;
 * from drm_device.h. */
enum switch_power_state {
	/** @DRM_SWITCH_POWER_ON: Power state is ON */
	DRM_SWITCH_POWER_ON = 0,

	/** @DRM_SWITCH_POWER_OFF: Power state is OFF */
	DRM_SWITCH_POWER_OFF = 1,

	/** @DRM_SWITCH_POWER_CHANGING: Power state is changing */
	DRM_SWITCH_POWER_CHANGING = 2,

	/** @DRM_SWITCH_POWER_DYNAMIC_OFF: Suspended */
	DRM_SWITCH_POWER_DYNAMIC_OFF = 3,
};

/* Stela has no DRM device; drivers embed one as their logging handle, and its
 * mode configuration and power state name what the unreached rest of a
 * driver would touch. */
struct drm_device {
	struct device *dev;
	u32 driver_features;
	struct drm_mode_config mode_config;
	enum switch_power_state switch_power_state;
};
#endif
