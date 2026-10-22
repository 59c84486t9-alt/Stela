/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_DEVICE_H
#define STELA_DRM_DEVICE_H
struct device;
/* Stela has no DRM device; drivers embed one only as their logging handle. */
struct drm_device {
	struct device *dev;
};
#endif
