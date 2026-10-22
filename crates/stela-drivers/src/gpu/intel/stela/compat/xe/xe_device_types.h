/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_DEVICE_TYPES_H
#define STELA_XE_DEVICE_TYPES_H
#include <drm/drm_device.h>
#include <linux/types.h>
#include "../../activation.h"
#include "xe_platform_types.h"
/* Register access through the activation owner's mapped BAR. */
struct xe_mmio {
	const struct stela_intel_activation_io *io;
	void *context;
};
struct xe_device {
	struct drm_device drm;
	struct {
		enum xe_platform platform;
		bool is_dgfx;
	} info;
};
#endif
