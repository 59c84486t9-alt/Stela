/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_DEVICE_H
#define STELA_XE_DEVICE_H
#include <drm/drm_print.h>
#include <linux/align.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/sprintf.h>
#include "xe_device_types.h"
#include "xe_gt_types.h"
#include "xe_macros.h"
#define IS_DGFX(xe) ((xe)->info.is_dgfx)
static inline struct xe_device *gt_to_xe(struct xe_gt *gt)
{
	return gt->xe;
}
static inline struct xe_force_wake *gt_to_fw(struct xe_gt *gt)
{
	return &gt->pm.fw;
}
#endif
