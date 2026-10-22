/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_ASSERT_H
#define STELA_XE_ASSERT_H
#include <linux/cleanup.h>
#include "xe_device_types.h"
#include "xe_gt_types.h"
/* As Linux builds without CONFIG_DRM_XE_DEBUG: type-checked, never evaluated. */
#define xe_assert(xe, condition) ({ \
	const struct xe_device *__stela_xe = (xe); \
	(void)__stela_xe; \
	(void)sizeof(!!(condition)); \
})
#define xe_gt_assert(gt, condition) ({ \
	const struct xe_gt *__stela_gt = (gt); \
	(void)__stela_gt; \
	(void)sizeof(!!(condition)); \
})
#endif
