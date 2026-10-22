/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GT_PRINTK_H
#define STELA_XE_GT_PRINTK_H
#include "xe_device.h"
/* Stela's GT reports carry the upstream message without the tile/GT prefix;
 * the adapter that owns the device already names it. */
#define xe_gt_err(gt, format, ...) drm_err(&gt_to_xe(gt)->drm, format, ##__VA_ARGS__)
#define xe_gt_notice(gt, format, ...) drm_notice(&gt_to_xe(gt)->drm, format, ##__VA_ARGS__)
#define xe_gt_info(gt, format, ...) drm_info(&gt_to_xe(gt)->drm, format, ##__VA_ARGS__)
#define xe_gt_dbg(gt, format, ...) drm_dbg(&gt_to_xe(gt)->drm, format, ##__VA_ARGS__)
/* Defined by each translation unit that prints through a GT printer. */
static struct drm_printer xe_gt_info_printer(struct xe_gt *gt);
#endif
