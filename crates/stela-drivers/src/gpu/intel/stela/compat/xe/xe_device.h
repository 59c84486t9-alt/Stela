/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_DEVICE_H
#define STELA_XE_DEVICE_H
#include <drm/drm_print.h>
#include <drm/drm_util.h>
#include <linux/align.h>
#include <linux/array_size.h>
#include <linux/bitops.h>
#include <linux/container_of.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/string_choices.h>
#include <vdso/time64.h>
#include "xe_device_types.h"
#include "xe_gt_types.h"
#include "xe_macros.h"
#include "xe_sriov.h"
/* Copyright © 2021 Intel Corporation; from xe_device.h. */
static inline struct xe_device *to_xe_device(const struct drm_device *dev)
{
	return container_of(dev, struct xe_device, drm);
}

static inline struct xe_tile *xe_device_get_root_tile(struct xe_device *xe)
{
	return &xe->tiles[0];
}

static inline struct xe_gt *xe_device_get_gt(struct xe_device *xe, u8 gt_id)
{
	struct xe_tile *tile;
	struct xe_gt *gt;

	if (gt_id >= xe->info.tile_count * xe->info.max_gt_per_tile)
		return NULL;

	tile = &xe->tiles[gt_id / xe->info.max_gt_per_tile];
	switch (gt_id % xe->info.max_gt_per_tile) {
	default:
		xe_assert(xe, false);
		fallthrough;
	case 0:
		gt = tile->primary_gt;
		break;
	case 1:
		gt = tile->media_gt;
		break;
	}

	if (!gt)
		return NULL;

	drm_WARN_ON(&xe->drm, gt->info.id != gt_id);
	drm_WARN_ON(&xe->drm, gt->info.type == XE_GT_TYPE_UNINITIALIZED);

	return gt;
}

static inline struct xe_mmio *xe_root_tile_mmio(struct xe_device *xe)
{
	return &xe->tiles[0].mmio;
}

static inline bool xe_device_uc_enabled(struct xe_device *xe)
{
	return !xe->info.force_execlist;
}

#define for_each_tile(tile__, xe__, id__) \
	for ((id__) = 0; (id__) < (xe__)->info.tile_count; (id__)++) \
		for_each_if((tile__) = &(xe__)->tiles[(id__)])

#define for_each_remote_tile(tile__, xe__, id__) \
	for ((id__) = 1; (id__) < (xe__)->info.tile_count; (id__)++) \
		for_each_if((tile__) = &(xe__)->tiles[(id__)])

#define for_each_gt(gt__, xe__, id__) \
	for ((id__) = 0; (id__) < (xe__)->info.tile_count * (xe__)->info.max_gt_per_tile; (id__)++) \
		for_each_if((gt__) = xe_device_get_gt((xe__), (id__)))

static inline struct xe_force_wake *gt_to_fw(struct xe_gt *gt)
{
	return &gt->pm.fw;
}
#endif
