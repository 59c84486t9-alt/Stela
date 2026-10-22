/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GT_H
#define STELA_XE_GT_H
#include "xe_gt_types.h"
/* Copyright © 2022 Intel Corporation; from xe_gt.h. */
static inline bool xe_gt_is_main_type(struct xe_gt *gt)
{
	return gt->info.type == XE_GT_TYPE_MAIN;
}
static inline bool xe_gt_is_media_type(struct xe_gt *gt)
{
	return gt->info.type == XE_GT_TYPE_MEDIA;
}
#endif
