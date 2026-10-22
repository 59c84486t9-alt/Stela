/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_HUC_ROLE_H
#define XE_HUC_ROLE_H
/* Original xe_huc_init no-main-GT-HuC rule, not missing-firmware policy. */
static inline bool xe_huc_role_unsupported(bool media_gt, unsigned graphics_verx100)
{
	return !media_gt && graphics_verx100 > 1255;
}
#endif
