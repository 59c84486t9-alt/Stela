/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_PT_TYPES_H
#define STELA_XE_PT_TYPES_H
#include <linux/types.h>
#include "xe_pt_walk.h"
/* Copyright © 2022 Intel Corporation; from xe_pt_types.h. */
enum xe_cache_level {
	XE_CACHE_NONE,
	XE_CACHE_WT,
	XE_CACHE_WB,
	XE_CACHE_NONE_COMPRESSION, /*UC + COH_NONE + COMPRESSION */
	XE_CACHE_WB_COMPRESSION,
	__XE_CACHE_LEVEL_COUNT,
};
#endif
