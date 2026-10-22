/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_CACHE_LEVEL_H
#define XE_CACHE_LEVEL_H
enum xe_cache_level {
	XE_CACHE_NONE,
	XE_CACHE_WT,
	XE_CACHE_WB,
	XE_CACHE_NONE_COMPRESSION, /*UC + COH_NONE + COMPRESSION */
	XE_CACHE_WB_COMPRESSION,
	__XE_CACHE_LEVEL_COUNT,
};
#endif
