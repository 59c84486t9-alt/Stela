/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_DEVICE_TYPES_H
#define STELA_XE_DEVICE_TYPES_H
#include <drm/drm_device.h>
#include <linux/types.h>
#include "xe_cache_level.h"
#include "xe_platform_types.h"
/* Copyright © 2022-2023 Intel Corporation; from xe_device_types.h. */
#define GRAPHICS_VER(xe) ((xe)->info.graphics_verx100 / 100)
#define MEDIA_VER(xe) ((xe)->info.media_verx100 / 100)
#define GRAPHICS_VERx100(xe) ((xe)->info.graphics_verx100)
#define MEDIA_VERx100(xe) ((xe)->info.media_verx100)
/* Register access through the activation owner's mapped BAR. */
struct stela_intel_activation_io;
struct xe_mmio {
	const struct stela_intel_activation_io *io;
	void *context;
};
struct xe_pat_ops;
struct xe_pat_table_entry;
struct xe_device {
	struct drm_device drm;
	struct {
		enum xe_platform platform;
		u32 graphics_verx100;
		u32 media_verx100;
		bool is_dgfx;
		bool has_llc;
		bool is_sriov_vf;
	} info;
	struct {
		const struct xe_pat_ops *ops;
		const struct xe_pat_table_entry *table;
		int n_entries;
		const struct xe_pat_table_entry *pat_ats;
		const struct xe_pat_table_entry *pat_primary_pta;
		const struct xe_pat_table_entry *pat_media_pta;
		u16 idx[__XE_CACHE_LEVEL_COUNT];
	} pat;
};
#endif
