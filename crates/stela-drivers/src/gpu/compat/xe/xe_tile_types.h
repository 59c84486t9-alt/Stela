/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_TILE_TYPES_H
#define STELA_XE_TILE_TYPES_H
#include <linux/types.h>
/* Register access through the activation owner's mapped BAR. */
struct stela_intel_activation_io;
struct xe_mmio {
	const struct stela_intel_activation_io *io;
	void *context;
	u32 adj_offset;
};
struct xe_device;
struct xe_gt;
struct xe_vram_region;
/* Copyright © 2022-2023 Intel Corporation; from xe_tile_types.h. */
#define tile_to_xe(tile__)									_Generic(tile__,										 const struct xe_tile * : (const struct xe_device *)((tile__)->xe),			 struct xe_tile * : (tile__)->xe)
struct xe_tile {
	struct xe_device *xe;
	u8 id;
	struct xe_gt *primary_gt;
	struct xe_gt *media_gt;
	struct xe_mmio mmio;
	struct {
		struct xe_vram_region *kernel_vram;
		struct xe_vram_region *vram;
	} mem;
};
#endif
