/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GT_TYPES_H
#define STELA_XE_GT_TYPES_H
#include <linux/container_of.h>
#include "xe_device_types.h"
#include "xe_force_wake_types.h"
#include "xe_gsc_types.h"
#include "xe_huc_types.h"
#include "xe_hw_engine_types.h"
#include "xe_uc_fw_types.h"
#include "xe_wopcm_types.h"
/* Copyright © 2022-2023 Intel Corporation; from xe_gt_types.h. */
enum xe_gt_type {
	XE_GT_TYPE_UNINITIALIZED,
	XE_GT_TYPE_MAIN,
	XE_GT_TYPE_MEDIA,
};
struct xe_guc {
	struct xe_uc_fw fw;
};
struct xe_uc {
	struct xe_guc guc;
	struct xe_huc huc;
	struct xe_gsc gsc;
	struct xe_wopcm wopcm;
};
#define gt_to_tile(gt__)							\
	_Generic(gt__,								\
		 const struct xe_gt * : (const struct xe_tile *)((gt__)->tile),	\
		 struct xe_gt * : (gt__)->tile)
#define gt_to_xe(gt__)										\
	_Generic(gt__,										\
		 const struct xe_gt * : (const struct xe_device *)(gt_to_tile(gt__)->xe),	\
		 struct xe_gt * : gt_to_tile(gt__)->xe)
struct xe_ring_ops;
struct xe_gt {
	struct xe_tile *tile;
	struct {
		enum xe_gt_type type;
		u32 reference_clock;
		u32 timestamp_base;
		u64 engine_mask;
		u32 gmdid;
		u16 multi_queue_engine_class_mask;
		u8 id;
		u8 has_indirect_ring_state:1;
		u8 has_xe2_blt_instructions:1;
		u8 num_geometry_xecore_fuse_regs;
		u8 num_compute_xecore_fuse_regs;
	} info;
	struct xe_mmio mmio;
	struct {
		struct xe_force_wake fw;
	} pm;
	struct xe_uc uc;
	const struct xe_ring_ops *ring_ops[XE_ENGINE_CLASS_MAX];
};
#endif
