/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GT_TYPES_H
#define STELA_XE_GT_TYPES_H
#include <linux/container_of.h>
#include "xe_device_types.h"
#include "xe_force_wake_types.h"
#include "xe_gt_type.h"
#include "xe_uc_fw_types.h"
#include "xe_wopcm_types.h"
struct xe_guc {
	struct xe_uc_fw fw;
};
struct xe_huc {
	struct xe_uc_fw fw;
};
struct xe_uc {
	struct xe_guc guc;
	struct xe_huc huc;
	struct xe_wopcm wopcm;
};
struct xe_gt {
	struct xe_device *xe;
	struct {
		enum xe_gt_type type;
	} info;
	struct xe_mmio mmio;
	struct {
		struct xe_force_wake fw;
	} pm;
	struct xe_uc uc;
};
#endif
