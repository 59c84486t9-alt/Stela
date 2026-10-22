// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "xe_wopcm.h"

#include <linux/fault-inject.h>

#include "regs/xe_guc_regs.h"
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_gt_types.h"
#include "xe_mmio.h"
#include "xe_uc_fw.h"

/**
 * DOC: Write Once Protected Content Memory (WOPCM) Layout
 *
 * The layout of the WOPCM will be fixed after writing to GuC WOPCM size and
 * offset registers whose values are calculated and determined by HuC/GuC
 * firmware size and set of hardware requirements/restrictions as shown below:
 *
 * ::
 *
 *    +=========> +====================+ <== WOPCM Top
 *    ^           |  HW contexts RSVD  |
 *    |     +===> +====================+ <== GuC WOPCM Top
 *    |     ^     |                    |
 *    |     |     |                    |
 *    |     |     |                    |
 *    |    GuC    |                    |
 *    |   WOPCM   |                    |
 *    |    Size   +--------------------+
 *  WOPCM   |     |    GuC FW RSVD     |
 *    |     |     +--------------------+
 *    |     |     |   GuC Stack RSVD   |
 *    |     |     +------------------- +
 *    |     v     |   GuC WOPCM RSVD   |
 *    |     +===> +====================+ <== GuC WOPCM base
 *    |           |     WOPCM RSVD     |
 *    |           +------------------- + <== HuC Firmware Top
 *    v           |      HuC FW        |
 *    +=========> +====================+ <== WOPCM Base
 *
 * GuC accessible WOPCM starts at GuC WOPCM base and ends at GuC WOPCM top.
 * The top part of the WOPCM is reserved for hardware contexts (e.g. RC6
 * context).
 */

static inline struct xe_gt *wopcm_to_gt(struct xe_wopcm *wopcm)
{
	return container_of(wopcm, struct xe_gt, uc.wopcm);
}

static inline struct xe_device *wopcm_to_xe(struct xe_wopcm *wopcm)
{
	return gt_to_xe(wopcm_to_gt(wopcm));
}

#define XE_WOPCM_WARN(core, id, condition) XE_WARN_ON(condition)
#include "xe_wopcm_core.h"

static u32 wopcm_read32(void *context, struct xe_reg reg)
{
	return xe_mmio_read32(&wopcm_to_gt(context)->mmio, reg);
}

static int wopcm_write32_and_verify(void *context, struct xe_reg reg,
				  u32 val, u32 mask, u32 eval)
{
	return xe_mmio_write32_and_verify(&wopcm_to_gt(context)->mmio, reg, val, mask, eval);
}

static bool wopcm_huc_available(void *context)
{
	return xe_uc_fw_is_available(&wopcm_to_gt(context)->uc.huc.fw);
}

static void wopcm_assert_held(void *context)
{
	xe_force_wake_assert_held(gt_to_fw(wopcm_to_gt(context)), XE_FW_GT);
}

static void wopcm_report(void *context, enum xe_wopcm_event event, u32 a, u32 b, u32 c)
{
	struct xe_device *xe = wopcm_to_xe(context);

	switch (event) {
	case XE_WOPCM_INVALID_LAYOUT:
		drm_err(&xe->drm, "WOPCM: invalid GuC region layout: %uK + %uK > %uK\n",
			a / SZ_1K, b / SZ_1K, c / SZ_1K);
		break;
	case XE_WOPCM_GUC_SPACE:
		drm_err(&xe->drm, "WOPCM: no space for %s: %uK < %uK\n",
			xe_uc_fw_type_repr(XE_UC_FW_TYPE_GUC), a / SZ_1K, b / SZ_1K);
		break;
	case XE_WOPCM_HUC_SPACE:
		drm_err(&xe->drm, "WOPCM: no space for %s: %uK < %uK\n",
			xe_uc_fw_type_repr(XE_UC_FW_TYPE_HUC), a / SZ_1K, b / SZ_1K);
		break;
	case XE_WOPCM_INIT_FAILED:
		drm_notice(&xe->drm, "Failed to init uC WOPCM registers!\n");
		break;
	case XE_WOPCM_OFFSET_READBACK:
		drm_notice(&xe->drm, "%s(%#x)=%#x\n", "DMA_GUC_WOPCM_OFFSET", a, b);
		break;
	case XE_WOPCM_SIZE_READBACK:
		drm_notice(&xe->drm, "%s(%#x)=%#x\n", "GUC_WOPCM_SIZE", a, b);
		break;
	case XE_WOPCM_TOTAL:
		drm_dbg(&xe->drm, "WOPCM: %uK\n", a / SZ_1K);
		break;
	case XE_WOPCM_LOCKED:
		drm_dbg(&xe->drm, "GuC WOPCM is already locked [%uK, %uK)\n", a / SZ_1K, b / SZ_1K);
		break;
	case XE_WOPCM_CALCULATED:
		drm_dbg(&xe->drm, "Calculated GuC WOPCM [%uK, %uK)\n", a / SZ_1K, b / SZ_1K);
		break;
	case XE_WOPCM_PARTITION_FAILED:
		drm_notice(&xe->drm, "Unsuccessful WOPCM partitioning\n");
		break;
	}
}

u32 xe_wopcm_size(struct xe_device *xe)
{
	return xe_wopcm_default_size(xe->info.platform, IS_DGFX(xe));
}

int xe_wopcm_init(struct xe_wopcm *wopcm)
{
	struct xe_device *xe = wopcm_to_xe(wopcm);
	struct xe_gt *gt = wopcm_to_gt(wopcm);
	u32 guc_fw_size = xe_uc_fw_get_upload_size(&gt->uc.guc.fw);
	u32 huc_fw_size = xe_uc_fw_get_upload_size(&gt->uc.huc.fw);
	static const struct xe_wopcm_core_ops ops = {
		wopcm_read32, wopcm_write32_and_verify, wopcm_huc_available,
		wopcm_assert_held, wopcm_report,
	};
	const struct xe_wopcm_core core = {wopcm, &ops};

	return xe_wopcm_core_init(wopcm, xe->info.platform, IS_DGFX(xe),
				 guc_fw_size, huc_fw_size, &core);
}
ALLOW_ERROR_INJECTION(xe_wopcm_init, ERRNO); /* See xe_pci_probe() */
