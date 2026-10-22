/* SPDX-License-Identifier: MIT */
/* Scalar RAM bindings only for compiling the actual donor/Linux caller; never
 * shipping Linux device objects, OS stubs or hardware capability providers. */
#include "guc_reset_model.h"
#define EIO 5
#define FIELD_PREP(mask, value) REG_FIELD_PREP(mask, value)
#define xe_guc reset_test_model
#define xe_gt reset_test_model
#define xe_mmio reset_test_mmio
#define guc_to_gt(guc) (guc)
#define gt_to_xe(gt) (gt)
#define gt_to_fw(gt) (gt)
#define XE_FW_GT 1u
#define IS_SRIOV_VF(gt) ((gt)->vf)
#define XE_GT_WA(gt, id) reset_test_wa(gt, id)
#define xe_gt_sriov_vf_bootstrap reset_test_bootstrap
#define xe_force_wake_assert_held reset_test_assert
#define xe_mmio_read32 reset_test_read
#define xe_mmio_write32 reset_test_write
#define xe_mmio_rmw32 reset_test_rmw
#define xe_mmio_wait32 reset_test_wait
#define xe_gt_warn reset_test_diagnostic
#define xe_gt_err reset_test_diagnostic
