/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GT_SRIOV_VF_H
#define STELA_XE_GT_SRIOV_VF_H
struct xe_gt;
struct xe_uc_fw_version;
/* Stela admits physical functions only; each translation unit that names a VF
 * service defines it. */
static void xe_gt_sriov_vf_guc_versions(struct xe_gt *gt, struct xe_uc_fw_version *wanted,
					struct xe_uc_fw_version *found);
#endif
