/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GT_MCR_H
#define STELA_XE_GT_MCR_H
#include "regs/xe_reg_defs.h"
#include "xe_gt_types.h"
/* Defined by each translation unit that references multicast registers. */
static u32 xe_gt_mcr_unicast_read_any(struct xe_gt *gt, struct xe_reg_mcr reg_mcr);
static void xe_gt_mcr_multicast_write(struct xe_gt *gt, struct xe_reg_mcr reg_mcr, u32 value);
#endif
