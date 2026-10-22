// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */
#ifndef XE_FORCE_WAKE_GT_H
#define XE_FORCE_WAKE_GT_H
static inline struct xe_reg xe_force_wake_gt_ack(u32 graphics_verx100)
{
	if (graphics_verx100 >= 1270)
		return FORCEWAKE_ACK_GT_MTL;
	return FORCEWAKE_ACK_GT;
}
static inline void xe_force_wake_domain_init(struct xe_force_wake_domain *domain,
		enum xe_force_wake_domain_id id, struct xe_reg reg, struct xe_reg ack)
{
	domain->id = id;
	domain->reg_ctl = reg;
	domain->reg_ack = ack;
	domain->val = FORCEWAKE_MT(FORCEWAKE_KERNEL);
	domain->mask = FORCEWAKE_MT_MASK(FORCEWAKE_KERNEL);
}
static inline int xe_force_wake_wait_status(int ret, u32 value)
{
	return value == ~((u32)0) ? -EIO : ret;
}
static inline u32 xe_force_wake_control(const struct xe_force_wake_domain *domain, bool wake)
{
	return domain->mask | (wake ? domain->val : 0);
}
#endif
