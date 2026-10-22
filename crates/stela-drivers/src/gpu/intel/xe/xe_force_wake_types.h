/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _XE_FORCE_WAKE_TYPES_H_
#define _XE_FORCE_WAKE_TYPES_H_

#include <linux/mutex.h>
#include <linux/types.h>

#include "regs/xe_reg_defs.h"

#include "xe_force_wake_domain_types.h"

/**
 * struct xe_force_wake - Xe force wake collection
 *
 * Represents a collection of related power domains (struct
 * xe_force_wake_domain) associated with a subunit of the device.
 *
 * Currently only used for GT power domains (where the term "forcewake" is used
 * in the hardware documentation), although the interface could be extended to
 * power wells in other parts of the hardware in the future.
 */
struct xe_force_wake {
	/** @gt: back pointers to GT */
	struct xe_gt *gt;
	/** @lock: protects everything force wake struct */
	spinlock_t lock;
	/** @awake_domains: mask of all domains awake */
	unsigned int awake_domains;
	/** @initialized_domains: mask of all initialized domains */
	unsigned int initialized_domains;
	/** @domains: force wake domains */
	struct xe_force_wake_domain domains[XE_FW_DOMAIN_ID_COUNT];
};

#endif
