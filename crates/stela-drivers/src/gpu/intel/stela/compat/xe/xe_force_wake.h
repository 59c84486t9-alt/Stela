/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_FORCE_WAKE_H
#define STELA_XE_FORCE_WAKE_H
#include <linux/cleanup.h>
#include "xe_force_wake_types.h"
/* Defined by each translation unit that uses forcewake. */
static unsigned int xe_force_wake_get(struct xe_force_wake *fw, unsigned int domains);
static void xe_force_wake_put(struct xe_force_wake *fw, unsigned int fw_ref);
static void xe_force_wake_assert_held(struct xe_force_wake *fw,
				      enum xe_force_wake_domains domain);
/* Copyright © 2022 Intel Corporation; from xe_force_wake.h. */
struct xe_force_wake_ref {
	struct xe_force_wake *fw;
	unsigned int domains;
};

static struct xe_force_wake_ref
xe_force_wake_constructor(struct xe_force_wake *fw, unsigned int domains)
{
	struct xe_force_wake_ref fw_ref = { .fw = fw };

	fw_ref.domains = xe_force_wake_get(fw, domains);

	return fw_ref;
}

DEFINE_CLASS(xe_force_wake, struct xe_force_wake_ref,
	     xe_force_wake_put(_T.fw, _T.domains),
	     xe_force_wake_constructor(fw, domains),
	     struct xe_force_wake *fw, unsigned int domains);
#endif
