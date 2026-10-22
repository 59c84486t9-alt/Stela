/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_FORCE_WAKE_H
#define STELA_XE_FORCE_WAKE_H
#include "xe_force_wake_types.h"
/* Defined by each translation unit that asserts forcewake. */
static void xe_force_wake_assert_held(struct xe_force_wake *fw,
				      enum xe_force_wake_domains domain);
#endif
