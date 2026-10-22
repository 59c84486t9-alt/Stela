/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_SUSPEND_H
#define STELA_LINUX_SUSPEND_H
#include <linux/compiler_types.h>
#include <linux/types.h>
/* Copyright Linux kernel contributors; from suspend.h, without
 * CONFIG_SUSPEND and CONFIG_HIBERNATION as Stela builds it. */
typedef int __bitwise suspend_state_t;

#define PM_SUSPEND_ON		((__force suspend_state_t) 0)
#define pm_suspend_target_state	(PM_SUSPEND_ON)
static inline bool pm_hibernation_mode_is_suspend(void) { return false; }
static inline bool pm_hibernate_is_recovering(void) { return false; }
#endif
