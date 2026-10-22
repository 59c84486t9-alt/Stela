/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_PM_H
#define STELA_LINUX_PM_H
#include <linux/bits.h>
#include <linux/kconfig.h>
#include <linux/util_macros.h>
struct device;

/* Copyright (C) 2006 Rafael J. Wysocki <rjw@sisk.pl>; from pm.h. */
struct dev_pm_ops {
	int (*prepare)(struct device *dev);
	void (*complete)(struct device *dev);
	int (*suspend)(struct device *dev);
	int (*resume)(struct device *dev);
	int (*freeze)(struct device *dev);
	int (*thaw)(struct device *dev);
	int (*poweroff)(struct device *dev);
	int (*restore)(struct device *dev);
	int (*suspend_late)(struct device *dev);
	int (*resume_early)(struct device *dev);
	int (*freeze_late)(struct device *dev);
	int (*thaw_early)(struct device *dev);
	int (*poweroff_late)(struct device *dev);
	int (*restore_early)(struct device *dev);
	int (*suspend_noirq)(struct device *dev);
	int (*resume_noirq)(struct device *dev);
	int (*freeze_noirq)(struct device *dev);
	int (*thaw_noirq)(struct device *dev);
	int (*poweroff_noirq)(struct device *dev);
	int (*restore_noirq)(struct device *dev);
	int (*runtime_suspend)(struct device *dev);
	int (*runtime_resume)(struct device *dev);
	int (*runtime_idle)(struct device *dev);
};

#define pm_ptr(_ptr) PTR_IF(IS_ENABLED(CONFIG_PM), (_ptr))
#define pm_sleep_ptr(_ptr) PTR_IF(IS_ENABLED(CONFIG_PM_SLEEP), (_ptr))

#define DPM_FLAG_NO_DIRECT_COMPLETE	BIT(0)
#define DPM_FLAG_SMART_PREPARE		BIT(1)
#define DPM_FLAG_SMART_SUSPEND		BIT(2)
#define DPM_FLAG_MAY_SKIP_RESUME	BIT(3)

/* Stela has no device power management core; a source that sets a power
 * flag declares it. */
static void dev_pm_set_driver_flags(struct device *dev, u32 flags);
#endif
