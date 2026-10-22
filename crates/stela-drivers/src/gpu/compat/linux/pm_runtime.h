/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_PM_RUNTIME_H
#define STELA_LINUX_PM_RUNTIME_H
#include <linux/pm.h>
/* Stela has no runtime power management core; a source that takes or drops
 * a runtime reference declares the call it uses. */
static int pm_runtime_get_sync(struct device *dev);
static int pm_runtime_put_autosuspend(struct device *dev);
static void pm_runtime_use_autosuspend(struct device *dev);
static void pm_runtime_set_autosuspend_delay(struct device *dev, int delay);
static void pm_runtime_allow(struct device *dev);
static void pm_runtime_forbid(struct device *dev);
static bool pm_runtime_suspended(struct device *dev);
static int pm_runtime_autosuspend(struct device *dev);
#endif
