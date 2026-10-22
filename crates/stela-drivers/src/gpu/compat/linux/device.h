/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_DEVICE_H
#define STELA_LINUX_DEVICE_H
#include <linux/kobject.h>
#include <linux/pm.h>
/* A driver's device. Stela's owners hold its state, so a source that asks
 * for its driver data declares the call. */
struct device {
	struct kobject kobj;
};
static void *dev_get_drvdata(const struct device *dev);
#endif
