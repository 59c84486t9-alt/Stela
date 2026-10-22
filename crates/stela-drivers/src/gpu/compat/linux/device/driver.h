/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_DEVICE_DRIVER_H
#define STELA_LINUX_DEVICE_DRIVER_H
struct dev_pm_ops;
/* Stela has no driver core; a driver's description names its power
 * operations. */
struct device_driver {
	const struct dev_pm_ops *pm;
};
#endif
