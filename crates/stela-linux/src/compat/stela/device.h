/* SPDX-License-Identifier: MIT */
#ifndef STELA_DEVICE_H
#define STELA_DEVICE_H
struct device;

/* Undoes the managed actions on dev, last first: a driver's teardown. */
void stela_linux_devres_release(struct device *dev);
#endif
