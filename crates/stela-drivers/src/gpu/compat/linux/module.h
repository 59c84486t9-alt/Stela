/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_MODULE_H
#define STELA_LINUX_MODULE_H
#include <linux/stringify.h>
/* Stela links no kernel modules, so there is no .modinfo section to fill. */
#define MODULE_FIRMWARE(_firmware)
#define MODULE_DEVICE_TABLE(type, name)
#endif
