/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_FIRMWARE_H
#define STELA_LINUX_FIRMWARE_H
#include <linux/module.h>
#include <linux/types.h>
struct device;
/* Stela's firmware Provider hands drivers immutable images; adapters wrap one
 * in this view. Each translation unit that requests firmware defines these. */
struct firmware {
	size_t size;
	const u8 *data;
};
static int firmware_request_nowarn(const struct firmware **fw, const char *name,
				   struct device *device);
static void release_firmware(const struct firmware *fw);
#endif
