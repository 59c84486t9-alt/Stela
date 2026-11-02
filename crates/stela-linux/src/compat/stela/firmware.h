/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_FIRMWARE_H
#define STELA_LINUX_FIRMWARE_H
#include <linux/types.h>
/* Shared Rust implementation, never a class-specific provider callback.
 * Authority is the Rust object of a real acquired original-device lease;
 * it retains exact source/config/code/catalogue through the complete copy. */
int stela_linux_firmware_image(const void *authority, const char *name,
                              const u8 **data, size_t *size);
#endif
