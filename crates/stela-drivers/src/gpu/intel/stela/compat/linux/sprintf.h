/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_SPRINTF_H
#define STELA_LINUX_SPRINTF_H
#include <linux/types.h>
/* Freestanding Stela has no C library formatter. Each translation unit that
 * formats defines this; the name keeps hosted <stdio.h> declarations apart. */
#define snprintf stela_linux_snprintf
static int stela_linux_snprintf(char *buf, size_t size, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
#endif
