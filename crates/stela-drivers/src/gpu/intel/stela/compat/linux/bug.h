/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_BUG_H
#define STELA_LINUX_BUG_H
#include <linux/compiler.h>
#include <linux/types.h>
/* Linux reports a failed WARN_ON and continues. Each translation unit that
 * uses WARN_ON defines this report, which must return. */
static void stela_linux_warn(const char *file, int line, const char *condition);
#define WARN_ON(condition) ({ \
	bool __stela_warned = !!(condition); \
	if (unlikely(__stela_warned)) \
		stela_linux_warn(__FILE__, __LINE__, #condition); \
	unlikely(__stela_warned); \
})
#endif
