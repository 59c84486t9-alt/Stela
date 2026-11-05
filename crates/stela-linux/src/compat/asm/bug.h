/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_BUG_H
#define _ASM_STELA_BUG_H
/* Stela's WARN sites. x86 traps into report_bug(), which finds the site in a
 * bug table; Stela links no such table, so each site reports itself to the
 * running owner through the kernel-API, with its condition text, and a
 * BUGFLAG_ONCE site reports only its first warning. */
#include <linux/types.h>

void stela_linux_warn(const char *file, int line, const char *condition, unsigned int flags);

#define __WARN_FLAGS(cond_str, flags)					\
do {									\
	static bool __stela_warned;					\
	if (!((flags) & BUGFLAG_ONCE) || !__stela_warned) {		\
		__stela_warned = true;					\
		stela_linux_warn(__FILE__, __LINE__, cond_str,		\
				 BUGFLAG_WARNING | (flags));		\
	}								\
} while (0)

#include <asm-generic/bug.h>
#endif
