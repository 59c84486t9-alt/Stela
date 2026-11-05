/* SPDX-License-Identifier: GPL-2.0 */
/* Stela's arch takes the memory routines the compiler itself calls from the
 * platform's C runtime; linux/string.h declares the rest, which the unchanged
 * lib/string.c supplies. */
#ifndef _ASM_STELA_STRING_H
#define _ASM_STELA_STRING_H

#include <linux/types.h>

#define __HAVE_ARCH_MEMCPY
#define __HAVE_ARCH_MEMMOVE
#define __HAVE_ARCH_MEMSET
#define __HAVE_ARCH_MEMCMP
#define __HAVE_ARCH_BCMP
void *memcpy(void *dest, const void *src, size_t count);
void *memmove(void *dest, const void *src, size_t count);
void *memset(void *s, int c, size_t count);
int memcmp(const void *a, const void *b, size_t count);
int bcmp(const void *a, const void *b, size_t count);

#endif
