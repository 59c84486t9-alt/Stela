/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_LOCALE_H
#define STELA_LIBC_LOCALE_H
#include <sys/cdefs.h>
__BEGIN_DECLS
typedef struct __locale *locale_t;
#define LC_ALL 6
#define LC_ALL_MASK 0x1fbf
#define LC_NUMERIC 1
#define LC_NUMERIC_MASK 2
char *setlocale(int category, const char *locale);
locale_t newlocale(int mask, const char *locale, locale_t base);
void freelocale(locale_t locale);
locale_t uselocale(locale_t locale);
__END_DECLS
#endif
