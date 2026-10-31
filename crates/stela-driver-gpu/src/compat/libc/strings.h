/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_STRINGS_H
#define STELA_LIBC_STRINGS_H
#include <sys/cdefs.h>
#include <stddef.h>
__BEGIN_DECLS
int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t size);
static inline int ffs(int value) { return __builtin_ffs(value); }
static inline int ffsl(long value) { return __builtin_ffsl(value); }
static inline int ffsll(long long value) { return __builtin_ffsll(value); }
__END_DECLS
#endif
