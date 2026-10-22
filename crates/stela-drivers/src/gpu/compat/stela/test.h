/* SPDX-License-Identifier: MIT */
#ifndef STELA_TEST_H
#define STELA_TEST_H
/* What hosted test programs built in Stela's Linux environment use of the
 * host. Its C library headers define POSIX types differently from Linux, so
 * these programs declare the few functions they call instead of including
 * them; stela/test.c implements the rest on the C library. */
#include <linux/compiler.h>
#include <linux/types.h>

__printf(1, 2) int printf(const char *format, ...);
void *calloc(size_t count, size_t size);
void *aligned_alloc(size_t alignment, size_t size);
void free(void *object);

/* The host's monotonic clock, and a sleep of at least usecs on it. */
s64 stela_test_now_ns(void);
void stela_test_sleep_us(u64 usecs);

__noreturn void stela_test_fail(const char *file, int line, const char *condition);
#define assert(condition) \
	((condition) ? (void)0 : stela_test_fail(__FILE__, __LINE__, #condition))
#endif
