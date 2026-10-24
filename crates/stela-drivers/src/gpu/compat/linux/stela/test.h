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
/* A separate child must stop at the contract trap instead of returning. */
int stela_test_traps(void (*operation)(void));
/* A bounded preallocated hosted heap model. Toggle only with no live try
 * allocation or concurrent allocator caller; it proves no native IRQ behavior. */
void stela_test_heap_try_enable(bool enable);
/* Diagnostic for the caller's own live allocation, excluding concurrent free
 * or reallocation. The occupied flag is not arbitrary-observer publication. */
bool stela_test_heap_try_contains(const void *object);

__noreturn void stela_test_fail(const char *file, int line, const char *condition);
#define assert(condition) \
	((condition) ? (void)0 : stela_test_fail(__FILE__, __LINE__, #condition))
#endif
