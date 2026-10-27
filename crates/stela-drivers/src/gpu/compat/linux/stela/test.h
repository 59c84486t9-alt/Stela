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

/* TEST ONLY: per-thread observation windows; other threads' allocator calls
 * are neither counted nor refused. Counts ATTEMPTS at every explicitly wired
 * route, including failed ones, not success/bytes. begin resets counters
 * without touching live ownership; end disarms refusal before returning the final snapshot. Page
 * fixture providers and canonical-Rust trampolines must wire their real route:
 * these counters do not observe an unwired allocation backend. */
#define STELA_TEST_ALLOC_HEAP 0U
#define STELA_TEST_ALLOC_HEAP_TRY 1U
#define STELA_TEST_ALLOC_PAGE 2U
struct stela_test_allocations { u64 heap, heap_try, pages; };
void stela_test_allocations_begin(bool refuse);
struct stela_test_allocations stela_test_allocations_snapshot(void);
struct stela_test_allocations stela_test_allocations_end(void);
bool stela_test_allocation_attempt(unsigned int route);

/* The host's monotonic clock, and a sleep of at least usecs on it. */
s64 stela_test_now_ns(void);
void stela_test_sleep_us(u64 usecs);
/* A separate child must stop at the contract trap instead of returning. */
int stela_test_traps(void (*operation)(void));
/* Separate child-local ordinary-C oracle. Only witness_passed's dedicated
 * status is accepted: SIGILL, crash, setup failure and return all fail. The
 * witness must inspect actual child state BEFORE calling witness_passed;
 * it never runs in a signal handler and supplies no production hook. */
int stela_test_witnessed(void (*operation)(void));
__noreturn void stela_test_witness_passed(void);
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
