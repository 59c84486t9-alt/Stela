/* SPDX-License-Identifier: MIT */
/* The host under hosted test programs: the platform heap behind Linux's
 * allocators, and the services stela/test.h declares. Built on the C library,
 * outside Stela's Linux environment. */
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void *stela_linux_heap_alloc(size_t size, size_t align);
void stela_linux_heap_free(void *object, size_t size, size_t align);
bool stela_linux_heap_try_available(void);
void *stela_linux_heap_try_alloc(size_t size, size_t align);
void stela_test_heap_try_enable(bool enable);
bool stela_test_heap_try_contains(const void *object);
int64_t stela_test_now_ns(void);
void stela_test_sleep_us(uint64_t usecs);
_Noreturn void stela_test_fail(const char *file, int line, const char *condition);
int stela_test_traps(void (*operation)(void));
int stela_test_witnessed(void (*operation)(void));
_Noreturn void stela_test_witness_passed(void);

/* Same test-only ABI as stela/test.h; this TU deliberately uses libc types
 * rather than mixing incompatible Linux/POSIX header definitions. */
struct stela_test_allocations { uint64_t heap, heap_try, pages; };
void stela_test_allocations_begin(bool refuse);
struct stela_test_allocations stela_test_allocations_snapshot(void);
struct stela_test_allocations stela_test_allocations_end(void);
bool stela_test_allocation_attempt(unsigned int route);
/* Per thread: a fixture counts and refuses only its own thread's attempts.
 * Other threads of the test process, such as the harness thread that spawned
 * the fixture's, keep allocating while a window is armed. */
static _Thread_local uint64_t allocation_attempts[3];
static _Thread_local bool refuse_allocations;

void stela_test_allocations_begin(bool refuse)
{
 for (unsigned int i = 0; i < 3; i++)
  allocation_attempts[i] = 0;
 refuse_allocations = refuse;
}

struct stela_test_allocations stela_test_allocations_snapshot(void)
{
 return (struct stela_test_allocations){
  .heap = allocation_attempts[0],
  .heap_try = allocation_attempts[1],
  .pages = allocation_attempts[2],
 };
}

struct stela_test_allocations stela_test_allocations_end(void)
{
 refuse_allocations = false;
 return stela_test_allocations_snapshot();
}

bool stela_test_allocation_attempt(unsigned int route)
{
 if (route >= 3 || allocation_attempts[route]++ == UINT64_MAX)
  abort();
 return !refuse_allocations;
}

#ifndef STELA_TEST_CANONICAL_RUST_HEAP
/* Actual preallocated storage, not a libc allocator called under NOWAIT.
 * One span makes contention/exhaustion and same-backend free observable. */
static _Alignas(4096) unsigned char try_storage[64 * 1024];
static _Atomic bool try_enabled;
static _Atomic bool try_occupied;
static size_t try_size, try_align;

void stela_test_heap_try_enable(bool enable)
{
	if (atomic_load_explicit(&try_occupied, memory_order_acquire))
		abort();
	atomic_store_explicit(&try_enabled, enable, memory_order_release);
}

bool stela_linux_heap_try_available(void)
{
	return atomic_load_explicit(&try_enabled, memory_order_acquire);
}

void *stela_linux_heap_try_alloc(size_t size, size_t align)
{
 if (!stela_test_allocation_attempt(1))
  return NULL;
	if (!stela_linux_heap_try_available())
		abort();
	if (!size || !align || (align & (align - 1)) ||
	    align > 4096 || size > sizeof(try_storage))
		return NULL;
	bool expected = false;
	if (!atomic_compare_exchange_strong_explicit(&try_occupied, &expected, true,
					     memory_order_acquire, memory_order_relaxed))
		return NULL;
	try_size = size;
	try_align = align;
	memset(try_storage, 0, size);
	return try_storage;
}

bool stela_test_heap_try_contains(const void *object)
{
	/* Caller owns this returned allocation and excludes free/reallocation;
	 * occupied alone does not publish the later plain size/align writes. */
	if (!atomic_load_explicit(&try_occupied, memory_order_acquire))
		return false;
	uintptr_t base = (uintptr_t)try_storage, address = (uintptr_t)object;
	return address >= base && address - base < try_size;
}

void *stela_linux_heap_alloc(size_t size, size_t align)
{
 if (!stela_test_allocation_attempt(0))
  return NULL;
	if (align < sizeof(void *))
		align = sizeof(void *);
	void *object = aligned_alloc(align, (size + align - 1) / align * align);
	if (object)
		memset(object, 0, size);
	return object;
}

void stela_linux_heap_free(void *object, size_t size, size_t align)
{
	if (object == try_storage) {
		if (!atomic_load_explicit(&try_occupied, memory_order_relaxed) ||
		    size != try_size || align != try_align)
			abort();
		memset(try_storage, 0xd3, size);
		atomic_store_explicit(&try_occupied, false, memory_order_release);
		return;
	}
	(void)size;
	(void)align;
	free(object);
}

#endif /* !STELA_TEST_CANONICAL_RUST_HEAP */

int64_t stela_test_now_ns(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now))
		abort();
	return (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

void stela_test_sleep_us(uint64_t usecs)
{
	struct timespec left = {(time_t)(usecs / 1000000), (long)(usecs % 1000000) * 1000};
	while (nanosleep(&left, &left) && errno == EINTR) {
	}
}

void stela_test_fail(const char *file, int line, const char *condition)
{
	fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, condition);
	abort();
}

static void expected_trap(int signal_number)
{
	(void)signal_number;
	_Exit(86);
}

int stela_test_traps(void (*operation)(void))
{
	pid_t child = fork();
	if (child < 0)
		abort();
	if (!child) {
		if (signal(SIGILL, expected_trap) == SIG_ERR)
			_Exit(87);
		operation();
		_Exit(88);
	}
	int status;
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR)
			abort();
	}
	return WIFEXITED(status) && WEXITSTATUS(status) == 86;
}

/* The observer reaches this only in ordinary C context, after its assertions.
 * This distinct status cannot be confused with the expected SIGILL handler,
 * normal operation return, setup failure or an arbitrary crashing child. */
_Noreturn void stela_test_witness_passed(void)
{
 _Exit(89);
}

int stela_test_witnessed(void (*operation)(void))
{
 pid_t child = fork();
 if (child < 0)
  abort();
 if (!child) {
  if (signal(SIGILL, expected_trap) == SIG_ERR)
   _Exit(87);
  operation();
  _Exit(88);
 }
 int status;
 while (waitpid(child, &status, 0) < 0) {
  if (errno != EINTR)
   abort();
 }
 return WIFEXITED(status) && WEXITSTATUS(status) == 89;
}
