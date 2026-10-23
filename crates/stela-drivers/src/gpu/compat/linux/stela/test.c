/* SPDX-License-Identifier: MIT */
/* The host under hosted test programs: the platform heap behind Linux's
 * allocators, and the services stela/test.h declares. Built on the C library,
 * outside Stela's Linux environment. */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void *stela_linux_heap_alloc(size_t size, size_t align);
void stela_linux_heap_free(void *object, size_t size, size_t align);
int64_t stela_test_now_ns(void);
void stela_test_sleep_us(uint64_t usecs);
_Noreturn void stela_test_fail(const char *file, int line, const char *condition);
int stela_test_traps(void (*operation)(void));

void *stela_linux_heap_alloc(size_t size, size_t align)
{
	if (align < sizeof(void *))
		align = sizeof(void *);
	void *object = aligned_alloc(align, (size + align - 1) / align * align);
	if (object)
		memset(object, 0, size);
	return object;
}

void stela_linux_heap_free(void *object, size_t size, size_t align)
{
	(void)size;
	(void)align;
	free(object);
}

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
