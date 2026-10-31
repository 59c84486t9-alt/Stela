// SPDX-License-Identifier: MIT
/* The host a test of the C library's users runs on: Linux, by its system calls,
 * with one processor. */
#include "host.h"
#include <ctype.h>
#include <errno.h>
#include <stela/host.h>
#include <string.h>
#include <wchar.h>

static long linux_call(long number, long a, long b, long c)
{
	long result;
	__asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b), "d"(c)
			 : "rcx", "r11", "memory");
	return result;
}

#define LINUX_WRITE 1
#define LINUX_CLOCK_GETTIME 228
#define LINUX_EXIT 231
#define MONOTONIC 1

void leave(int status)
{
	linux_call(LINUX_EXIT, status, 0, 0);
	__builtin_trap();
}

void *memcpy(void *destination, const void *source, size_t size)
{
	__asm__ volatile("rep movsb" : "+D"(destination), "+S"(source), "+c"(size) : : "memory");
	return destination;
}

void *memset(void *destination, int value, size_t size)
{
	unsigned char *bytes = destination;
	while (size--)
		*bytes++ = (unsigned char)value;
	return destination;
}

void *memmove(void *destination, const void *source, size_t size)
{
	unsigned char *to = destination;
	const unsigned char *from = source;
	if (to < from) {
		while (size--)
			*to++ = *from++;
	} else {
		while (size--)
			to[size] = from[size];
	}
	return destination;
}

int memcmp(const void *a, const void *b, size_t size)
{
	const unsigned char *left = a, *right = b;
	for (size_t at = 0; at < size; at++) {
		if (left[at] != right[at])
			return left[at] - right[at];
	}
	return 0;
}

static _Alignas(4096) unsigned char arena[1 << 28];
static size_t arena_used;
size_t live_blocks;

void *stela_libc_allocate(size_t size, size_t alignment)
{
	size_t start = (arena_used + alignment - 1) & ~(alignment - 1);
	if (start + size > sizeof(arena))
		return NULL;
	arena_used = start + size;
	live_blocks++;
	return arena + start;
}

void stela_libc_release(void *pointer, size_t size, size_t alignment)
{
	(void)pointer;
	(void)size;
	(void)alignment;
	live_blocks--;
}

void stela_libc_log(const char *text, size_t size)
{
	linux_call(LINUX_WRITE, 2, (long)text, (long)size);
}

_Noreturn void stela_libc_fatal(const char *message)
{
	stela_libc_log(message, strlen(message));
	leave(2);
	__builtin_unreachable();
}

uint64_t stela_libc_now_ns(void)
{
	struct {
		long seconds, nanoseconds;
	} time;
	linux_call(LINUX_CLOCK_GETTIME, MONOTONIC, (long)&time, 0);
	return (uint64_t)time.seconds * 1000000000 + (uint64_t)time.nanoseconds;
}

unsigned int current_core;
int thread_start_error;

unsigned int stela_libc_core(void)
{
	return current_core;
}

/* One host processor: a thread runs through at its start. */
int stela_libc_thread_start(void (*body)(void *), void *argument, unsigned int core)
{
	if (thread_start_error)
		return thread_start_error;
	unsigned int caller = current_core;
	current_core = core;
	body(argument);
	current_core = caller;
	return 0;
}

unsigned int waits, wakes;
volatile unsigned int *waited_word;
unsigned int waited_value;

void stela_libc_wait(const volatile unsigned int *word, unsigned int value, uint64_t deadline)
{
	(void)deadline;
	waits++;
	if (word == waited_word)
		*waited_word = waited_value;
	(void)value;
}

void stela_libc_wake(const volatile unsigned int *word)
{
	(void)word;
	wakes++;
}

int stela_libc_drm_open(unsigned int minor)
{
	(void)minor;
	return -ENODEV;
}

int stela_libc_drm_close(int fd)
{
	(void)fd;
	return -ENODEV;
}

int stela_libc_drm_dup(int fd)
{
	(void)fd;
	return -ENODEV;
}

long stela_libc_drm_rdev(int fd)
{
	(void)fd;
	return -ENODEV;
}

int stela_libc_drm_ioctl(int fd, unsigned long request, void *argument)
{
	(void)fd;
	(void)request;
	(void)argument;
	return -ENODEV;
}

void *stela_libc_drm_mmap(int fd, uint64_t offset, size_t size)
{
	(void)fd;
	(void)offset;
	(void)size;
	return (void *)-ENODEV;
}

/* Inject the real host ABI's recognized-mapping result without freeing the
 * test's allocator backing, which lets the fixture detect an incorrect free. */
void *drm_unmap_address;
int drm_unmap_result;

int stela_libc_drm_munmap(void *address, size_t size)
{
	(void)size;
	return address == drm_unmap_address ? drm_unmap_result : 0;
}

unsigned int stela_libc_drm_devices(void)
{
	return 0;
}

void stela_libc_drm_device(unsigned int index, struct stela_libc_drm_device *device)
{
	(void)index;
	(void)device;
}

__asm__(".globl _start\n_start:\n\tand $-16, %rsp\n\tcall start\n");

extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

__attribute__((used)) static void start(void)
{
	for (void (**constructor)(void) = __init_array_start; constructor < __init_array_end;
	     constructor++)
		(*constructor)();
	leave(test());
}

/* `stela.efi` takes these from what shares its image: Linux's lib/string.c, and
 * the UEFI crates' wcslen. */

void *memchr(const void *from, int value, size_t size)
{
	const unsigned char *at = from;
	for (; size; at++, size--) {
		if (*at == (unsigned char)value)
			return (void *)at;
	}
	return NULL;
}

/* What compilers turn a memcmp's equality into. */
int bcmp(const void *left, const void *right, size_t size)
{
	return memcmp(left, right, size);
}

size_t strlen(const char *text)
{
	const char *at = text;
	while (*at)
		at++;
	return (size_t)(at - text);
}

size_t strnlen(const char *text, size_t limit)
{
	size_t size = 0;
	while (size < limit && text[size])
		size++;
	return size;
}

char *stpcpy(char *to, const char *from)
{
	while ((*to = *from++))
		to++;
	return to;
}

char *strcpy(char *to, const char *from)
{
	stpcpy(to, from);
	return to;
}

char *strcat(char *to, const char *from)
{
	strcpy(to + strlen(to), from);
	return to;
}

char *strncat(char *to, const char *from, size_t size)
{
	char *end = to + strlen(to);
	size_t length = strnlen(from, size);
	memcpy(end, from, length);
	end[length] = 0;
	return to;
}

int strcmp(const char *a, const char *b)
{
	for (; *a && *a == *b; a++, b++)
		;
	return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t size)
{
	for (; size && *a && *a == *b; a++, b++, size--)
		;
	return size ? (unsigned char)*a - (unsigned char)*b : 0;
}

int strcasecmp(const char *a, const char *b)
{
	for (; *a && tolower((unsigned char)*a) == tolower((unsigned char)*b); a++, b++)
		;
	return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

int strncasecmp(const char *a, const char *b, size_t size)
{
	for (; size && *a && tolower((unsigned char)*a) == tolower((unsigned char)*b);
	     a++, b++, size--)
		;
	return size ? tolower((unsigned char)*a) - tolower((unsigned char)*b) : 0;
}

char *strchr(const char *text, int c)
{
	for (;; text++) {
		if (*text == (char)c)
			return (char *)text;
		if (!*text)
			return NULL;
	}
}

char *strrchr(const char *text, int c)
{
	const char *found = NULL;
	do {
		if (*text == (char)c)
			found = text;
	} while (*text++);
	return (char *)found;
}

char *strstr(const char *text, const char *needle)
{
	return memmem(text, strlen(text), needle, strlen(needle));
}

size_t strspn(const char *text, const char *accept)
{
	size_t size = 0;
	while (text[size] && strchr(accept, text[size]))
		size++;
	return size;
}

size_t strcspn(const char *text, const char *reject)
{
	size_t size = 0;
	while (text[size] && !strchr(reject, text[size]))
		size++;
	return size;
}

char *strpbrk(const char *text, const char *accept)
{
	text += strcspn(text, accept);
	return *text ? (char *)text : NULL;
}

size_t wcslen(const wchar_t *text)
{
	size_t length = 0;
	while (text[length])
		length++;
	return length;
}
