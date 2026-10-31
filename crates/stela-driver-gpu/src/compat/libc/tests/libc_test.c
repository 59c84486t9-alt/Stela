// SPDX-License-Identifier: MIT
/* The C library against the C standard's answers, as a static Linux program
 * with only this file for a host: `cargo xtask gpu nvk` builds and runs it. */
#include <errno.h>
#include <fenv.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stela/host.h>

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

static void leave(int status)
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

static _Alignas(4096) unsigned char arena[1 << 24];
static size_t arena_used;
static size_t live_blocks;

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

static unsigned int current_core;

unsigned int stela_libc_core(void)
{
	return current_core;
}

/* One host processor: a thread runs through at its start. */
int stela_libc_thread_start(void (*body)(void *), void *argument, unsigned int core)
{
	unsigned int caller = current_core;
	current_core = core;
	body(argument);
	current_core = caller;
	return 0;
}

static unsigned int waits, wakes;
/* What a wait changes, as another processor would. */
static volatile unsigned int *waited_word;
static unsigned int waited_value;

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

int stela_libc_drm_munmap(void *address, size_t size)
{
	(void)address;
	(void)size;
	return 0;
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

static int failures;

#define CHECK(condition)                                                                          \
	do {                                                                                      \
		if (!(condition)) {                                                               \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);           \
			failures++;                                                               \
		}                                                                                 \
	} while (0)

#define FORMATS(expected, ...)                                                                    \
	do {                                                                                      \
		char text[128];                                                                   \
		int length = snprintf(text, sizeof(text), __VA_ARGS__);                           \
		CHECK(!strcmp(text, expected));                                                   \
		CHECK(length == (int)strlen(expected));                                           \
	} while (0)

static int close_to(double value, double expected)
{
	double difference = fabs(value - expected);
	return difference <= 1e-12 * (fabs(expected) + 1e-300) || difference < 1e-300;
}

static void test_formatting(void)
{
	FORMATS("7", "%d", 7);
	FORMATS("-42|   -42|-42   |-0042", "%d|%6d|%-6d|%05d", -42, -42, -42, -42);
	FORMATS("ff FF 0xff 377", "%x %X %#x %o", 255u, 255u, 255u, 255u);
	FORMATS("18446744073709551615", "%llu", (unsigned long long)-1);
	FORMATS("-9223372036854775807", "%lld", -9223372036854775807ll);
	FORMATS("12345 12", "%zu %hhd", (size_t)12345, 268);
	FORMATS("a %", "%c %%", 'a');
	FORMATS("abc|  ab|ab  ", "%s|%4.2s|%-4.2s", "abc", "abc", "abc");
	FORMATS("(null)", "%s", (char *)NULL);
	FORMATS("3.141590", "%f", 3.14159);
	FORMATS("3.14|   3.1|0.5000", "%.2f|%6.1f|%.4f", 3.14159, 3.14159, 0.5);
	FORMATS("1.500000e+00", "%e", 1.5);
	FORMATS("1.5 100000 1e+06 0.0001 1e-05", "%g %g %g %g %g", 1.5, 100000.0, 1e6, 1e-4, 1e-5);
	FORMATS("inf -inf nan", "%f %f %f", (double)INFINITY, -(double)INFINITY, (double)NAN);
	FORMATS(" 5", "%*d", 2, 5);
	char small[4];
	CHECK(snprintf(small, sizeof(small), "%s", "abcdef") == 6);
	CHECK(!strcmp(small, "abc"));

	char *printed = NULL;
	CHECK(asprintf(&printed, "%d-%s", 1, "x") == 3);
	CHECK(!strcmp(printed, "1-x"));
	free(printed);

	char *stream_bytes = NULL;
	size_t stream_size = 0;
	FILE *stream = open_memstream(&stream_bytes, &stream_size);
	CHECK(stream != NULL);
	for (int i = 0; i < 1000; i++)
		fprintf(stream, "%03d", i);
	fclose(stream);
	CHECK(stream_size == 3000);
	CHECK(!memcmp(stream_bytes + 2997, "999", 3));
	free(stream_bytes);
}

static void test_parsing(void)
{
	char *end;
	CHECK(strtol("  -123x", &end, 10) == -123 && *end == 'x');
	CHECK(strtol("0x1f", NULL, 0) == 31);
	CHECK(strtol("077", NULL, 0) == 63);
	CHECK(strtoul("ff", NULL, 16) == 255);
	CHECK(strtoull("18446744073709551615", NULL, 10) == UINT64_MAX);
	CHECK(atoi("12") == 12);
	CHECK(close_to(strtod("1.5", NULL), 1.5));
	CHECK(close_to(strtod("-2.5e3", &end), -2500.0) && !*end);
	CHECK(close_to(strtod("1e10", NULL), 1e10));
	CHECK(close_to(strtod(".25", NULL), 0.25));
	CHECK(strtod("0.1", NULL) == 0.1);
	CHECK(strtod("123456789.125", NULL) == 123456789.125);
	CHECK(isinf(strtod("inf", NULL)));
	CHECK(isnan(strtod("nan", NULL)));
	CHECK(strtof("0.5", NULL) == 0.5f);
	int number = 0;
	char word[8];
	float real = 0;
	CHECK(sscanf("12 ab 2.5", "%d %7s %f", &number, word, &real) == 3);
	CHECK(number == 12 && !strcmp(word, "ab") && real == 2.5f);
	int consumed = 0;
	CHECK(sscanf("  7 x", "%d%n", &number, &consumed) == 1 && number == 7 && consumed == 3);
	CHECK(sscanf("abcdef", "%3s", word) == 1 && !strcmp(word, "abc"));
	unsigned int high, low;
	CHECK(sscanf("10de:2c02", "%x:%x", &high, &low) == 2);
	CHECK(high == 0x10de && low == 0x2c02);
}

static int ascending(const void *a, const void *b)
{
	int left = *(const int *)a, right = *(const int *)b;
	return (left > right) - (left < right);
}

static void test_sorting(void)
{
	int values[1024];
	unsigned int state = 1;
	for (int i = 0; i < 1024; i++) {
		state = state * 1103515245 + 12345;
		values[i] = (int)(state >> 16);
	}
	qsort(values, 1024, sizeof(int), ascending);
	for (int i = 1; i < 1024; i++)
		CHECK(values[i - 1] <= values[i]);
	int key = values[512];
	int *found = bsearch(&key, values, 1024, sizeof(int), ascending);
	CHECK(found && *found == key);
	key = values[0] - 1;
	CHECK(!bsearch(&key, values, 1024, sizeof(int), ascending));
}

static void test_strings(void)
{
	CHECK(strlen("abc") == 3);
	CHECK(strcmp("a", "b") < 0);
	CHECK(!strncmp("abcd", "abce", 3));
	CHECK(!strcasecmp("AbC", "aBc"));
	CHECK(!strcmp(strchr("a.b.c", '.'), ".b.c"));
	CHECK(!strcmp(strrchr("a.b.c", '.'), ".c"));
	CHECK(!strcmp(strstr("needle in", "in"), "in"));
	CHECK(strspn("aab", "a") == 2);
	CHECK(strcspn("aab", "b") == 2);
	char *copy = strdup("x,y");
	char *rest = NULL;
	CHECK(!strcmp(strtok_r(copy, ",", &rest), "x"));
	CHECK(!strcmp(strtok_r(NULL, ",", &rest), "y"));
	CHECK(!strtok_r(NULL, ",", &rest));
	free(copy);
	CHECK(strerror(ENOMEM)[0]);
}

static void test_allocation(void)
{
	size_t before = live_blocks;
	char *block = malloc(16);
	memset(block, 7, 16);
	block = realloc(block, 4096);
	CHECK(block[15] == 7);
	free(block);
	unsigned char *zero = calloc(32, 4);
	for (int i = 0; i < 128; i++)
		CHECK(zero[i] == 0);
	free(zero);
	void *aligned = aligned_alloc(4096, 8192);
	CHECK(!((uintptr_t)aligned & 4095));
	free(aligned);
	void *pointer = NULL;
	CHECK(!posix_memalign(&pointer, 64, 100));
	CHECK(!((uintptr_t)pointer & 63));
	free(pointer);
	CHECK(live_blocks == before);
	free(NULL);
}

static void test_math(void)
{
	CHECK(close_to(sin(1.0), 0.8414709848078965));
	CHECK(close_to(cos(1.0), 0.5403023058681398));
	CHECK(close_to(tan(0.5), 0.5463024898437905));
	CHECK(close_to(atan2(1.0, -1.0), 2.356194490192345));
	CHECK(close_to(asin(0.5), 0.5235987755982989));
	CHECK(close_to(acos(0.5), 1.0471975511965979));
	CHECK(close_to(exp(1.5), 4.4816890703380645));
	CHECK(close_to(log(10.0), 2.302585092994046));
	CHECK(close_to(log2(1024.0), 10.0));
	CHECK(close_to(log10(1000.0), 3.0));
	CHECK(close_to(pow(2.0, 0.5), 1.4142135623730951));
	CHECK(pow(2.0, 10.0) == 1024.0);
	CHECK(pow(-2.0, 3.0) == -8.0);
	CHECK(pow(0.0, 0.0) == 1.0);
	CHECK(close_to(cbrt(27.0), 3.0));
	CHECK(sqrt(9.0) == 3.0);
	CHECK(fmod(7.5, 2.0) == 1.5);
	CHECK(fmod(-7.5, 2.0) == -1.5);
	CHECK(remainder(7.0, 2.0) == -1.0);
	CHECK(floor(-1.5) == -2.0 && ceil(-1.5) == -1.0);
	CHECK(trunc(-1.5) == -1.0 && round(2.5) == 3.0);
	CHECK(lround(-2.5) == -3);
	CHECK(lrint(2.5) == 2);
	CHECK(llrint(3.5) == 4);
	CHECK(ldexp(3.0, 4) == 48.0);
	int exponent;
	CHECK(frexp(48.0, &exponent) == 0.75 && exponent == 6);
	double whole;
	CHECK(modf(-1.25, &whole) == -0.25 && whole == -1.0);
	CHECK(copysign(2.0, -0.0) == -2.0);
	CHECK(fma(2.0, 3.0, 1.0) == 7.0);
	CHECK(nextafter(1.0, 2.0) > 1.0);
	CHECK(powf(2.0f, 3.0f) == 8.0f);
	CHECK(sqrtf(16.0f) == 4.0f);
	CHECK(isnan(sqrt(-1.0)));
	CHECK(fesetround(FE_UPWARD) == 0);
	CHECK(fegetround() == FE_UPWARD);
	CHECK(lrint(2.1) == 3);
	CHECK(fesetround(FE_TONEAREST) == 0);
	feclearexcept(FE_ALL_EXCEPT);
	volatile double zero = 0.0;
	CHECK(isinf(1.0 / zero));
	CHECK(fetestexcept(FE_DIVBYZERO));
	feclearexcept(FE_ALL_EXCEPT);
	CHECK(!fetestexcept(FE_DIVBYZERO));
}

static void test_time(void)
{
	time_t epoch = 86400 * 365;
	struct tm parts;
	CHECK(localtime_r(&epoch, &parts) == &parts);
	CHECK(parts.tm_year == 71 && parts.tm_mon == 0 && parts.tm_mday == 1);
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	clock_gettime(CLOCK_MONOTONIC, &end);
	CHECK(end.tv_sec >= start.tv_sec);
	CHECK(!getenv("HOME"));
}

static _Thread_local int per_thread = 5;
static int once_runs;

static void once_body(void)
{
	once_runs++;
}

static void *thread_body(void *argument)
{
	CHECK(pthread_self() == STELA_LIBC_PROCESSORS + 1);
	CHECK(per_thread == 5);
	per_thread = 6;
	return (char *)argument + 1;
}

/* A compiler takes a thread-local object's address once per function. */
__attribute__((noinline)) static int *per_thread_on(unsigned int core)
{
	current_core = core;
	return &per_thread;
}

static void test_threads(void)
{
	/* A thread and each processor have their own thread-local object. */
	*per_thread_on(0) = 7;
	CHECK(*per_thread_on(3) == 5);
	CHECK(*per_thread_on(0) == 7);

	char argument[2];
	pthread_t thread;
	CHECK(!pthread_create(&thread, NULL, thread_body, argument));
	void *result = NULL;
	CHECK(!pthread_join(thread, &result));
	CHECK(result == argument + 1);
	CHECK(*per_thread_on(0) == 7);
	CHECK(pthread_join(1, NULL) == EINVAL);

	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	unsigned int woken = wakes;
	CHECK(!pthread_mutex_lock(&mutex));
	CHECK(pthread_mutex_trylock(&mutex) == EBUSY);
	/* A waiter goes through the host, where the holder lets go. */
	waited_word = (volatile unsigned int *)&mutex.locked;
	waited_value = 0;
	unsigned int waited = waits;
	CHECK(!pthread_mutex_lock(&mutex));
	CHECK(waits == waited + 1);
	waited_word = NULL;
	CHECK(!pthread_mutex_unlock(&mutex));
	CHECK(wakes == woken + 1);

	pthread_mutexattr_t attribute;
	pthread_mutexattr_init(&attribute);
	pthread_mutexattr_settype(&attribute, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_t recursive;
	pthread_mutex_init(&recursive, &attribute);
	CHECK(!pthread_mutex_lock(&recursive));
	CHECK(!pthread_mutex_lock(&recursive));
	CHECK(!pthread_mutex_unlock(&recursive));
	CHECK(recursive.locked);
	CHECK(!pthread_mutex_unlock(&recursive));
	CHECK(!recursive.locked);

	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	pthread_mutex_lock(&mutex);
	CHECK(pthread_cond_timedwait(&cond, &mutex, &now) == ETIMEDOUT);
	CHECK(mutex.locked);
	/* Another processor signals while this one waits. */
	waited_word = &cond.generation;
	waited_value = 1;
	CHECK(!pthread_cond_wait(&cond, &mutex));
	waited_word = NULL;
	pthread_mutex_unlock(&mutex);

	pthread_once_t once = PTHREAD_ONCE_INIT;
	CHECK(!pthread_once(&once, once_body));
	CHECK(!pthread_once(&once, once_body));
	CHECK(once_runs == 1);

	pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
	CHECK(!pthread_rwlock_rdlock(&lock));
	CHECK(!pthread_rwlock_rdlock(&lock));
	CHECK(lock.state == 2);
	CHECK(!pthread_rwlock_unlock(&lock));
	CHECK(!pthread_rwlock_unlock(&lock));
	CHECK(!pthread_rwlock_wrlock(&lock));
	CHECK(lock.state == -1);
	CHECK(!pthread_rwlock_unlock(&lock));
	CHECK(!lock.state);

	pthread_barrier_t barrier;
	pthread_barrier_init(&barrier, NULL, 1);
	CHECK(pthread_barrier_wait(&barrier) == PTHREAD_BARRIER_SERIAL_THREAD);

	pthread_key_t key;
	CHECK(!pthread_key_create(&key, NULL));
	CHECK(!pthread_setspecific(key, argument));
	CHECK(pthread_getspecific(key) == argument);
	current_core = 3;
	CHECK(!pthread_getspecific(key));
	current_core = 0;
}

__asm__(".globl _start\n_start:\n\tand $-16, %rsp\n\tcall run\n");

__attribute__((used)) static void run(void)
{
	test_formatting();
	test_parsing();
	test_sorting();
	test_strings();
	test_allocation();
	test_math();
	test_time();
	test_threads();
	if (failures)
		fprintf(stderr, "%d of the C library's checks failed\n", failures);
	leave(failures != 0);
}
