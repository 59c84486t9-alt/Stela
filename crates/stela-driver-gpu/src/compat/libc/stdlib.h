/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_STDLIB_H
#define STELA_LIBC_STDLIB_H
#include <sys/cdefs.h>
#include <alloca.h>
#include <stddef.h>
__BEGIN_DECLS
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX 0x7fffffff
typedef struct {
	int quot;
	int rem;
} div_t;
typedef struct {
	long quot;
	long rem;
} ldiv_t;
typedef struct {
	long long quot;
	long long rem;
} lldiv_t;
void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *pointer, size_t size);
void free(void *pointer);
void *aligned_alloc(size_t alignment, size_t size);
int posix_memalign(void **pointer, size_t alignment, size_t size);
_Noreturn void abort(void);
_Noreturn void exit(int status);
_Noreturn void _Exit(int status);
int atexit(void (*function)(void));
char *getenv(const char *name);
char *secure_getenv(const char *name);
int mkstemps(char *path, int suffix);
int mkstemp(char *path);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
char *realpath(const char *path, char *resolved);
int atoi(const char *text);
long atol(const char *text);
double atof(const char *text);
long strtol(const char *text, char **end, int base);
unsigned long strtoul(const char *text, char **end, int base);
long long strtoll(const char *text, char **end, int base);
unsigned long long strtoull(const char *text, char **end, int base);
double strtod(const char *text, char **end);
float strtof(const char *text, char **end);
long double strtold(const char *text, char **end);
void qsort(void *base, size_t count, size_t size, int (*compare)(const void *, const void *));
void qsort_r(void *base, size_t count, size_t size,
	     int (*compare)(const void *, const void *, void *), void *context);
void *bsearch(const void *key, const void *base, size_t count, size_t size,
	      int (*compare)(const void *, const void *));
int abs(int value);
long labs(long value);
long long llabs(long long value);
div_t div(int number, int divisor);
ldiv_t ldiv(long number, long divisor);
lldiv_t lldiv(long long number, long long divisor);
int rand(void);
void srand(unsigned int seed);
__END_DECLS
#endif
