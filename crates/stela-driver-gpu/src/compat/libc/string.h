/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_STRING_H
#define STELA_LIBC_STRING_H
#include <sys/cdefs.h>
#include <stddef.h>
#include <strings.h>
__BEGIN_DECLS
void *memcpy(void *to, const void *from, size_t size);
void *memmove(void *to, const void *from, size_t size);
void *memset(void *to, int value, size_t size);
int memcmp(const void *a, const void *b, size_t size);
void *memchr(const void *from, int value, size_t size);
void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size);
size_t strlen(const char *text);
size_t strnlen(const char *text, size_t limit);
char *strcpy(char *to, const char *from);
char *strncpy(char *to, const char *from, size_t size);
char *stpcpy(char *to, const char *from);
char *strcat(char *to, const char *from);
char *strncat(char *to, const char *from, size_t size);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t size);
char *strchr(const char *text, int c);
char *strrchr(const char *text, int c);
char *strstr(const char *text, const char *needle);
char *strdup(const char *text);
char *strndup(const char *text, size_t limit);
size_t strspn(const char *text, const char *accept);
size_t strcspn(const char *text, const char *reject);
char *strpbrk(const char *text, const char *accept);
char *strtok(char *text, const char *delimiters);
char *strtok_r(char *text, const char *delimiters, char **state);
char *strerror(int error);
int strerror_r(int error, char *buffer, size_t size);
__END_DECLS
#endif
