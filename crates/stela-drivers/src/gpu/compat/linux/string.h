/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_STRING_H
#define STELA_LINUX_STRING_H
#include <linux/types.h>
/* Freestanding Stela has no C library. The name keeps hosted <string.h>
 * declarations apart. Linux's lib/string.c strcmp(). */
static inline int stela_linux_strcmp(const char *a, const char *b)
{
	while (*a && *a == *b)
		++a, ++b;
	return (unsigned char)*a - (unsigned char)*b;
}
#define strcmp stela_linux_strcmp
/* The platform's compiler runtime supplies these, as the kernel does. The
 * parentheses keep a hosted C library's checking macros from expanding. */
void *(memcpy)(void *dest, const void *src, size_t count);
void *(memset)(void *dest, int c, size_t count);
int (memcmp)(const void *a, const void *b, size_t count);
#endif
