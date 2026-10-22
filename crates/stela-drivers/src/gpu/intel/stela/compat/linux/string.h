/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_STRING_H
#define STELA_LINUX_STRING_H
/* Freestanding Stela has no C library. The name keeps hosted <string.h>
 * declarations apart. Linux's lib/string.c strcmp(). */
static inline int stela_linux_strcmp(const char *a, const char *b)
{
	while (*a && *a == *b)
		++a, ++b;
	return (unsigned char)*a - (unsigned char)*b;
}
#define strcmp stela_linux_strcmp
#endif
