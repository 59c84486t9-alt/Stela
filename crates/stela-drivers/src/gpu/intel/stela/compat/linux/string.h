/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_STRING_H
#define STELA_LINUX_STRING_H
/* Freestanding Stela has no C library. Each translation unit that compares
 * strings defines this; the name keeps hosted <string.h> declarations apart. */
#define strcmp stela_linux_strcmp
static int stela_linux_strcmp(const char *a, const char *b);
#endif
