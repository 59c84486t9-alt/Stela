/* SPDX-License-Identifier: MIT */
/* See assert.h. The firmware image supplies memcpy. */
#ifndef STELA_FREESTANDING_STRING_H
#define STELA_FREESTANDING_STRING_H
#include <stddef.h>
void *memcpy(void *restrict, const void *restrict, size_t);
#endif
