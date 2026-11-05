/* SPDX-License-Identifier: MIT */
#ifndef STELA_STDINT_H
#define STELA_STDINT_H
/* The <stdint.h> Stela's own headers use in its Linux environment, which has
 * no C library: Linux's fixed-width and pointer-sized integers, which keep the
 * C library's LP64 sizes and signedness, with limits and constants spelled as
 * Linux spells them. */
#include <linux/limits.h>
#include <linux/types.h>

#define INT8_MIN S8_MIN
#define INT8_MAX S8_MAX
#define INT16_MIN S16_MIN
#define INT16_MAX S16_MAX
#define INT32_MIN S32_MIN
#define INT32_MAX S32_MAX
#define INT64_MIN S64_MIN
#define INT64_MAX S64_MAX
#define UINT8_MAX U8_MAX
#define UINT16_MAX U16_MAX
#define UINT32_MAX U32_MAX
#define UINT64_MAX U64_MAX
#define PTRDIFF_MIN (-PTRDIFF_MAX - 1)
#define PTRDIFF_MAX ((ptrdiff_t)(SIZE_MAX >> 1))

#define INT8_C(value) value
#define INT16_C(value) value
#define INT32_C(value) value
#define INT64_C(value) value##LL
#define UINT8_C(value) value
#define UINT16_C(value) value
#define UINT32_C(value) value##U
#define UINT64_C(value) value##ULL
#endif
