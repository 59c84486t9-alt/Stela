/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_GENERIC_INT_LL64_H
#define _UAPI_ASM_GENERIC_INT_LL64_H
/* Linux's fixed-width integers are the C library's, so Stela's interface
 * headers, its hosted tests and Linux code share one type system. Linux
 * spells 64 bits long long, which an LP64 <stdint.h> need not. */
#include <asm/bitsperlong.h>
#include <stdint.h>

typedef int8_t __s8;
typedef uint8_t __u8;
typedef int16_t __s16;
typedef uint16_t __u16;
typedef int32_t __s32;
typedef uint32_t __u32;
typedef int64_t __s64;
typedef uint64_t __u64;
#endif
