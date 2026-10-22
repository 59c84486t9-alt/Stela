/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_TYPES_H
#define STELA_LINUX_TYPES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef u16 __le16;
typedef u32 __le32;
typedef u64 __le64;
typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;
typedef s8 __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;
/* Linux x86-64 sizes and page offsets are 64-bit; UEFI's unsigned long is not. */
typedef size_t __kernel_size_t;
typedef u64 pgoff_t;
_Static_assert(sizeof(pgoff_t) == 8, "GPU page offsets must not truncate");
#endif
