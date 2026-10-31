/* SPDX-License-Identifier: MIT */
/* The kernel's fixed-width names, for its UAPI headers. */
#ifndef STELA_LIBC_LINUX_TYPES_H
#define STELA_LIBC_LINUX_TYPES_H
#include <stddef.h>
#include <stdint.h>
typedef int8_t __s8;
typedef uint8_t __u8;
typedef int16_t __s16;
typedef uint16_t __u16;
typedef int32_t __s32;
typedef uint32_t __u32;
typedef int64_t __s64;
typedef uint64_t __u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;
typedef unsigned int __poll_t;
typedef size_t __kernel_size_t;
#define __user
#endif
