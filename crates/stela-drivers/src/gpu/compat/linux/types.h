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
typedef u16 __be16;
typedef u32 __be32;
typedef u64 __be64;
typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;
typedef s8 __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;
/* Copyright Linux kernel contributors; from uapi/linux/types.h, without
 * sparse. */
#define __bitwise
/* Copyright Linux kernel contributors; from types.h. */
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
/* Linux x86-64 sizes and page offsets are 64-bit; UEFI's unsigned long is not. */
typedef size_t __kernel_size_t;
typedef u64 pgoff_t;
_Static_assert(sizeof(pgoff_t) == 8, "GPU page offsets must not truncate");
typedef s64 loff_t;
typedef ptrdiff_t ssize_t;
typedef unsigned short umode_t;
typedef u64 phys_addr_t;
typedef phys_addr_t resource_size_t;
typedef u64 dma_addr_t;
/* Copyright Linux kernel contributors; from types.h. */
struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};
#endif
