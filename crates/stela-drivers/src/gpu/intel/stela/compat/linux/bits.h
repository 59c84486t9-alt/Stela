/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_BITS_H
#define STELA_LINUX_BITS_H
#include <linux/types.h>
/* Linux defines these with unsigned long, which is 64-bit on x86-64. */
#define BIT(n) (UINT64_C(1) << (n))
#define BIT_ULL(n) BIT(n)
#define GENMASK(h, l) ((UINT64_MAX << (l)) & (UINT64_MAX >> (63 - (h))))
#define GENMASK_ULL(h, l) GENMASK(h, l)
#define BIT_U8(n) ((u8)BIT(n))
#define BIT_U16(n) ((u16)BIT(n))
#define BIT_U32(n) ((u32)BIT(n))
#define BIT_U64(n) ((u64)BIT(n))
#define GENMASK_U8(h, l) ((u8)GENMASK(h, l))
#define GENMASK_U16(h, l) ((u16)GENMASK(h, l))
#define GENMASK_U32(h, l) ((u32)GENMASK(h, l))
#define GENMASK_U64(h, l) ((u64)GENMASK(h, l))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
#define upper_32_bits(n) ((u32)((u64)(n) >> 32))
#endif
