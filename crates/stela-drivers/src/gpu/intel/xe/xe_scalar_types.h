/* SPDX-License-Identifier: MIT */
#ifndef XE_SCALAR_TYPES_H
#define XE_SCALAR_TYPES_H
/* Fixed-width native definitions for retained pure types. No Linux services. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#define BIT(n) (UINT64_C(1) << (n))
#define GENMASK(h, l) ((UINT64_MAX << (l)) & (UINT64_MAX >> (63 - (h))))
#define GENMASK_ULL(h, l) GENMASK(h, l)
#define SZ_4M (UINT32_C(4) * 1024 * 1024)
#define const_ilog2(n) (31 - __builtin_clz((unsigned)(n)))
#ifdef static_assert
#undef static_assert
#endif
#define static_assert(c) _Static_assert((c), #c)
#define REG_BIT(n) (UINT32_C(1) << (n))
#define REG_GENMASK(h, l) ((UINT32_MAX << (l)) & (UINT32_MAX >> (31 - (h))))
#define REG_FIELD_GET(mask, value) (((u32)(value) & (u32)(mask)) >> __builtin_ctz((u32)(mask)))
#define REG_FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz((u32)(mask))) & (u32)(mask))
#endif
