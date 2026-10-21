/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_COMMAND_BITS_H
#define STELA_INTEL_COMMAND_BITS_H

#include <stdint.h>

/* Scalar operations used by the existing Intel MI instruction definitions.
 * Fixed-width values avoid the LP64/LLP64 difference in UEFI's C ABI.
 */
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(n) (UINT32_C(1) << (n))
#define REG_BIT(n) BIT(n)
#define GENMASK(high, low) ((UINT32_MAX << (low)) & (UINT32_MAX >> (31 - (high))))
#define REG_GENMASK(high, low) GENMASK(high, low)
#define REG_FIELD_PREP(mask, value) \
    (((uint32_t)(value) << __builtin_ctz((uint32_t)(mask))) & (uint32_t)(mask))
#define lower_32_bits(value) ((uint32_t)(uint64_t)(value))
#define upper_32_bits(value) ((uint32_t)((uint64_t)(value) >> 32))

#endif
