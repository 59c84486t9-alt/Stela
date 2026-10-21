/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_I915_BITS_H
#define STELA_INTEL_I915_BITS_H

#include "command_bits.h"

/* Scalar definitions used by the retained i915 command header. */
#define GENMASK_ULL(high, low) ((UINT64_MAX << (low)) & (UINT64_MAX >> (63 - (high))))
static inline u64 stela_i915_sign_extend64(u64 value, unsigned int index)
{
    u64 sign = UINT64_C(1) << index;
    return ((value & ((sign - 1) | sign)) ^ sign) - sign;
}
#define sign_extend64(value, index) stela_i915_sign_extend64((value), (index))

#endif
