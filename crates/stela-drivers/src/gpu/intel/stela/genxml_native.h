/* SPDX-License-Identifier: MIT */
/* Integer-only platform definitions for the original Mesa XML packers. */
#ifndef STELA_INTEL_GENXML_NATIVE_H
#define STELA_INTEL_GENXML_NATIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define UNUSED __attribute__((unused))
#define ASSERTED __attribute__((unused))
/* No libc assertion handler exists in the native backend. A violated internal
 * packer invariant stops execution rather than truncating a field silently.
 * Public packet inputs are validated before any output is modified.
 */
#define assert(condition) do { if (!(condition)) __builtin_trap(); } while (0)
#define util_bitpack_validate_value(value)

/* Same scalar limit operation as Mesa's util/macros.h, without pulling in
 * that hosted header's stdio/string/assert and unrelated platform facilities.
 */
static inline uint64_t
u_uintN_max(unsigned bit_size)
{
   assert(bit_size <= 64 && bit_size > 0);
   return UINT64_MAX >> (64 - bit_size);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wsign-conversion"
#include "util/bitpack_uint.h"
#pragma clang diagnostic pop

#define __gen_address_type uint64_t
#define __gen_user_data void
static inline uint64_t
stela_genxml_combine(void *data, void *location, uint64_t address, uint32_t delta)
{
    (void)data;
    (void)location;
    assert(address <= UINT64_MAX - delta);
    return address + delta;
}
#define __gen_combine_address stela_genxml_combine
#include "genX_helpers.h"

#endif
