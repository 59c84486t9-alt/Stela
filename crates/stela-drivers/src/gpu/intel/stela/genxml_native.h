/* SPDX-License-Identifier: MIT */
/* The address type the original Mesa XML packers combine: a plain GPU address
 * with no relocation, as the native encoders emit it.
 */
#ifndef STELA_INTEL_GENXML_NATIVE_H
#define STELA_INTEL_GENXML_NATIVE_H

#include <assert.h>
#include <stdint.h>

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

#endif
