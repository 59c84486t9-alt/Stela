/* SPDX-License-Identifier: MIT */
#include "../i915_commands.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define __gen_address_type uint64_t
#define __gen_user_data void
static inline uint64_t combine_address(void *data, void *location,
                                       uint64_t address, uint32_t delta)
{
    (void)data; (void)location;
    return address + delta;
}
#define __gen_combine_address combine_address
#include "intel/genxml/gen_macros.h"
#include "intel/genxml/genX_pack.h"

int main(void)
{
    uint64_t random = UINT64_C(0x91551e1a);
    for (unsigned int i = 0; i < 10000; ++i) {
        random ^= random << 13; random ^= random >> 7; random ^= random << 17;
        bool secure = (i & 1) != 0;
#if GFX_VERx10 >= 80
        uint32_t encoding = STELA_INTEL_I915_BATCH_GEN8;
        uint64_t address = random & ((UINT64_C(1) << 48) - 8);
        bool no_preempt = (i & 2) != 0;
#elif GFX_VERx10 == 75
        uint32_t encoding = STELA_INTEL_I915_BATCH_HASWELL;
        uint64_t address = random & UINT32_C(0xfffffff8);
        bool no_preempt = false;
#else
        uint32_t encoding = STELA_INTEL_I915_BATCH_GEN6;
        uint64_t address = random & UINT32_C(0xfffffff8);
        bool no_preempt = false;
#endif
        uint32_t actual[8] = {0}, expected[8] = {0};
        struct stela_intel_commands commands = {actual, 8, 0, 48};
        assert(stela_intel_i915_batch_start(&commands, encoding, address, secure, no_preempt) == 0);
        struct GENX(MI_BATCH_BUFFER_START) batch = {
            GENX(MI_BATCH_BUFFER_START_header),
            .AddressSpaceIndicator = secure ? 0 : 1,
            .BatchBufferStartAddress = address,
#if GFX_VERx10 == 75
            .NonPrivileged = !secure,
#endif
        };
#if GFX_VERx10 >= 80
        struct GENX(MI_ARB_ON_OFF) arb = {GENX(MI_ARB_ON_OFF_header)};
        arb.ArbitrationEnable = !no_preempt;
        GENX(MI_ARB_ON_OFF_pack)(NULL, expected, &arb);
        GENX(MI_BATCH_BUFFER_START_pack)(NULL, expected + 1, &batch);
        if (!no_preempt) {
            arb.ArbitrationEnable = false;
            GENX(MI_ARB_ON_OFF_pack)(NULL, expected + 4, &arb);
        }
        assert(commands.used == (no_preempt ? 4u : 6u));
#else
        GENX(MI_BATCH_BUFFER_START_pack)(NULL, expected, &batch);
        assert(commands.used == 2);
#endif
        assert(memcmp(actual, expected, sizeof(actual)) == 0);
    }
    printf("Intel i915 batch vs Mesa GFX_VERx10=%d: 10000 streams passed\n", GFX_VERx10);
    return 0;
}
