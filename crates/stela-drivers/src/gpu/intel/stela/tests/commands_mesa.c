/* SPDX-License-Identifier: MIT */
#include "../commands.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Test addresses are already assigned GPU VAs, so no relocation is needed. */
#define __gen_address_type uint64_t
#define __gen_user_data void
static inline uint64_t combine_address(void *data, void *location,
                                       uint64_t address, uint32_t delta)
{
    (void)data;
    (void)location;
    return address + delta;
}
#define __gen_combine_address combine_address
#include "intel/genxml/gen_macros.h"
#include "intel/genxml/genX_pack.h"

static uint64_t random_u64(uint64_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

int main(void)
{
    uint64_t state = UINT64_C(0x51e1a1c0ffee);
    for (unsigned int i = 0; i < 10000; ++i) {
        uint64_t batch = random_u64(&state) & ((UINT64_C(1) << 57) - 4);
        uint64_t address = random_u64(&state) & ((UINT64_C(1) << 48) - 8);
        uint64_t value = random_u64(&state);
        bool ppgtt = (i & 1) != 0;
        uint32_t actual[12] = {0}, expected[12] = {0};
        struct stela_intel_commands commands = {actual, 12, 0, 57};
        assert(stela_intel_batch_start(&commands, batch, ppgtt) == 0);
        assert(stela_intel_store_qword(&commands, address, value) == 0);
        assert(stela_intel_user_interrupt(&commands) == 0);
        assert(stela_intel_batch_end(&commands) == 0);

        struct GENX(MI_BATCH_BUFFER_START) start = {
            GENX(MI_BATCH_BUFFER_START_header),
            .AddressSpaceIndicator = ppgtt ? 1 : 0,
            .BatchBufferStartAddress = batch,
        };
        GENX(MI_BATCH_BUFFER_START_pack)(NULL, expected, &start);
        struct GENX(MI_STORE_DATA_IMM) store = {
            GENX(MI_STORE_DATA_IMM_header),
            .StoreQword = true, .Address = address, .ImmediateData = value,
        };
        store.DWordLength = 3;
        GENX(MI_STORE_DATA_IMM_pack)(NULL, expected + 3, &store);
        struct GENX(MI_USER_INTERRUPT) interrupt = {GENX(MI_USER_INTERRUPT_header)};
        GENX(MI_USER_INTERRUPT_pack)(NULL, expected + 8, &interrupt);
        struct GENX(MI_ARB_ON_OFF) arbitration = {GENX(MI_ARB_ON_OFF_header)};
        GENX(MI_ARB_ON_OFF_pack)(NULL, expected + 9, &arbitration);
        struct GENX(MI_ARB_CHECK) check = {GENX(MI_ARB_CHECK_header)};
        GENX(MI_ARB_CHECK_pack)(NULL, expected + 10, &check);
        struct GENX(MI_BATCH_BUFFER_END) end = {GENX(MI_BATCH_BUFFER_END_header)};
        GENX(MI_BATCH_BUFFER_END_pack)(NULL, expected + 11, &end);
        assert(commands.used == 12);
        assert(memcmp(actual, expected, sizeof(actual)) == 0);
    }
    printf("Intel MI packets vs Mesa GFX_VERx10=%d: 10000 streams passed\n", GFX_VERx10);
    return 0;
}
