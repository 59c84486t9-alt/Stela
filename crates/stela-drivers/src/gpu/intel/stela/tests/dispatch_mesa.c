/* SPDX-License-Identifier: MIT */
#include "../dispatch.h"
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

static uint32_t random_u32(uint32_t *value)
{
    *value ^= *value << 13; *value ^= *value >> 17; *value ^= *value << 5;
    return *value;
}

int main(void)
{
    uint32_t random = 0x51e1a;
    for (unsigned int i = 0; i < 10000; ++i) {
        uint32_t simd = 8u << (random_u32(&random) % 3);
        uint32_t threads = 1 + random_u32(&random) % 64;
        uint32_t active = 1 + random_u32(&random) % simd;
        struct stela_intel_gpgpu_dispatch dispatch = {
            .gfx_verx10 = GFX_VERx10, .group_size = (threads - 1) * simd + active,
            .simd_size = simd, .threads = threads,
            .right_mask = UINT32_MAX >> (32 - active),
            .groups = {random_u32(&random) | 1, random_u32(&random) | 1, random_u32(&random) | 1},
        };
        uint32_t actual[20] = {0}, expected[20] = {0};
        struct stela_intel_commands commands = {actual, 20, 0, 48};
        assert(stela_intel_gpgpu_dispatch(&commands, &dispatch) == 0);
        /* Original hosted packet generation and Iris direct-dispatch policy,
         * compiled separately from the native-prologue generation objects. */
        struct GENX(GPGPU_WALKER) walker = {
            GENX(GPGPU_WALKER_header),
            .SIMDSize = simd / 16, .ThreadWidthCounterMaximum = threads - 1,
            .ThreadGroupIDXDimension = dispatch.groups[0],
            .ThreadGroupIDYDimension = dispatch.groups[1],
            .ThreadGroupIDZDimension = dispatch.groups[2],
            .RightExecutionMask = dispatch.right_mask, .BottomExecutionMask = UINT32_MAX,
        };
        struct GENX(MEDIA_STATE_FLUSH) flush = {GENX(MEDIA_STATE_FLUSH_header)};
        GENX(GPGPU_WALKER_pack)(NULL, expected, &walker);
        GENX(MEDIA_STATE_FLUSH_pack)(NULL, expected + GENX(GPGPU_WALKER_length), &flush);
        assert(commands.used == GENX(GPGPU_WALKER_length) + GENX(MEDIA_STATE_FLUSH_length));
        assert(memcmp(actual, expected, sizeof(actual)) == 0);
    }
    printf("Native GPGPU dispatch vs hosted Mesa GFX_VERx10=%d: 10000 streams passed\n", GFX_VERx10);
    return 0;
}
