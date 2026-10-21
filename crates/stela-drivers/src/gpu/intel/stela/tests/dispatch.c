/* SPDX-License-Identifier: MIT */
#include "../dispatch.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct stela_intel_gpgpu_dispatch valid(uint32_t generation)
{
    return (struct stela_intel_gpgpu_dispatch){generation, 19, 16, 2, 7, {3, 5, 7}};
}

static void exact_packets_and_generation_boundaries(void)
{
    const uint32_t generations[] = {70, 75, 80, 90, 110, 120};
    for (unsigned int i = 0; i < 6; ++i) {
        uint32_t out[20];
        for (unsigned int j = 0; j < 20; ++j) out[j] = 0xa5a5a5a5;
        struct stela_intel_commands commands = {out, 20, 1, 48};
        struct stela_intel_gpgpu_dispatch dispatch = valid(generations[i]);
        assert(stela_intel_gpgpu_dispatch(&commands, &dispatch) == 0);
        const uint32_t gen7[] = {
            0x71050009, 0, 0x40000001, 0, 3, 0, 5, 0, 7, 7, UINT32_MAX,
            0x70040000, 0,
        };
        const uint32_t gen8[] = {
            0x7105000d, 0, 0, 0, 0x40000001, 0, 0, 3, 0, 0, 5, 0, 7, 7, UINT32_MAX,
            0x70040000, 0,
        };
        size_t length = i < 2 ? 13 : 17;
        assert(commands.used == length + 1);
        assert(memcmp(out + 1, i < 2 ? gen7 : gen8, length * sizeof(uint32_t)) == 0);
        assert(out[0] == 0xa5a5a5a5 && out[commands.used] == 0xa5a5a5a5);
    }
}

static void invalid_inputs_leave_storage_unchanged(void)
{
    uint32_t out[20], before[20];
    for (unsigned int j = 0; j < 20; ++j) out[j] = 0xa5a5a5a5;
    memcpy(before, out, sizeof(out));
    struct stela_intel_commands commands = {out, 20, 1, 48};
    for (unsigned int fault = 0; fault < 11; ++fault) {
        struct stela_intel_gpgpu_dispatch dispatch = valid(80);
        switch (fault) {
        case 0: dispatch.simd_size = 4; break;
        case 1: dispatch.threads = 0; break;
        case 2: dispatch.threads = 65; break;
        case 3: dispatch.group_size = 16; break;
        case 4: dispatch.group_size = 33; break;
        case 5: dispatch.right_mask = 5; break;
        case 6: dispatch.right_mask = UINT32_MAX; break;
        case 7: dispatch.groups[0] = 0; break;
        case 8: dispatch.groups[1] = 0; break;
        case 9: dispatch.groups[2] = 0; break;
        case 10: dispatch.simd_size = UINT32_MAX; break;
        }
        assert(stela_intel_gpgpu_dispatch(&commands, &dispatch) == -22);
        assert(commands.used == 1 && memcmp(out, before, sizeof(out)) == 0);
    }
    struct stela_intel_gpgpu_dispatch dispatch = valid(125);
    assert(stela_intel_gpgpu_dispatch(&commands, &dispatch) == -95);
    dispatch = valid(80);
    for (size_t capacity = 1; capacity < 18; ++capacity) {
        commands.capacity = capacity;
        assert(stela_intel_gpgpu_dispatch(&commands, &dispatch) == -28);
        assert(commands.used == 1 && memcmp(out, before, sizeof(out)) == 0);
    }
    commands.capacity = 18;
    assert(stela_intel_gpgpu_dispatch(&commands, &dispatch) == 0 && commands.used == 18);
}

int main(void)
{
    exact_packets_and_generation_boundaries();
    invalid_inputs_leave_storage_unchanged();
    puts("Intel generated native GPGPU dispatch: 2 suites passed");
    return 0;
}
