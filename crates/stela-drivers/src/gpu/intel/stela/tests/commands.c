/* SPDX-License-Identifier: MIT */
#include "../commands.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void exact_command_stream(void)
{
    uint32_t words[16] = {0};
    struct stela_intel_commands commands = {words, 16, 0, 48};
    assert(stela_intel_batch_start(&commands, UINT64_C(0x123456780004), true) == 0);
    assert(stela_intel_store_qword(&commands, UINT64_C(0xabc00008), UINT64_C(0x1122334455667788)) ==
        0);
    assert(stela_intel_user_interrupt(&commands) == 0);
    assert(stela_intel_batch_end(&commands) == 0);
    static const uint32_t expected[] = {
        0x18800101, 0x56780004, 0x00001234,
        0x10200003, 0xabc00008, 0, 0x55667788, 0x11223344,
        0x01000000, 0x04000001, 0x02800000,
        0x05000000,
    };
    assert(commands.used == sizeof(expected) / sizeof(expected[0]));
    assert(memcmp(words, expected, sizeof(expected)) == 0);
    assert(words[commands.used] == 0);
}

static void writes_are_atomic_on_error(void)
{
    uint32_t words[16], before[16];
    for (unsigned int i = 0; i < 16; ++i) words[i] = 0xa5a5a5a5;
    memcpy(before, words, sizeof(words));
    struct stela_intel_commands commands = {words, 16, 0, 48};
    assert(stela_intel_batch_start(&commands, 1, true) == -22);
    assert(stela_intel_batch_start(&commands, UINT64_C(1) << 48, false) == -22);
    assert(stela_intel_store_qword(&commands, 4, 0) == -22);
    assert(stela_intel_store_qword(&commands, UINT64_MAX - 7, 0) == -22);
    assert(commands.used == 0 && memcmp(words, before, sizeof(words)) == 0);
    for (size_t free = 0; free < 5; ++free) {
        commands.used = 16 - free;
        assert(stela_intel_store_qword(&commands, 0, 0) == -28);
        assert(commands.used == 16 - free);
        assert(memcmp(words, before, sizeof(words)) == 0);
    }
    commands.used = 17;
    assert(stela_intel_batch_end(&commands) == -22);
    commands.used = 0; commands.capacity = SIZE_MAX;
    assert(stela_intel_batch_end(&commands) == -22);
    commands.capacity = 16; commands.address_bits = 64;
    assert(stela_intel_batch_start(&commands, 0, true) == -22);
    commands.address_bits = 48; commands.words = NULL;
    assert(stela_intel_batch_end(&commands) == -22);
    assert(stela_intel_batch_end(NULL) == -22);
    assert(memcmp(words, before, sizeof(words)) == 0);
}

static void full_width_addresses_and_final_slot(void)
{
    uint32_t words[8] = {0};
    struct stela_intel_commands commands = {words, 8, 0, 57};
    assert(stela_intel_batch_start(&commands, (UINT64_C(1) << 57) - 4, false) == 0);
    assert(words[0] == 0x18800001 && words[1] == 0xfffffffc && words[2] == 0x01ffffff);
    assert(stela_intel_store_qword(&commands, UINT64_C(1) << 48, UINT64_MAX) == -22);
    assert(commands.used == 3 && words[3] == 0);
    assert(stela_intel_store_qword(&commands, (UINT64_C(1) << 48) - 8, UINT64_MAX) == 0);
    assert(commands.used == 8 && words[3] == 0x10200003);
    assert(words[4] == 0xfffffff8 && words[5] == 0x0000ffff);
    assert(words[6] == UINT32_MAX && words[7] == UINT32_MAX);
    assert(stela_intel_batch_end(&commands) == -28 && commands.used == 8);
}

int main(void)
{
    exact_command_stream();
    writes_are_atomic_on_error();
    full_width_addresses_and_final_slot();
    puts("Intel native Xe MI command writer: 3 suites passed");
    return 0;
}
