/* SPDX-License-Identifier: MIT */
#include "../i915_commands.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void generation_and_security_matrix(void)
{
    const uint32_t encodings[] = {4, 6, 75, 8};
    const uint32_t headers[] = {0x18800180, 0x18800100, 0x18802100, 0x18800101};
    for (unsigned int i = 0; i < 4; ++i) {
        for (unsigned int secure = 0; secure < 2; ++secure) {
            for (unsigned int no_preempt = 0; no_preempt <= (i == 3 ? 1u : 0u); ++no_preempt) {
                uint32_t words[8] = {0};
                struct stela_intel_commands commands = {words, 8, 0, 48};
                uint64_t address = i == 3 ? UINT64_C(0x123456789000) : 0x12345000;
                assert(stela_intel_i915_batch_start(&commands, encodings[i], address,
                                                    secure != 0, no_preempt != 0) == 0);
                if (i < 3) {
                    assert(commands.used == 2);
                    assert(words[0] ==
                           (secure ? (i == 0 ? 0x18800080u : 0x18800000u) : headers[i]));
                    assert(words[1] == (uint32_t)address);
                } else {
                    assert(commands.used == (no_preempt ? 4u : 6u));
                    assert(words[0] == (no_preempt ? 0x04000000u : 0x04000001u));
                    assert(words[1] == (secure ? 0x18800001u : 0x18800101u));
                    assert(words[2] == 0x56789000 && words[3] == 0x1234);
                    if (!no_preempt) assert(words[4] == 0x04000000 && words[5] == 0);
                }
                assert(words[commands.used] == 0);
            }
        }
    }
}

static void atomic_errors_and_limits(void)
{
    uint32_t words[8], before[8];
    for (unsigned int i = 0; i < 8; ++i) words[i] = 0xa5a5a5a5;
    memcpy(before, words, sizeof(words));
    struct stela_intel_commands commands = {words, 8, 1, 57};
    assert(stela_intel_i915_batch_start(&commands, 2, 0, false, false) == -22);
    assert(stela_intel_i915_batch_start(&commands, 12, 0, false, false) == -22);
    assert(stela_intel_i915_batch_start(&commands, 4, 0, false, true) == -22);
    assert(stela_intel_i915_batch_start(&commands, 6, UINT64_C(1) << 32, false, false) == -22);
    assert(stela_intel_i915_batch_start(&commands, 8, UINT64_C(1) << 48, false, false) == -22);
    assert(stela_intel_i915_batch_start(&commands, 8, 4, false, false) == -22);
    for (size_t free = 0; free < 6; ++free) {
        commands.used = 8 - free;
        assert(stela_intel_i915_batch_start(&commands, 8, 0, false, false) == -28);
        assert(commands.used == 8 - free);
    }
    assert(memcmp(before, words, sizeof(words)) == 0);
    commands.used = 6;
    assert(stela_intel_i915_batch_start(&commands, 75, UINT64_C(0xfffffff8), false, false) == 0);
    assert(commands.used == 8 && words[7] == 0xfffffff8);
}

int main(void)
{
    generation_and_security_matrix();
    atomic_errors_and_limits();
    puts("Intel native i915 batch writer: 2 suites passed");
    return 0;
}
