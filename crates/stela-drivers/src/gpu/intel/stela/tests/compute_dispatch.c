/* SPDX-License-Identifier: MIT */
#include "../compute_dispatch.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct stela_intel_compute_dispatch fixture(uint32_t generation)
{
    return (struct stela_intel_compute_dispatch) {
        .gfx_verx10 = generation, .local_size = {7, 3, 2}, .simd_size = 16,
        .threads = 3, .right_mask = 0x3ff, .groups = {19, 23, 29},
        .kernel_offset = 0xffffffc0, .binding_table_offset = 0x1fffe0,
        .binding_table_entry_count = 31, .sampler_offset = 0xffffffe0,
        .sampler_count = 4, .uses_sampler = 1,
        .preferred_slm_encoding = generation == 125 ? 8 : 0,
        .thread_group_dispatch_size = 3, .register_blocks = generation >= 300 ? 7 : 0,
        .generate_local_id = 0, .walk_order = 2, .post_sync_mocs = 127,
    };
}

static void invalid(const struct stela_intel_compute_dispatch *dispatch, int status)
{
    uint32_t words[44], before[44];
    memset(words, 0xa5, sizeof(words));
    memcpy(before, words, sizeof(words));
    struct stela_intel_commands commands = {words, 44, 1, 48};
    assert(stela_intel_compute_dispatch(&commands, dispatch) == status);
    assert(commands.used == 1 && !memcmp(words, before, sizeof(words)));
}

static void exercise(uint32_t generation)
{
    struct stela_intel_compute_dispatch dispatch = fixture(generation);
    uint32_t words[44];
    memset(words, 0xa5, sizeof(words));
    struct stela_intel_commands commands = {words, 44, 1, 57};
    assert(stela_intel_compute_dispatch(&commands, &dispatch) == 0);
    size_t count = generation == 125 ? 39 : 40;
    assert(commands.used == count + 1 && words[0] == 0xa5a5a5a5 && words[count + 1] == 0xa5a5a5a5);
    /* Independently inspect XML field positions, not another native helper. */
    assert((words[1] & 0xff) == count - 2);
    assert(words[7] == (6u | (2u << 10) | (1u << 20)));
    assert(words[8] == 19 && words[9] == 23 && words[10] == 29);
    assert(words[generation == 125 ? 19 : 20] == dispatch.kernel_offset);
    assert(words[generation == 125 ? 27 : 28] == 127u << 4);

    uint32_t before[44];
    memcpy(before, words, sizeof(words));
    commands.used = 44 - count + 1;
    size_t used = commands.used;
    assert(stela_intel_compute_dispatch(&commands, &dispatch) == -28);
    assert(commands.used == used && !memcmp(words, before, sizeof(words)));
    commands.used = 45;
    assert(stela_intel_compute_dispatch(&commands, &dispatch) == -22 && commands.used == 45);
    commands.used = 0;
    commands.address_bits = 32;
    assert(stela_intel_compute_dispatch(&commands, &dispatch) == -22);

    const struct {size_t offset; uint32_t value; int status;
    } cases[] = {
#define BAD(field, value) {offsetof(struct stela_intel_compute_dispatch, field), value, -22}
        BAD(local_size[0], 0),
        BAD(local_size[1], 1025),
        BAD(local_size[2], 1024),
        BAD(groups[0], 0),
        BAD(groups[1], 0),
        BAD(groups[2], 0),
        BAD(simd_size, 0),
        BAD(simd_size, 64),
        BAD(threads, 0),
        BAD(threads, 1024),
        BAD(right_mask, 0),
        BAD(right_mask, 0x1ff),
        BAD(kernel_offset, 63),
        BAD(binding_table_offset, 0x200000),
        BAD(binding_table_offset, 1),
        BAD(binding_table_entry_count, 32),
        BAD(sampler_offset, 1),
        BAD(sampler_count, 5),
        BAD(uses_sampler, 0),
        BAD(uses_sampler, 2),
        BAD(slm_encoding, 15),
        BAD(preferred_slm_encoding, 16),
        BAD(barrier_encoding, 8),
        BAD(thread_group_dispatch_size, 4),
        BAD(register_blocks, 6),
        BAD(register_blocks, 8),
        BAD(generate_local_id, 2),
        BAD(generate_local_id, 7),
        BAD(generate_local_id, 8),
        BAD(walk_order, 6),
        BAD(post_sync_mocs, 0),
        BAD(post_sync_mocs, 128),
        {offsetof(struct stela_intel_compute_dispatch, push_bytes), 32, -95},
        {offsetof(struct stela_intel_compute_dispatch, gfx_verx10), 120, -95},
#undef BAD
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct stela_intel_compute_dispatch changed = dispatch;
        memcpy((char *)&changed + cases[i].offset, &cases[i].value, sizeof(uint32_t));
        invalid(&changed, cases[i].status);
    }
    struct stela_intel_compute_dispatch changed = dispatch;
    if (generation == 125) {
        changed.preferred_slm_encoding = 7;
        invalid(&changed, -22);
        changed = dispatch;
        changed.slm_encoding = 8;
        invalid(&changed, -22);
    } else {
        changed.simd_size = 8;
        invalid(&changed, -22);
        changed = dispatch;
        changed.preferred_slm_encoding = 11;
        invalid(&changed, -22);
    }
    if (generation < 300) {
        changed = dispatch;
        changed.register_blocks = 1;
        invalid(&changed, -22);
    }
    /* Exact 1024-lane product/full mask boundary, then one-lane overflow. */
    changed = dispatch;
    changed.local_size[0] = 1024; changed.local_size[1] = changed.local_size[2] = 1;
    changed.simd_size = 32; changed.threads = 32; changed.right_mask = UINT32_MAX;
    commands = (struct stela_intel_commands) {words, 44, 0, 48};
    assert(stela_intel_compute_dispatch(&commands, &changed) == 0);
    changed.local_size[1] = 2;
    invalid(&changed, -22);
    changed = dispatch;
    changed.local_size[0] = 8; changed.local_size[1] = 4;
    changed.threads = 4; changed.right_mask = 0xffff; changed.generate_local_id = 7;
    commands = (struct stela_intel_commands) {words, 44, 0, 48};
    assert(stela_intel_compute_dispatch(&commands, &changed) == 0);
    changed.generate_local_id = 3;
    invalid(&changed, -22);
    /* Metadata may overlap output; snapshot must precede the first store. */
    memcpy(words, &dispatch, sizeof(dispatch));
    commands = (struct stela_intel_commands) {words, 44, 0, 48};
    assert(stela_intel_compute_dispatch(&commands, (const void *)words) == 0);
}

int main(void)
{
    exercise(125); exercise(200); exercise(300); exercise(350);
    assert(stela_intel_compute_dispatch(NULL, NULL) == -22);
    puts("Native COMPUTE_WALKER bounds/fields/atomic errors: 4 generations passed");
    return 0;
}
