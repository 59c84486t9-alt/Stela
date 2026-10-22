/* SPDX-License-Identifier: GPL-2.0-only */
#include "../pt_walk.h"
#include <stela/test.h>
#include <linux/string.h>

#define ENTRIES 512U
#define EVENT_LIMIT 2048U
#define NO_LEVEL 99U

struct node {
    struct xe_ptw base;
    struct xe_ptw *children[ENTRIES];
    struct xe_ptw *staging[ENTRIES];
};

struct event {
    const struct xe_ptw *parent;
    pgoff_t offset;
    unsigned int level;
    u64 addr, end;
    bool post;
};

struct fixture {
    struct xe_pt_walk walk;
    struct event events[EVENT_LIMIT];
    size_t count;
    unsigned int fail_entry_level, fail_post_level, skip_level;
    bool retry, retried;
    struct xe_ptw *new_child;
};

static const u64 normal[] = {12, 21, 30, 39, 48};
static const u64 compact[] = {16, 21, 30, 39, 48};

static void record(struct fixture *f, struct xe_ptw *parent, pgoff_t offset,
                   unsigned int level, u64 addr, u64 end, bool post)
{
    assert(f->count < EVENT_LIMIT);
    assert(addr < end);
    f->events[f->count++] = (struct event){parent, offset, level, addr, end, post};
}

static int entry(struct xe_ptw *parent, pgoff_t offset, unsigned int level,
                 u64 addr, u64 end, struct xe_ptw **child,
                 enum page_walk_action *action, struct xe_pt_walk *walk)
{
    struct fixture *f = (struct fixture *)walk;
    record(f, parent, offset, level, addr, end, false);
    if (f->fail_entry_level == level)
        return -5;
    if (f->retry && !f->retried) {
        f->retried = true;
        *action = ACTION_AGAIN;
    } else if (f->skip_level == level) {
        *action = ACTION_CONTINUE;
    } else if (level == 1 && !*child && f->new_child) {
        *child = f->new_child;
    }
    return 0;
}

static int post(struct xe_ptw *parent, pgoff_t offset, unsigned int level,
                u64 addr, u64 end, struct xe_ptw **child,
                enum page_walk_action *action, struct xe_pt_walk *walk)
{
    struct fixture *f = (struct fixture *)walk;
    (void)child;
    (void)action;
    record(f, parent, offset, level, addr, end, true);
    return f->fail_post_level == level ? -71 : 0;
}

static const struct xe_pt_walk_ops ops = {entry, post};

static void reset(struct fixture *f, unsigned int max_level)
{
    memset(f, 0, sizeof(*f));
    f->walk = (struct xe_pt_walk){.ops = &ops, .shifts = normal, .max_level = max_level};
    f->fail_entry_level = f->fail_post_level = f->skip_level = NO_LEVEL;
}

static void node_init(struct node *n)
{
    memset(n, 0, sizeof(*n));
    n->base.children = n->children;
    n->base.staging = n->staging;
}

static void normal_order_and_crossing(void)
{
    struct node root, mid, leaf0, leaf1;
    struct fixture f;
    node_init(&root); node_init(&mid); node_init(&leaf0); node_init(&leaf1);
    root.children[0] = &mid.base;
    mid.children[0] = &leaf0.base;
    mid.children[1] = &leaf1.base;
    reset(&f, 2);
    assert(stela_intel_pt_walk(&root.base, 2, 0x1ff000, 0x202000, &f.walk, false) == 0);
    assert(f.count == 9);
    assert(f.events[0].level == 2 && !f.events[0].post);
    assert(f.events[2].parent == &leaf0.base && f.events[2].offset == 511);
    assert(f.events[3].level == 1 && f.events[3].post);
    assert(f.events[5].parent == &leaf1.base && f.events[5].offset == 0);
    assert(f.events[6].offset == 1 && f.events[6].end == 0x202000);
    assert(f.events[8].level == 2 && f.events[8].post);
}

static void callback_control_and_errors(void)
{
    struct node root, leaf;
    struct fixture f;
    node_init(&root); node_init(&leaf);
    root.children[0] = &leaf.base;
    reset(&f, 1);
    f.skip_level = 1;
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, &f.walk, false) == 0);
    assert(f.count == 1);

    reset(&f, 1);
    f.retry = true;
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, &f.walk, false) == 0);
    assert(f.retried && f.count == 4);
    assert(f.events[0].parent == f.events[1].parent && f.events[0].offset == f.events[1].offset);

    reset(&f, 1);
    f.fail_entry_level = 0;
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, &f.walk, false) == -5);
    assert(f.count == 2 && !f.events[1].post);

    reset(&f, 1);
    f.fail_post_level = 1;
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, &f.walk, false) == -71);
    assert(f.count == 3 && f.events[2].post);

    root.children[0] = NULL;
    reset(&f, 1);
    f.new_child = &leaf.base;
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, &f.walk, false) == 0);
    assert(f.count == 3 && f.events[1].parent == &leaf.base);
    assert(root.children[0] == NULL); /* callback owns publishing new children */
}

static void staging_and_shared_unbind(void)
{
    struct node root, live, staged, leaf2;
    struct fixture f;
    node_init(&root); node_init(&live); node_init(&staged); node_init(&leaf2);
    root.children[0] = &live.base;
    root.staging[0] = &staged.base;
    reset(&f, 1);
    f.walk.staging = true;
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, &f.walk, false) == 0);
    assert(f.events[1].parent == &staged.base);

    root.children[2] = &leaf2.base;
    reset(&f, 1);
    assert(stela_intel_pt_walk(&root.base, 1, 4096, 0x401000, &f.walk, true) == 0);
    assert(f.walk.shared_pt_mode && f.count == 6);
    assert(f.events[0].level == 2 && f.events[5].level == 2 && f.events[5].post);
    assert(f.events[1].offset == 0 && f.events[3].offset == 2);
    for (size_t i = 0; i < f.count; ++i)
        assert(f.events[i].level != 0); /* fully covered leaf entries are private */
}

static void ranges_match_independent_page_partition(void)
{
    struct node root, leaf;
    struct fixture f;
    node_init(&root); node_init(&leaf);
    root.children[0] = &leaf.base;
    uint32_t random = 0x51e1a;
    for (unsigned int page_mode = 0; page_mode < 2; ++page_mode) {
        u64 page_size = page_mode ? 65536 : 4096;
        for (unsigned int n = 0; n < 500; ++n) {
            random = random * 1664525U + 1013904223U;
            u64 addr = random % 0x1f0000U;
            random = random * 1664525U + 1013904223U;
            u64 end = addr + 1 + random % 65536U;
            reset(&f, 1);
            f.walk.shifts = page_mode ? compact : normal;
            assert(stela_intel_pt_walk(&root.base, 1, addr, end, &f.walk, false) == 0);
            u64 cursor = addr;
            size_t count = 0;
            for (size_t i = 0; i < f.count; ++i) {
                const struct event *event = &f.events[i];
                if (event->post || event->level)
                    continue;
                u64 next = ((cursor / page_size) + 1) * page_size;
                if (next > end) next = end;
                assert(event->addr == cursor && event->end == next);
                assert(event->offset == cursor / page_size);
                cursor = next;
                ++count;
            }
            assert(count && cursor == end);
        }
    }
}

static void invalid_inputs_do_not_call_the_walker(void)
{
    struct node root;
    struct fixture f;
    node_init(&root); reset(&f, 1);
    assert(stela_intel_pt_walk(NULL, 1, 0, 4096, &f.walk, false) == -22);
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, NULL, false) == -22);
    assert(stela_intel_pt_walk(&root.base, 2, 0, 4096, &f.walk, false) == -22);
    assert(stela_intel_pt_walk(&root.base, 1, 4096, 0, &f.walk, false) == -22);
    assert(stela_intel_pt_walk(&root.base, 1, 0, (1ULL << 30) + 1, &f.walk, false) == -22);
    assert(stela_intel_pt_walk(&root.base, 0, 0x1ff000, 0x201000, &f.walk, false) == -22);
    assert(stela_intel_pt_walk(&root.base, 1, 0, 0, &f.walk, false) == 0);
    static const u64 malformed[] = {12, 64};
    f.walk.shifts = malformed;
    assert(stela_intel_pt_walk(&root.base, 1, 0, 4096, &f.walk, false) == -22);
    assert(f.count == 0);
}

int main(void)
{
    normal_order_and_crossing();
    callback_control_and_errors();
    staging_and_shared_unbind();
    ranges_match_independent_page_partition();
    invalid_inputs_do_not_call_the_walker();
    printf("Intel native Xe page walker: 5 suites / 1000 range partitions passed\n");
    return 0;
}
