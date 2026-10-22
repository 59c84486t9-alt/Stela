/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "rbtree_bind.h"
#include "rbtree-body.inc"

#define COUNT 257
struct item { unsigned key, maximum; struct rb_node node; };
static unsigned value(struct item *item) { return item->key; }
RB_DECLARE_CALLBACKS_MAX(static, maxima, struct item, node, unsigned, maximum, value)
static uint64_t checksum = UINT64_C(1469598103934665603);
static size_t checks;
static void record(unsigned v) { checksum = (checksum ^ v) * UINT64_C(1099511628211); }
static unsigned verify_node(struct rb_node *node, struct rb_node *parent, int lo, int hi,
                            bool augmented, unsigned *count, unsigned *maximum)
{
    if (!node) { *maximum = 0; return 1; }
    struct item *item = rb_entry(node, struct item, node);
    assert(rb_parent(node) == parent);
    assert((int)item->key > lo && (int)item->key < hi);
    assert(!(node->__rb_parent_color & 2));
    if (rb_is_red(node)) {
        assert(!node->rb_left || rb_is_black(node->rb_left));
        assert(!node->rb_right || rb_is_black(node->rb_right));
    }
    unsigned left, right;
    unsigned lb = verify_node(node->rb_left, node, lo, (int)item->key, augmented, count, &left);
    unsigned rb = verify_node(node->rb_right, node, (int)item->key, hi, augmented, count, &right);
    assert(lb == rb);
    *maximum = item->key;
    if (left > *maximum) *maximum = left;
    if (right > *maximum) *maximum = right;
    if (augmented) assert(item->maximum == *maximum);
    ++*count;
    record(item->key * 2 + (unsigned)rb_color(node));
    return lb + (unsigned)rb_is_black(node);
}
static void verify(struct rb_root *root, const bool *present, unsigned expected, bool augmented)
{
    unsigned count = 0, maximum;
    if (root->rb_node) assert(rb_is_black(root->rb_node));
    verify_node(root->rb_node, NULL, -1, COUNT, augmented, &count, &maximum);
    assert(count == expected);
    struct rb_node *n = rb_first(root), *prev = NULL;
    for (unsigned i = 0; i < COUNT; ++i) {
        if (!present[i]) continue;
        assert(n && rb_entry(n, struct item, node)->key == i);
        assert(rb_prev(n) == prev);
        prev = n;
        n = rb_next(n);
    }
    assert(!n && prev == rb_last(root));
    unsigned post = 0;
    bool visited[COUNT] = {false};
    for (n = rb_first_postorder(root); n; n = rb_next_postorder(n)) {
        assert(++post <= expected);
        unsigned key = rb_entry(n, struct item, node)->key;
        assert(present[key] && !visited[key]);
        if (n->rb_left) assert(visited[rb_entry(n->rb_left, struct item, node)->key]);
        if (n->rb_right) assert(visited[rb_entry(n->rb_right, struct item, node)->key]);
        visited[key] = true;
        struct rb_node *p = rb_parent(n);
        if (p) assert(p->rb_left == n || p->rb_right == n);
    }
    assert(post == expected);
    ++checks;
}
static void insert(struct rb_root *root, struct item *item, bool augmented)
{
    struct rb_node **link = &root->rb_node, *parent = NULL;
    while (*link) {
        parent = *link;
        struct item *other = rb_entry(parent, struct item, node);
        assert(item->key != other->key);
        link = item->key < other->key ? &parent->rb_left : &parent->rb_right;
    }
    item->maximum = item->key;
    rb_link_node(&item->node, parent, link);
    if (augmented) {
        maxima.propagate(parent, NULL);
        rb_insert_augmented(&item->node, root, &maxima);
    } else rb_insert_color(&item->node, root);
}
static uint32_t random_word(uint32_t *s) { *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5; return *s; }
static void shuffle(unsigned *order, uint32_t *seed)
{
    for (unsigned i = 0; i < COUNT; ++i) order[i] = i;
    for (unsigned i = COUNT - 1; i; --i) {
        unsigned j = random_word(seed) % (i + 1), t = order[i]; order[i] = order[j]; order[j] = t;
    }
}
int main(void)
{
    struct item *items = calloc(COUNT + 1, sizeof(*items));
    assert(items && (__UINTPTR_TYPE__)items > UINT32_MAX);
    fprintf(stderr, "actual owned allocation=%p last_node=%p parent_word_bytes=%zu\n",
            (void *)items, (void *)&items[COUNT].node, sizeof(items[0].node.__rb_parent_color));
    struct rb_node *p = &items[0].node, *n = &items[1].node, *link = NULL;
    for (unsigned tag = 0; tag < 4; ++tag) {
        n->__rb_parent_color = (__UINTPTR_TYPE__)p | tag;
        assert(rb_parent(n) == p && __rb_parent(n->__rb_parent_color) == p);
    }
    for (unsigned color = 0; color < 2; ++color) {
        rb_set_parent_color(n, p, (int)color);
        assert(rb_parent(n) == p && rb_color(n) == color);
        rb_set_parent(n, &items[2].node);
        assert(rb_parent(n) == &items[2].node && rb_color(n) == color);
    }
    RB_CLEAR_NODE(n); assert(RB_EMPTY_NODE(n) && !rb_next(n) && !rb_prev(n));
    rb_link_node(n, p, &link);
    assert(link == n && rb_parent(n) == p && !n->rb_left && !n->rb_right);
    for (unsigned mode = 0; mode < 2; ++mode) {
        for (unsigned round = 1; round <= 32; ++round) {
            struct rb_root root = RB_ROOT;
            bool present[COUNT] = {false};
            unsigned order[COUNT], count = 0;
            uint32_t seed = round;
            shuffle(order, &seed);
            for (unsigned i = 0; i < COUNT; ++i) {
                items[i].key = i;
                RB_CLEAR_NODE(&items[i].node);
            }
            for (unsigned i = 0; i < COUNT; ++i) {
                unsigned k = order[i];
                insert(&root, &items[k], mode != 0);
                present[k] = true;
                verify(&root, present, ++count, mode != 0);
            }
            /* Replace a real high-address node with a distinct owned node. */
            unsigned k = round % COUNT;
            struct item *replacement = &items[COUNT];
            replacement->key = k;
            replacement->maximum = items[k].maximum;
            rb_replace_node(&items[k].node, &replacement->node, &root);
            verify(&root, present, count, mode != 0);
            rb_replace_node(&replacement->node, &items[k].node, &root);
            verify(&root, present, count, mode != 0);
            shuffle(order, &seed);
            for (unsigned i = 0; i < COUNT; ++i) {
                k = order[i];
                if (mode) rb_erase_augmented(&items[k].node, &root, &maxima);
                else rb_erase(&items[k].node, &root);
                RB_CLEAR_NODE(&items[k].node);
                assert(RB_EMPTY_NODE(&items[k].node));
                present[k] = false;
                verify(&root, present, --count, mode != 0);
            }
            assert(RB_EMPTY_ROOT(&root));
        }
    }
    printf("STELA_RBTREE checks=%zu checksum=%016llx actual_owned_pointers_above_4GiB=1\n", checks, (unsigned long long)checksum);
    free(items);
}
