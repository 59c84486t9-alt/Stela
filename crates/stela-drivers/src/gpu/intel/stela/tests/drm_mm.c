/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "drm_mm_algorithm.c"

#define SPAN 257
#define NODES 96
struct drm_printer { unsigned calls; };
static unsigned warnings;
void drm_printf(struct drm_printer *printer, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    /* Exercise genuine variadic formatting without printing every dump. */
    char text[256];
    int n = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    assert(n > 0 && (size_t)n < sizeof(text));
    ++printer->calls;
}
int stela_test_mm_warn(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    ++warnings;
    return 1;
}
static uint32_t random_word(uint32_t *state)
{
    *state ^= *state << 13; *state ^= *state >> 17; *state ^= *state << 5;
    return *state;
}
static uint64_t checksum = UINT64_C(1469598103934665603);
static unsigned checks;
static void record(u64 value) { checksum = (checksum ^ value) * UINT64_C(1099511628211); }
static void verify(struct drm_mm *mm, u64 base, const bool *used, struct drm_mm_node *nodes)
{
    bool seen[SPAN] = {false};
    struct drm_mm_node *node;
    u64 last = base;
    unsigned allocated = 0;
    drm_mm_for_each_node(node, mm) {
        assert(node >= nodes && node < nodes + NODES);
        assert(node->mm == mm && drm_mm_node_allocated(node));
        assert(node->start >= last && node->start >= base && node->size > 0);
        assert(node->start - base + node->size <= SPAN);
        for (u64 i = node->start - base; i < node->start - base + node->size; ++i) {
            assert(!seen[i]); seen[i] = true;
        }
        last = node->start + node->size;
        ++allocated;
        record(node->start - base); record(node->size);
    }
    assert(memcmp(seen, used, sizeof(seen)) == 0);
    unsigned free_bytes = 0, hole_count = 0;
    u64 start, end;
    drm_mm_for_each_hole(node, mm, start, end) {
        assert(start >= base && end > start && end <= base + SPAN);
        for (u64 i = start - base; i < end - base; ++i) assert(!used[i]);
        free_bytes += (unsigned)(end - start);
        ++hole_count;
    }
    unsigned expected_free = 0;
    for (unsigned i = 0; i < SPAN; ++i) expected_free += !used[i];
    assert(free_bytes == expected_free);
    assert(hole_count <= allocated + 1);
    /* Independent byte-coordinate oracle for actual interval search. */
    for (unsigned i = 0; i < SPAN; ++i) {
        node = __drm_mm_interval_first(mm, base + i, base + i);
        if (used[i]) assert(node != &mm->head_node && node->start <= base + i && node->start + node->size > base + i);
        else assert(node == &mm->head_node);
    }
    ++checks;
}
static bool fits(const bool *used, u64 base, unsigned offset, unsigned bytes,
                 unsigned alignment, u64 range_start, u64 range_end)
{
    if (!bytes || offset + bytes > SPAN || base + offset < range_start || base + offset + bytes > range_end) return false;
    if (alignment && (base + offset) % alignment) return false;
    for (unsigned i = offset; i < offset + bytes; ++i) if (used[i]) return false;
    return true;
}
static void mark(bool *used, u64 base, struct drm_mm_node *node, bool occupied)
{
    assert(node->start >= base && node->start - base + node->size <= SPAN);
    for (u64 i = node->start - base; i < node->start - base + node->size; ++i) {
        assert(used[i] != occupied); used[i] = occupied;
    }
}
static void scenario(u64 base, uint32_t seed, struct drm_mm *mm, struct drm_mm_node *nodes)
{
    bool used[SPAN] = {false};
    memset(mm, 0, sizeof(*mm)); memset(nodes, 0, NODES * sizeof(*nodes));
    drm_mm_init(mm, base, SPAN);
    /* Inherited display/firmware ranges are real reservations, not allocation hints. */
    const unsigned offsets[] = {0, 43, 211};
    for (unsigned i = 0; i < 3; ++i) {
        nodes[i].start = base + offsets[i]; nodes[i].size = 7;
        assert(drm_mm_reserve_node(mm, &nodes[i]) == 0);
        mark(used, base, &nodes[i], true);
    }
    verify(mm, base, used, nodes);
    for (unsigned iteration = 0; iteration < 512; ++iteration) {
        unsigned slot = 3 + random_word(&seed) % (NODES - 3);
        struct drm_mm_node *node = &nodes[slot];
        if (drm_mm_node_allocated(node)) {
            mark(used, base, node, false); drm_mm_remove_node(node);
        } else {
            unsigned size = random_word(&seed) % 20;
            unsigned alignment = random_word(&seed) % 19;
            unsigned lo = random_word(&seed) % SPAN;
            unsigned hi = lo + random_word(&seed) % (SPAN - lo + 1);
            enum drm_mm_insert_mode mode = (enum drm_mm_insert_mode)(random_word(&seed) % 4);
            bool once = (random_word(&seed) % 7) == 0;
            if (once) mode |= DRM_MM_INSERT_ONCE;
            int lowest = -1, highest = -1;
            for (unsigned i = 0; i < SPAN; ++i) if (fits(used, base, i, size, alignment, base + lo, base + hi)) {
                if (lowest < 0) lowest = (int)i;
                highest = (int)i;
            }
            struct drm_mm_node before = *node;
            struct drm_mm mm_before = *mm;
            int error = drm_mm_insert_node_in_range(mm, node, size, alignment, 0, base + lo, base + hi, mode);
            if (error) {
                assert(error == -ENOSPC);
                assert(once || lowest < 0);
                assert(memcmp(node, &before, sizeof(before)) == 0);
                assert(memcmp(mm, &mm_before, sizeof(mm_before)) == 0);
                record(0xffff);
            } else {
                assert(lowest >= 0 && fits(used, base, (unsigned)(node->start - base), size, alignment, base + lo, base + hi));
                if ((mode & ~DRM_MM_INSERT_ONCE) == DRM_MM_INSERT_LOW) assert(node->start == base + (unsigned)lowest);
                if ((mode & ~DRM_MM_INSERT_ONCE) == DRM_MM_INSERT_HIGH) assert(node->start == base + (unsigned)highest);
                mark(used, base, node, true);
            }
        }
        verify(mm, base, used, nodes);
    }
    struct drm_printer printer = {0}; drm_mm_print(mm, &printer); assert(printer.calls >= 2);
    /* Exact overlap/overflow reservation refusal must preserve both inventories. */
    struct drm_mm_node refused = {.start = base, .size = 1}, before = refused;
    struct drm_mm old = *mm;
    assert(drm_mm_reserve_node(mm, &refused) == -ENOSPC);
    assert(memcmp(&refused, &before, sizeof(before)) == 0 && memcmp(mm, &old, sizeof(old)) == 0);
    refused.start = U64_MAX - 1; refused.size = 4; before = refused;
    assert(drm_mm_reserve_node(mm, &refused) == -ENOSPC);
    assert(memcmp(&refused, &before, sizeof(before)) == 0 && memcmp(mm, &old, sizeof(old)) == 0);
    for (unsigned i = 0; i < NODES; ++i) if (drm_mm_node_allocated(&nodes[i])) {
        mark(used, base, &nodes[i], false); drm_mm_remove_node(&nodes[i]);
    }
    verify(mm, base, used, nodes);
    assert(drm_mm_clean(mm)); drm_mm_takedown(mm); assert(!warnings);
}
static void scan_scenario(struct drm_mm *mm, struct drm_mm_node *nodes, bool high)
{
    bool used[SPAN] = {false}, evict[4] = {false};
    memset(mm, 0, sizeof(*mm)); memset(nodes, 0, NODES * sizeof(*nodes));
    drm_mm_init(mm, 0, SPAN);
    for (unsigned i = 0; i < 4; ++i) {
        nodes[i].start = i * 64; nodes[i].size = 64;
        assert(drm_mm_reserve_node(mm, &nodes[i]) == 0);
        mark(used, 0, &nodes[i], true);
    }
    struct drm_mm_scan scan;
    drm_mm_scan_init_with_range(&scan, mm, 96, 16, 0, 0, SPAN,
                                high ? DRM_MM_INSERT_HIGH : DRM_MM_INSERT_LOW);
    const unsigned order[] = {1, 3, 0, 2};
    unsigned added = 0;
    while (added < 4) {
        if (drm_mm_scan_add_block(&scan, &nodes[order[added++]])) break;
    }
    assert(scan.hit_end - scan.hit_start == 96);
    /* Respect original LIFO restoration; no other operation during scanning. */
    for (unsigned i = added; i; --i) evict[order[i - 1]] = drm_mm_scan_remove_block(&scan, &nodes[order[i - 1]]);
    assert(mm->scan_active == 0);
    for (unsigned i = 0; i < 4; ++i) if (evict[i]) {
        mark(used, 0, &nodes[i], false); drm_mm_remove_node(&nodes[i]);
    }
    assert(drm_mm_scan_color_evict(&scan) == NULL); /* actual color0 policy */
    verify(mm, 0, used, nodes);
    assert(drm_mm_insert_node_in_range(mm, &nodes[4], 96, 16, 0, 0, SPAN, DRM_MM_INSERT_EVICT) == 0);
    assert(fits(used, 0, (unsigned)nodes[4].start, 96, 16, 0, SPAN));
    mark(used, 0, &nodes[4], true); verify(mm, 0, used, nodes);
    /* Original warning continues without freeing a still-owned reservation. */
    drm_mm_takedown(mm); assert(warnings == 1 && drm_mm_node_allocated(&nodes[4]));
    for (unsigned i = 0; i < 5; ++i) if (drm_mm_node_allocated(&nodes[i])) {
        mark(used, 0, &nodes[i], false); drm_mm_remove_node(&nodes[i]);
    }
    verify(mm, 0, used, nodes); assert(drm_mm_clean(mm));
    drm_mm_takedown(mm); assert(warnings == 1); warnings = 0;
}
int main(void)
{
    struct drm_mm *mm = calloc(1, sizeof(*mm));
    struct drm_mm_node *nodes = calloc(NODES, sizeof(*nodes));
    assert(mm && nodes && (__UINTPTR_TYPE__)mm > UINT32_MAX && (__UINTPTR_TYPE__)nodes > UINT32_MAX);
    fprintf(stderr, "actual owned mm=%p nodes=%p node_bytes=%zu long_bytes=%zu\n", (void *)mm, (void *)nodes, sizeof(*nodes), sizeof(long));
    const u64 bases[] = {0, 0x100000000ULL, U64_MAX - 4095};
    for (unsigned i = 0; i < 3; ++i) for (uint32_t seed = 1; seed <= 16; ++seed) scenario(bases[i], seed, mm, nodes);
    scan_scenario(mm, nodes, false); scan_scenario(mm, nodes, true);
    printf("STELA_DRM_MM checks=%u checksum=%016llx actual_owned_pointers_above_4GiB=1\n", checks, (unsigned long long)checksum);
    free(nodes); free(mm);
}
