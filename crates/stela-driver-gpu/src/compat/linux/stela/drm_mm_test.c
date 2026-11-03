// SPDX-License-Identifier: MIT
/* Whole original drm_mm range algorithm versus an independent byte occupancy
 * model. Metadata offsets grant no backing, CPU mapping, IOVA or GPU address. */
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <drm/drm_mm.h>
#include <stela/test.h>

/* This oracle exercises caller-owned metadata only. Any diagnostic is a
 * test failure, so it does not need the runtime task or DRM printer graph. */
struct drm_printer;
void drm_printf(struct drm_printer *printer, const char *format, ...);
void stela_linux_warn(const char *file, int line, const char *condition, unsigned int flags);
void drm_printf(struct drm_printer *printer, const char *format, ...)
{
	(void)printer;
	stela_test_fail(__FILE__, __LINE__, format);
}
void stela_linux_warn(const char *file, int line, const char *condition, unsigned int flags)
{
	(void)flags;
	stela_test_fail(file, line, condition ?: "unexpected DRM warning");
}
void __warn_printk(const char *format, ...)
{
	stela_test_fail(__FILE__, __LINE__, format);
}

#define UNITS 256U
#define NODES 32U
static unsigned int operations;

static u32 next_random(u32 *state)
{
	u32 value = *state;
	value ^= value << 13;
	value ^= value >> 17;
	value ^= value << 5;
	return *state = value;
}

static void verify(struct drm_mm *mm, const bool used[UNITS], u64 base)
{
	bool observed[UNITS] = {0}, holes[UNITS] = {0};
	struct drm_mm_node *node;
	u64 previous_end = base;
	drm_mm_for_each_node(node, mm) {
		assert(drm_mm_node_allocated(node) && node->mm == mm && node->size);
		assert(node->start >= previous_end && node->start >= base);
		assert(node->start - base < UNITS && node->size <= UNITS - (node->start - base));
		for (u64 i = 0; i < node->size; i++)
			observed[node->start - base + i] = true;
		previous_end = node->start + node->size;
	}
	u64 start, end;
	drm_mm_for_each_hole(node, mm, start, end) {
		assert(start >= base && start < end && end - base <= UNITS);
		for (u64 address = start; address < end; address++) {
			assert(!holes[address - base]);
			holes[address - base] = true;
		}
	}
	for (unsigned int i = 0; i < UNITS; i++) {
		assert(observed[i] == used[i] && holes[i] == !used[i]);
		node = __drm_mm_interval_first(mm, base + i, base + i);
		/* The original interval API returns its unallocated head sentinel
		 * for no overlap, rather than NULL. */
		assert((node != &mm->head_node) == used[i]);
		if (node != &mm->head_node)
			assert(node->start <= base + i && base + i < node->start + node->size);
	}
}

static void sequences(u64 base, u32 seed)
{
	struct drm_mm mm = {0};
	struct drm_mm_node nodes[NODES] = {0};
	bool used[UNITS] = {0};
	drm_mm_init(&mm, base, UNITS);
	verify(&mm, used, base);
	const u64 alignments[] = {0, 1, 2, 3, 4, 7, 8, 16, 64, 512, 2048};
	for (unsigned int step = 0; step < 10000; step++) {
		struct drm_mm_node *node = nodes + next_random(&seed) % NODES;
		if (drm_mm_node_allocated(node)) {
			for (u64 i = 0; i < node->size; i++) {
				assert(used[node->start - base + i]);
				used[node->start - base + i] = false;
			}
			drm_mm_remove_node(node);
			assert(!drm_mm_node_allocated(node));
		} else {
			u64 size = next_random(&seed) % 33;
			u64 alignment = alignments[next_random(&seed) % ARRAY_SIZE(alignments)];
			u64 low = next_random(&seed) % (UNITS + 1);
			u64 high = next_random(&seed) % (UNITS + 1);
			if (low > high) {
				u64 temporary = low;
				low = high;
				high = temporary;
			}
			enum drm_mm_insert_mode mode = next_random(&seed) & 1U ?
				DRM_MM_INSERT_LOW : DRM_MM_INSERT_HIGH;
			bool found = false;
			u64 expected = 0;
			if (size && high - low >= size) {
				for (u64 candidate = low; candidate <= high - size; candidate++) {
					if (alignment > 1 && (base + candidate) % alignment)
						continue;
					bool free = true;
					for (u64 i = 0; i < size; i++)
						free &= !used[candidate + i];
					if (!free)
						continue;
					expected = candidate;
					found = true;
					if (mode == DRM_MM_INSERT_LOW)
						break;
				}
			}
			/* Original removal explicitly permits reusing the same node without
			 * clearing it again; failures must not republish its old allocation. */
			int result = drm_mm_insert_node_in_range(&mm, node, size, alignment,
				step, base + low, base + high, mode);
			assert(result == (found ? 0 : -ENOSPC));
			assert(drm_mm_node_allocated(node) == found);
			if (found) {
				assert(node->start == base + expected && node->size == size);
				assert(node->color == step);
				for (u64 i = 0; i < size; i++) {
					assert(!used[expected + i]);
					used[expected + i] = true;
				}
			}
		}
		operations++;
		if (!(step % 31))
			verify(&mm, used, base);
	}
	verify(&mm, used, base);
	for (unsigned int i = 0; i < NODES; i++)
		if (drm_mm_node_allocated(nodes + i))
			drm_mm_remove_node(nodes + i);
	assert(drm_mm_clean(&mm));
	drm_mm_takedown(&mm);
}

static void reservation(void)
{
	struct drm_mm mm = {0};
	struct drm_mm_node first = {.start = 1032, .size = 16};
	struct drm_mm_node overlap = {.start = 1040, .size = 8};
	struct drm_mm_node end = {.start = 1276, .size = 4};
	struct drm_mm_node overflow = {.start = U64_MAX - 2, .size = 4};
	drm_mm_init(&mm, 1024, UNITS);
	assert(!drm_mm_reserve_node(&mm, &first));
	assert(drm_mm_reserve_node(&mm, &overlap) == -ENOSPC);
	assert(!drm_mm_node_allocated(&overlap));
	assert(!drm_mm_reserve_node(&mm, &end));
	assert(drm_mm_reserve_node(&mm, &overflow) == -ENOSPC);
	assert(!drm_mm_node_allocated(&overflow));
	drm_mm_remove_node(&first);
	drm_mm_remove_node(&end);
	assert(drm_mm_clean(&mm));
	drm_mm_takedown(&mm);
}

static void color_adjust(const struct drm_mm_node *before, unsigned long color,
			 u64 *start, u64 *end)
{
	const struct drm_mm_node *after = list_next_entry(before, node_list);
	if (before->color != color)
		(*start)++;
	if (after->color != color)
		(*end)--;
}

static void colors(void)
{
	struct drm_mm mm = {0};
	struct drm_mm_node a = {0}, b = {0}, c = {0};
	drm_mm_init(&mm, 4096, 64);
	mm.color_adjust = color_adjust;
	assert(!drm_mm_insert_node_generic(&mm, &a, 8, 0, 1, DRM_MM_INSERT_LOW));
	assert(a.start == 4097);
	assert(!drm_mm_insert_node_generic(&mm, &b, 8, 0, 1, DRM_MM_INSERT_LOW));
	assert(b.start == 4105);
	assert(!drm_mm_insert_node_generic(&mm, &c, 8, 0, 2, DRM_MM_INSERT_LOW));
	assert(c.start == 4114);
	drm_mm_remove_node(&b);
	assert(!drm_mm_insert_node_generic(&mm, &b, 8, 0, 1, DRM_MM_INSERT_LOW));
	assert(b.start == 4105 && b.start + b.size + 1 == c.start);
	drm_mm_remove_node(&a);
	drm_mm_remove_node(&b);
	drm_mm_remove_node(&c);
	assert(drm_mm_clean(&mm));
	drm_mm_takedown(&mm);
}

int main(void)
{
	sequences(4096, 0x4139U);
	sequences(0x100000000003ULL, 0xc28aU);
	sequences(U64_MAX - 512, 0x9bd7U);
	reservation();
	colors();
	printf("Linux DRM mm: %u linear-oracle operations, holes/intervals, alignment, high addresses, reservations and colors\n", operations);
	return 0;
}
