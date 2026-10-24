// SPDX-License-Identifier: GPL-2.0-only
/* Authored integration fixtures over unchanged Linux IDR/IDA/radix/XArray.
 * Production links those original translation units, not a tree substitute. */
#ifdef STELA_LINUX_TREES_TEST
#include <linux/array_size.h>
#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/limits.h>
#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xarray.h>
#include <stela/cache.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/test.h>

static_assert(IS_ENABLED(CONFIG_XARRAY_MULTI));

/* The original shared cache is declared by lib/radix-tree.h. No private node
 * algorithm is copied here; only its actual public cache handle is borrowed. */
extern struct kmem_cache *radix_tree_node_cachep;

#define TEST_PAGES 8UL
#define TEST_BYTES (TEST_PAGES * PAGE_SIZE)
#define TEST_PHYSICAL 0x36000000ULL
#define TEST_IDS 8192U
#define MAP_SIZE 256U

struct model_pin {
	bool active;
	size_t first, count;
	u64 physical[TEST_PAGES];
};

static struct {
	u8 *cpu;
	bool used[TEST_PAGES];
	struct model_pin pins[TEST_PAGES];
	unsigned int allocations, releases;
	unsigned int validations, exhausted_requests;
	bool exhausted;
} model;

static unsigned int payload[TEST_IDS];
static unsigned int unsupported_calls;

static void unsupported(void *context, const char *operation)
{
	(void)context;
	unsupported_calls++;
	printf("Unexpected tree dependency refusal: %s\n", operation);
	assert(false);
}

static int validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	assert(context == &model);
	model.validations++;
	if (atomic || !stela_linux_page_request_blocking(gfp) ||
	    !stela_linux_page_request_reclaimable(gfp))
		return -EOPNOTSUPP;
	assert(gfp & (__force u32)__GFP_COMP);
	return order <= 3 ? 0 : -ENOMEM;
}

static int allocate(void *context, u32 gfp, unsigned int order, bool atomic,
		    struct stela_linux_page_allocation *result)
{
	int error = validate(context, gfp, order, atomic);
	if (error)
		return error;
	if (model.exhausted) {
		model.exhausted_requests++;
		return -ENOMEM;
	}
	size_t count = 1UL << order;
	for (size_t first = 0; first + count <= TEST_PAGES; first += count) {
		bool free = true;
		for (size_t i = 0; i < count; i++)
			free &= !model.used[first + i];
		if (!free)
			continue;
		struct model_pin *pin = &model.pins[first];
		assert(!pin->active);
		pin->active = true;
		pin->first = first;
		pin->count = count;
		for (size_t i = 0; i < count; i++) {
			model.used[first + i] = true;
			pin->physical[i] = TEST_PHYSICAL + (u64)(first + i) * PAGE_SIZE;
		}
		u8 *cpu = model.cpu + first * PAGE_SIZE;
		memset(cpu, 0, count * PAGE_SIZE);
		*result = (struct stela_linux_page_allocation){
			.pin = pin, .cpu_base = cpu,
			.physical_pages = pin->physical, .page_count = count,
		};
		model.allocations++;
		return 0;
	}
	model.exhausted_requests++;
	return -ENOMEM;
}

static void release(void *context, void *handle)
{
	assert(context == &model);
	struct model_pin *pin = handle;
	bool known = false;
	for (size_t i = 0; i < TEST_PAGES; i++)
		known |= pin == &model.pins[i];
	assert(known && pin->active);
	for (size_t i = 0; i < pin->count; i++) {
		assert(model.used[pin->first + i]);
		model.used[pin->first + i] = false;
	}
	memset(model.cpu + pin->first * PAGE_SIZE, 0xd3, pin->count * PAGE_SIZE);
	pin->active = false;
	model.releases++;
}

static void settle_empty_cache(void)
{
	assert(stela_linux_quiescent());
	assert(!per_cpu(radix_tree_preloads, 0).nr);
	rcu_barrier();
	assert(!kmem_cache_shrink(radix_tree_node_cachep));
	stela_linux_pages_finish();
	struct stela_linux_slab_pages totals = stela_linux_slab_owned_pages();
	assert(!totals.reclaimable && !totals.unreclaimable);
	assert(model.allocations == model.releases);
	for (size_t i = 0; i < TEST_PAGES; i++)
		assert(!model.used[i] && !model.pins[i].active);
}

static void bitmap_range_math(void)
{
	/* Guarded complete rounded words, with a deliberately non-word bit count.
	 * Direct symbols exercise the original out-of-line helpers independently
	 * of public constant-size inline specialization. */
	const unsigned int bits = 193;
	for (unsigned int start = 0; start <= bits; start++) {
		for (unsigned int count = 0; count <= bits - start; count++) {
			struct { unsigned long before, words[4], after; } actual = {
				.before = 0x459d, .after = 0xa143,
			};
			unsigned long expected[4];
			for (size_t i = 0; i < ARRAY_SIZE(expected); i++)
				expected[i] = actual.words[i] = 0xa5963c7eb419d250UL ^ i;
			__bitmap_clear(actual.words, start, (int)count);
			for (unsigned int i = start; i < start + count; i++)
				expected[i / BITS_PER_LONG] &= ~(1UL << (i % BITS_PER_LONG));
			assert(!memcmp(actual.words, expected, sizeof(expected)));
			assert(actual.before == 0x459d && actual.after == 0xa143);
			__bitmap_set(actual.words, start, (int)count);
			for (unsigned int i = start; i < start + count; i++)
				expected[i / BITS_PER_LONG] |= 1UL << (i % BITS_PER_LONG);
			assert(!memcmp(actual.words, expected, sizeof(expected)));
			assert(actual.before == 0x459d && actual.after == 0xa143);
			unsigned int weight = 0;
			for (unsigned int i = 0; i < bits; i++)
				weight += !!(expected[i / BITS_PER_LONG] & (1UL << (i % BITS_PER_LONG)));
			assert(__bitmap_weight(actual.words, bits) == weight);
		}
	}
}

static void verify_idr(struct idr *tree, void *const *expected)
{
	for (unsigned int i = 0; i < MAP_SIZE; i++)
		assert(idr_find(tree, i) == expected[i]);
	int next = 0;
	for (unsigned int i = 0; i < MAP_SIZE; i++) {
		if (!expected[i])
			continue;
		assert(idr_get_next(tree, &next) == expected[i] && next == (int)i);
		next++;
	}
	assert(!idr_get_next(tree, &next));
}

static void idr_map_and_ranges(void)
{
	struct idr tree;
	idr_init(&tree);
	void *expected[MAP_SIZE] = {0};
	for (unsigned int operation = 0; operation < 1024; operation++) {
		unsigned int start = operation * 37 % MAP_SIZE;
		unsigned int end = start + 16 < MAP_SIZE ? start + 16 : MAP_SIZE;
		int first = -ENOSPC;
		for (unsigned int i = start; i < end; i++) {
			if (!expected[i]) {
				first = (int)i;
				break;
			}
		}
		int actual = idr_alloc(&tree, &payload[operation], (int)start, (int)end, GFP_KERNEL);
		assert(actual == first);
		if (actual >= 0)
			expected[(unsigned int)actual] = &payload[operation];
		if (operation % 3 == 0) {
			unsigned int index = operation * 73 % MAP_SIZE;
			assert(idr_remove(&tree, index) == expected[index]);
			expected[index] = NULL;
		}
		verify_idr(&tree, expected);
	}
	assert(idr_alloc(&tree, &payload[0], 31, 30, GFP_KERNEL) == -ENOSPC);
	idr_destroy(&tree);
	assert(idr_is_empty(&tree));
	for (unsigned int i = 0; i < 1024; i++)
		assert(payload[i] == i); /* Destroy never owns the client objects. */
	settle_empty_cache();
	idr_init_base(&tree, 1000);
	assert(idr_alloc(&tree, &payload[1], 0, 1002, GFP_KERNEL) == 1000);
	assert(idr_alloc(&tree, &payload[2], 1000, 1002, GFP_KERNEL) == 1001);
	assert(idr_alloc(&tree, &payload[3], 1000, 1002, GFP_KERNEL) == -ENOSPC);
	assert(idr_replace(&tree, &payload[4], 1000) == &payload[1]);
	assert(idr_find(&tree, 1000) == &payload[4]);
	assert(PTR_ERR(idr_replace(&tree, &payload[5], 1005)) == -ENOENT);
	idr_destroy(&tree);
	idr_init(&tree);
	idr_set_cursor(&tree, 3);
	const int cyclic[] = {3, 0, 1, 2};
	for (size_t i = 0; i < ARRAY_SIZE(cyclic); i++)
		assert(idr_alloc_cyclic(&tree, &payload[i], 0, 4, GFP_KERNEL) == cyclic[i]);
	assert(idr_alloc_cyclic(&tree, &payload[5], 0, 4, GFP_KERNEL) == -ENOSPC);
	assert(idr_remove(&tree, 1) == &payload[2]);
	assert(idr_alloc_cyclic(&tree, &payload[6], 0, 4, GFP_KERNEL) == 1);
	idr_destroy(&tree);
	idr_init(&tree);
	u32 next = UINT_MAX - 1;
	assert(!idr_alloc_u32(&tree, &payload[7], &next, UINT_MAX, GFP_KERNEL));
	assert(next == UINT_MAX - 1 && idr_find(&tree, next) == &payload[7]);
	assert(!idr_alloc_u32(&tree, &payload[8], &next, UINT_MAX, GFP_KERNEL));
	assert(next == UINT_MAX && idr_find(&tree, next) == &payload[8]);
	assert(idr_alloc_u32(&tree, &payload[9], &next, UINT_MAX, GFP_KERNEL) == -ENOSPC);
	assert(next == UINT_MAX);
	idr_destroy(&tree);
	settle_empty_cache();
}

static void ida_bitmap_and_real_fallback(void)
{
	struct ida ids;
	ida_init(&ids);
	/* Occupying the actual single NOWAIT span forces the original IDA path to
	 * unlock before using its own ordinary GFP_KERNEL fallback. */
	void *held = kmalloc(128, GFP_NOWAIT);
	assert(held && stela_test_heap_try_contains(held));
	assert(ida_alloc_range(&ids, 63, 63, GFP_KERNEL) == 63);
	void *bitmap = xa_load(&ids.xa, 0);
	assert(bitmap && !xa_is_value(bitmap) && !stela_test_heap_try_contains(bitmap));
	kfree(held);
	ida_free(&ids, 63);
	assert(ida_is_empty(&ids));
	/* With retained raw storage available, the locked allocation really uses
	 * that span rather than a libc allocation disguised as nonblocking. */
	assert(ida_alloc_range(&ids, 63, 63, GFP_KERNEL) == 63);
	bitmap = xa_load(&ids.xa, 0);
	assert(bitmap && !xa_is_value(bitmap) && stela_test_heap_try_contains(bitmap));
	ida_free(&ids, 63);
	assert(ida_is_empty(&ids));
	bool expected[2304] = {0};
	for (unsigned int i = 0; i < ARRAY_SIZE(expected); i++) {
		assert(ida_alloc_range(&ids, i, i, GFP_KERNEL) == (int)i);
		expected[i] = true;
	}
	assert(ida_alloc_range(&ids, 0, 2303, GFP_KERNEL) == -ENOSPC);
	for (unsigned int i = 0; i < ARRAY_SIZE(expected); i += 3) {
		ida_free(&ids, i);
		expected[i] = false;
	}
	for (unsigned int lower = 0; lower < ARRAY_SIZE(expected); lower += 29) {
		int first = -ENOENT;
		for (unsigned int i = lower; i < ARRAY_SIZE(expected); i++) {
			if (expected[i]) {
				first = (int)i;
				break;
			}
		}
		assert(ida_find_first_range(&ids, lower, 2303) == first);
	}
	for (unsigned int i = 0; i < ARRAY_SIZE(expected); i += 3)
		assert(ida_alloc_range(&ids, 0, 2303, GFP_KERNEL) == (int)i);
	ida_destroy(&ids);
	assert(ida_is_empty(&ids));
	settle_empty_cache();
}

static void radix_tags_and_indices(void)
{
	RADIX_TREE(tree, GFP_KERNEL);
	const unsigned long indices[] = {0, 1, 63, 64, 4096, ULONG_MAX};
	for (size_t i = 0; i < ARRAY_SIZE(indices); i++) {
		assert(!radix_tree_insert(&tree, indices[i], &payload[i]));
		rcu_read_lock();
		assert(radix_tree_lookup(&tree, indices[i]) == &payload[i]);
		rcu_read_unlock();
		assert(radix_tree_insert(&tree, indices[i], &payload[i + 10]) == -EEXIST);
		if (i & 1)
			assert(radix_tree_tag_set(&tree, indices[i], 1) == &payload[i]);
	}
	void *found[ARRAY_SIZE(indices)];
	rcu_read_lock();
	assert(radix_tree_gang_lookup_tag(&tree, found, 0, (unsigned int)ARRAY_SIZE(found), 1) == 3);
	rcu_read_unlock();
	for (size_t i = 0; i < 3; i++)
		assert(found[i] == &payload[2 * i + 1]);
	assert(radix_tree_tag_clear(&tree, 64, 1) == &payload[3]);
	rcu_read_lock();
	assert(!radix_tree_tag_get(&tree, 64, 1));
	assert(radix_tree_tagged(&tree, 1));
	rcu_read_unlock();
	for (size_t i = 0; i < ARRAY_SIZE(indices); i++)
		assert(radix_tree_delete(&tree, indices[i]) == &payload[i]);
	assert(!tree.xa_head && !radix_tree_tagged(&tree, 1));
	settle_empty_cache();
}

static void verify_xarray(struct xarray *tree, void *const *expected)
{
	for (unsigned long i = 0; i < MAP_SIZE; i++)
		assert(xa_load(tree, i) == expected[i]);
	unsigned long next = 0;
	for (unsigned long i = 0; i < MAP_SIZE; i++) {
		if (!expected[i])
			continue;
		assert(xa_find(tree, &next, MAP_SIZE - 1, XA_PRESENT) == expected[i] && next == i);
		next++;
	}
	assert(!xa_find(tree, &next, MAP_SIZE - 1, XA_PRESENT));
}

static void xarray_map_and_allocations(void)
{
	struct xarray tree;
	xa_init(&tree);
	void *expected[MAP_SIZE] = {0};
	for (unsigned int operation = 0; operation < 1024; operation++) {
		unsigned long index = operation * 73 % MAP_SIZE;
		void *next = operation % 3 ? (void *)&payload[operation] : NULL;
		assert(xa_store(&tree, index, next, GFP_KERNEL) == expected[index]);
		expected[index] = next;
		verify_xarray(&tree, expected);
	}
	xa_set_mark(&tree, 73, XA_MARK_2);
	assert(xa_get_mark(&tree, 73, XA_MARK_2));
	xa_clear_mark(&tree, 73, XA_MARK_2);
	assert(!xa_get_mark(&tree, 73, XA_MARK_2));
	xa_destroy(&tree);
	assert(xa_empty(&tree));
	xa_init_flags(&tree, XA_FLAGS_ALLOC);
	u32 id = 77;
	assert(!xa_alloc(&tree, &id, &payload[0], XA_LIMIT(10, 12), GFP_KERNEL) && id == 10);
	assert(!xa_alloc(&tree, &id, &payload[1], XA_LIMIT(10, 12), GFP_KERNEL) && id == 11);
	assert(!xa_alloc(&tree, &id, &payload[2], XA_LIMIT(10, 12), GFP_KERNEL) && id == 12);
	assert(xa_alloc(&tree, &id, &payload[3], XA_LIMIT(10, 12), GFP_KERNEL) == -EBUSY);
	assert(id == 12);
	assert(xa_erase(&tree, 11) == &payload[1]);
	u32 cursor = 12;
	int result = xa_alloc_cyclic(&tree, &id, &payload[4], XA_LIMIT(10, 12), &cursor, GFP_KERNEL);
	assert(!result && id == 11); /* Public wrapper normalizes wrap to zero. */
	assert(xa_erase(&tree, 11) == &payload[4]);
	cursor = 12;
	xa_lock(&tree);
	result = __xa_alloc_cyclic(&tree, &id, &payload[5], XA_LIMIT(10, 12), &cursor, GFP_KERNEL);
	xa_unlock(&tree);
	assert(result == 1 && id == 11); /* Advanced API preserves the wrap result. */
	xa_destroy(&tree);
	settle_empty_cache();
}

static void xarray_ordered_entries(void)
{
	struct xarray tree;
	xa_init(&tree);
	assert(!xa_store(&tree, 1, &payload[0], GFP_KERNEL));
	assert(!xa_store(&tree, 127, &payload[1], GFP_KERNEL));
	xa_set_mark(&tree, 1, XA_MARK_0);
	xa_set_mark(&tree, 127, XA_MARK_1);
	/* Joining marked leaves exercises original runtime bitmap_clear. */
	assert(!xa_store_range(&tree, 0, 255, &payload[2], GFP_KERNEL));
	for (unsigned long i = 0; i < 256; i++) {
		assert(xa_load(&tree, i) == &payload[2] && xa_get_order(&tree, i) == 8);
		assert(xa_get_mark(&tree, i, XA_MARK_0) && xa_get_mark(&tree, i, XA_MARK_1));
	}
	XA_STATE(state, &tree, 0);
	xas_set_order(&state, 0, 3);
	xas_split_alloc(&state, &payload[2], 8, GFP_KERNEL);
	assert(!xas_error(&state));
	xas_lock(&state);
	xas_split(&state, &payload[2], 8);
	xas_unlock(&state);
	xas_destroy(&state);
	for (unsigned long i = 0; i < 256; i++) {
		assert(xa_load(&tree, i) == &payload[2] && xa_get_order(&tree, i) == 3);
		assert(xa_get_mark(&tree, i, XA_MARK_0) && xa_get_mark(&tree, i, XA_MARK_1));
	}
	assert(xa_store(&tree, 11, &payload[3], GFP_KERNEL) == &payload[2]);
	for (unsigned long i = 0; i < 256; i++)
		assert(xa_load(&tree, i) == (i >= 8 && i < 16 ? &payload[3] : &payload[2]));
	assert(xa_erase(&tree, 9) == &payload[3]);
	for (unsigned long i = 0; i < 256; i++)
		assert(xa_load(&tree, i) == (i >= 8 && i < 16 ? NULL : &payload[2]));
	xa_destroy(&tree);
	settle_empty_cache();
}

static void allocation_failure(void)
{
	struct idr tree;
	idr_init(&tree);
	model.exhausted = true;
	u32 next = UINT_MAX;
	assert(idr_alloc_u32(&tree, &payload[0], &next, UINT_MAX, GFP_KERNEL) == -ENOMEM);
	assert(next == UINT_MAX && idr_is_empty(&tree));
	struct xarray array;
	xa_init(&array);
	assert(!xa_store(&array, 0, &payload[1], GFP_KERNEL)); /* Root needs no node. */
	assert(xa_err(xa_store(&array, ULONG_MAX, &payload[2], GFP_KERNEL)) == -ENOMEM);
	assert(xa_load(&array, 0) == &payload[1] && !xa_load(&array, ULONG_MAX));
	assert(model.exhausted_requests);
	model.exhausted = false;
	idr_destroy(&tree);
	xa_destroy(&array);
	settle_empty_cache();
}

static void preload_lifetime_and_retirement(const struct stela_linux_owner *owner)
{
	struct idr tree;
	idr_init(&tree);
	idr_preload(GFP_KERNEL);
	unsigned int count = per_cpu(radix_tree_preloads, 0).nr;
	assert(count && !stela_linux_quiescent());
	idr_preload_end();
	assert(stela_linux_quiescent());
	struct stela_linux_slab_pages before = stela_linux_slab_owned_pages();
	assert(before.reclaimable && !before.unreclaimable);
	assert(stela_linux_page_catalog_unregister(1) == -EBUSY);
	stela_linux_exit();
	stela_linux_enter(&stela_linux_bare);
	assert(per_cpu(radix_tree_preloads, 0).nr == count);
	struct stela_linux_slab_pages after = stela_linux_slab_owned_pages();
	assert(before.reclaimable == after.reclaimable && !after.unreclaimable);
	assert(stela_linux_page_catalog_unregister(1) == -EBUSY);
	stela_linux_exit();
	stela_linux_enter(owner);
	/* Consume original retained pool through original IDR allocation. Every
	 * cache/bitmap attempt remains genuinely nonblocking; no fake CPU death,
	 * direct private pool mutation or fixture-only drain is involved. Eight
	 * backing pages hold fewer nodes than required by TEST_IDS dense IDs. */
	preempt_disable();
	unsigned int inserted = 0;
	for (; inserted < TEST_IDS; inserted++) {
		int id = idr_alloc(&tree, &payload[inserted], 0, (int)TEST_IDS, GFP_NOWAIT);
		if (id == -ENOMEM)
			break;
		assert(id == (int)inserted);
	}
	assert(inserted && inserted < TEST_IDS && !per_cpu(radix_tree_preloads, 0).nr);
	preempt_enable();
	for (unsigned int i = 0; i < inserted; i++)
		assert(idr_find(&tree, i) == &payload[i]);
	rcu_read_lock();
	idr_destroy(&tree);
	/* Internal nodes cannot return to the cache before this reader ends. */
	after = stela_linux_slab_owned_pages();
	assert(after.reclaimable && !after.unreclaimable);
	rcu_read_unlock();
	settle_empty_cache();
	assert(!stela_linux_page_catalog_unregister(1));
}

int main(void)
{
	model.cpu = aligned_alloc(TEST_BYTES, TEST_BYTES);
	assert(model.cpu);
	memset(model.cpu, 0xd3, TEST_BYTES);
	for (unsigned int i = 0; i < TEST_IDS; i++)
		payload[i] = i;
	const struct stela_linux_services services = {.unsupported = unsupported};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	const struct stela_linux_page_reservation reservation = {
		.generation = 1, .physical_base = TEST_PHYSICAL,
		.cpu_base = model.cpu, .page_count = TEST_PAGES,
	};
	const struct stela_linux_page_ops operations = {
		.validate = validate, .allocate = allocate, .release = release,
	};
	assert(!stela_linux_page_catalog_register(&reservation, &operations, &model));
	/* Real original once-only initialization; no per-enter constructor or
	 * replacement global cache/CPUHP callback is introduced. */
	radix_tree_init();
	assert(radix_tree_node_cachep);
	stela_test_heap_try_enable(true);
	bitmap_range_math();
	idr_map_and_ranges();
	ida_bitmap_and_real_fallback();
	radix_tags_and_indices();
	xarray_map_and_allocations();
	xarray_ordered_entries();
	allocation_failure();
	preload_lifetime_and_retirement(&owner);
	stela_test_heap_try_enable(false);
	assert(!unsupported_calls);
	stela_linux_exit();
	free(model.cpu);
	printf("Linux trees: original IDR/IDA/radix/XArray, bounded bitmap, allocation and retained lifetime\n");
	return 0;
}
#endif
