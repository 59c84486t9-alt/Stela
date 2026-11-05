/* SPDX-License-Identifier: MIT */
/* Original nonbatched RCU-free helpers. The hosted source fixture joins real
 * RCU and both fixtures observe the actual allocator/queue through ELF wrappers. */
#include <linux/bottom_half.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <stela/allocation.h>
#include <stela/cache.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/test.h>

void kvfree_rcu_cb(struct rcu_head *);
void *__real_stela_linux_heap_alloc(size_t, size_t);
void __real_stela_linux_heap_free(void *, size_t, size_t);
void __real_call_rcu(struct rcu_head *, rcu_callback_t);

/* All original continuations in the fixture run on the same host thread. */
static _Thread_local bool capture_allocation, forbid_free, forbid_enqueue;
static _Thread_local void *captured_base;
static _Thread_local const struct rcu_head *expected_callback;
static _Thread_local unsigned int captured_frees, queued;
static _Thread_local unsigned long required_cookie;

void *__wrap_stela_linux_heap_alloc(size_t size, size_t align)
{
	void *object = __real_stela_linux_heap_alloc(size, align);
	if (capture_allocation) {
		assert(object && !captured_base);
		captured_base = object;
		capture_allocation = false;
	}
	return object;
}

void __wrap_stela_linux_heap_free(void *object, size_t size, size_t align)
{
	assert(!forbid_free);
	if (object == captured_base) {
		assert(!captured_frees++);
		if (expected_callback) {
			assert(stela_linux_rcu_callback_current(expected_callback));
			assert(in_serving_softirq() && !irqs_disabled());
		} else {
			assert(stela_linux_quiescent());
			assert(get_state_synchronize_rcu() != required_cookie);
		}
	}
	__real_stela_linux_heap_free(object, size, align);
}

void __wrap_call_rcu(struct rcu_head *head, rcu_callback_t callback)
{
	assert(!forbid_enqueue);
	queued++;
	__real_call_rcu(head, callback);
}

#ifdef STELA_LINUX_DEFERRED_FREE_SOURCE_TEST
void stela_linux_deferred_free_source_test(void);

static void reset_observer(void)
{
	captured_base = NULL;
	captured_frees = 0;
	expected_callback = NULL;
	required_cookie = 0;
}

static void embedded(size_t offset)
{
	reset_observer();
	capture_allocation = true;
	u8 *object = kmalloc(offset + sizeof(struct rcu_head) + 16, GFP_KERNEL);
	assert(object && captured_base && !capture_allocation);
	memset(object, 0xa9, offset + sizeof(struct rcu_head) + 16);
	struct rcu_head *head = (void *)(object + offset);
	expected_callback = head;
	unsigned long address = (unsigned long)object;
	struct stela_linux_allocation allocation;
	assert(stela_linux_allocation_range(head, sizeof(*head), &allocation));
	assert(allocation.object == object && !allocation.cache);
	assert(allocation.bytes == offset + sizeof(*head) + 16);
	unsigned int before = queued;
	rcu_read_lock();
	rcu_read_lock_bh();
	kvfree_call_rcu(head, object);
	assert(queued == before + 1 && !captured_frees);
	for (size_t i = 0; i < offset; i++) assert(object[i] == 0xa9);
	for (size_t i = 0; i < 16; i++) assert(object[offset + sizeof(*head) + i] == 0xa9);
	rcu_read_unlock_bh();
	assert(!captured_frees);
	rcu_read_unlock();
	assert(!captured_frees);
	synchronize_rcu();
	assert(!captured_frees); /* Grace completion is not callback delivery. */
	rcu_barrier();
	assert(captured_frees == 1);
	assert(!stela_linux_allocation_range((void *)address, 1, &allocation));
	assert(!stela_linux_rcu_callback_current(head));
	reset_observer();
}

static void headless(void)
{
	reset_observer();
	capture_allocation = true;
	void *object = kmalloc(97, GFP_KERNEL);
	assert(object && captured_base);
	required_cookie = get_state_synchronize_rcu();
	kvfree_call_rcu(NULL, object);
	assert(captured_frees == 1);
	reset_observer();
	kvfree(NULL);
	kvfree(ZERO_SIZE_PTR);
}

struct page_callback {
	struct rcu_head head;
	struct page *page;
	bool retired;
};

static void retire_page(struct rcu_head *head)
{
	struct page_callback *callback = container_of(head, struct page_callback, head);
	assert(stela_linux_rcu_callback_current(head) && in_serving_softirq() && !stela_linux_quiescent());
	assert(!callback->retired);
	__free_page(callback->page);
	callback->retired = true;
}

static void page_backing_returns_after_callback(void)
{
	/* Let the original startup finish populating its page-backed workers
	 * before measuring the exact free inventory across the callback. */
	for (unsigned int tick = 0; tick < HZ && !READ_ONCE(bdi_wq); tick++)
		schedule_timeout_uninterruptible(1);
	assert(READ_ONCE(bdi_wq));
	stela_linux_pages_finish();
	unsigned long before, available;
	assert(!stela_linux_available_page_frames(&before) && before);
	struct page_callback callback = {.page = alloc_page(GFP_KERNEL)};
	assert(callback.page);
	assert(!stela_linux_available_page_frames(&available) && available == before - 1);
	rcu_read_lock();
	call_rcu(&callback.head, retire_page);
	assert(!callback.retired && page_ref_count(callback.page) == 1);
	rcu_read_unlock();
	stela_linux_rcu_finish();
	assert(callback.retired);
	stela_linux_pages_finish();
	assert(!stela_linux_available_page_frames(&available) && available == before);
	struct page *reused = alloc_page(GFP_KERNEL);
	assert(reused == callback.page);
	__free_page(reused);
	stela_linux_pages_finish();
}

struct cache_object {
	u8 prefix[64];
	struct rcu_head head;
	u8 payload[32];
};

static void cache_destruction_joins_deferred_objects(void)
{
	struct stela_linux_slab_pages totals = stela_linux_slab_owned_pages();
	unsigned long before, available;
	assert(!stela_linux_available_page_frames(&before));
	struct kmem_cache_args args = {.align = 128};
	struct kmem_cache *cache = __kmem_cache_create_args("source-cache-rcu",
		sizeof(struct cache_object), &args, SLAB_TYPESAFE_BY_RCU);
	assert(cache);
	struct cache_object *object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	unsigned long address = (unsigned long)object;
	memset(object->prefix, 0x49, sizeof(object->prefix));
	memset(object->payload, 0x92, sizeof(object->payload));
	struct stela_linux_allocation allocation;
	assert(stela_linux_allocation_range(&object->head, sizeof(object->head), &allocation));
	assert(allocation.object == object && allocation.cache == cache && allocation.bytes == sizeof(*object));
	assert(!stela_linux_allocation_range((u8 *)object + sizeof(*object) - 8, 16, &allocation));
	rcu_read_lock();
	kvfree_rcu(object, head);
	assert(stela_linux_allocation_range(object, sizeof(*object), &allocation));
	for (size_t i = 0; i < sizeof(object->prefix); i++) assert(object->prefix[i] == 0x49);
	for (size_t i = 0; i < sizeof(object->payload); i++) assert(object->payload[i] == 0x92);
	rcu_read_unlock();
	/* Destroy must join the queued object free while its cache is still live,
	 * then join the detached slab before returning its backing. */
	kmem_cache_destroy(cache);
	assert(!stela_linux_allocation_range((void *)address, 1, &allocation));
	assert(!stela_linux_available_page_frames(&available) && available == before);

	cache = __kmem_cache_create_args("source-cache-kfree", sizeof(struct cache_object), &args, 0);
	assert(cache);
	object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	address = (unsigned long)object;
	kfree(object);
	assert(!stela_linux_allocation_range((void *)address, 1, &allocation));
	kmem_cache_destroy(cache);
	assert(!stela_linux_available_page_frames(&available) && available == before);
	struct stela_linux_slab_pages after = stela_linux_slab_owned_pages();
	assert(after.reclaimable == totals.reclaimable && after.unreclaimable == totals.unreclaimable);
}

static unsigned int constructors;

static void initialize_cache_object(void *pointer)
{
	u64 *value = pointer;
	constructors++;
	*value = 0x123456789abcdef0ULL;
}

static void cache_shrink_preserves_late_page_reference(void)
{
	struct stela_linux_slab_pages before = stela_linux_slab_owned_pages();
	unsigned long free_before, available;
	assert(!stela_linux_available_page_frames(&free_before));
	struct kmem_cache_args args = {.align = 128, .ctor = initialize_cache_object};
	struct kmem_cache *cache = __kmem_cache_create_args("source-cache-late-page-ref",
		PAGE_SIZE + 1, &args, SLAB_TYPESAFE_BY_RCU);
	assert(cache);
	u64 *object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object && *object == 0x123456789abcdef0ULL && constructors == 1);
	struct page *head = virt_to_page(object);
	struct page *tail = head + 1;
	assert(PageHead(head) && PageTail(tail));
	*object = 0xfedcba9876543210ULL;
	kmem_cache_free(cache, object);
	assert(!kmem_cache_shrink(cache));
	struct stela_linux_slab_pages detached = stela_linux_slab_owned_pages();
	assert(detached.unreclaimable == before.unreclaimable + 2);
	rcu_read_lock();
	get_page(tail);
	assert(*object == 0xfedcba9876543210ULL);
	rcu_read_unlock();
	stela_linux_rcu_finish();
	assert(page_ref_count(head) == 2 && kmem_cache_shrink(cache) == 1);
	assert(!stela_linux_available_page_frames(&available) && available + 2 == free_before);
	u64 *reused = kmem_cache_alloc(cache, GFP_NOWAIT);
	assert(reused == object && *reused == 0xfedcba9876543210ULL && constructors == 1);
	kmem_cache_free(cache, reused);
	put_page(tail);
	assert(page_ref_count(head) == 1 && !kmem_cache_shrink(cache));
	stela_linux_rcu_finish();
	struct stela_linux_slab_pages retired = stela_linux_slab_owned_pages();
	assert(retired.reclaimable == before.reclaimable && retired.unreclaimable == before.unreclaimable);
	/* The dispatcher can drain the returned frames during the RCU wait. */
	stela_linux_pages_finish();
	assert(!stela_linux_available_page_frames(&available) && available == free_before);
	kmem_cache_destroy(cache);
}

void stela_linux_deferred_free_source_test(void)
{
	embedded(0);
	embedded(64);
	embedded(4080);
	headless();
	page_backing_returns_after_callback();
	cache_destruction_joins_deferred_objects();
	cache_shrink_preserves_late_page_reference();
}
#else

struct record {
	u8 prefix[64];
	struct rcu_head head;
	u8 payload[32];
};

static void bad_context(void)
{
	void *object = kmalloc(96, GFP_KERNEL);
	assert(object);
	forbid_free = true;
	rcu_read_lock();
	kvfree_call_rcu(NULL, object);
}

static void foreign(void)
{
	struct record object;
	memset(&object, 0xa5, sizeof(object));
	forbid_enqueue = true;
	kvfree_call_rcu(&object.head, &object);
}

static void mismatched_base(void)
{
	struct record *one = kmalloc(sizeof(*one), GFP_KERNEL);
	struct record *two = kmalloc(sizeof(*two), GFP_KERNEL);
	assert(one && two);
	forbid_enqueue = true;
	kvfree_call_rcu(&one->head, two);
}

static void outside_logical_extent(void)
{
	u8 *object = kmalloc(96, GFP_KERNEL);
	assert(object);
	forbid_enqueue = true;
	kvfree_call_rcu((void *)(object + 88), object);
}

static void offset_too_large(void)
{
	u8 *object = kmalloc(8192, GFP_KERNEL);
	assert(object);
	forbid_enqueue = true;
	kvfree_call_rcu((void *)(object + 4096), object);
}

static void early_callback(void)
{
	struct record *object = kmalloc(sizeof(*object), GFP_KERNEL);
	assert(object);
	forbid_free = true;
	kvfree_rcu_cb(&object->head);
}

static void raw_allocation_lifetimes(void)
{
	void *objects[129];
	size_t sizes[129];
	struct stela_linux_allocation allocation;
	for (size_t i = 0; i < ARRAY_SIZE(objects); i++) {
		sizes[i] = 17 + (i * 73) % 997;
		objects[i] = kmalloc(sizes[i], GFP_KERNEL);
		assert(objects[i]);
		memset(objects[i], (int)i, sizes[i]);
	}
	for (size_t n = 0; n < ARRAY_SIZE(objects); n++) {
		size_t i = n * 47 % ARRAY_SIZE(objects); /* 47 and129 are coprime. */
		u8 *object = objects[i];
		assert(stela_linux_allocation_range(object + sizes[i] - 1, 1, &allocation));
		assert(allocation.object == object && allocation.bytes == sizes[i]);
		assert(!stela_linux_allocation_range(object + sizes[i] - 1, 2, &allocation));
		assert(!stela_linux_allocation_range(object, SIZE_MAX, &allocation));
		for (size_t b = 0; b < sizes[i]; b++) assert(object[b] == (u8)i);
		unsigned long address = (unsigned long)object;
		kvfree(object);
		assert(!stela_linux_allocation_range((void *)address, 1, &allocation));
	}
	assert(!stela_linux_allocation_range((void *)1UL, 1, &allocation));
	assert(!stela_linux_allocation_range((void *)ULONG_MAX, 1, &allocation));
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);
	raw_allocation_lifetimes();
	assert(stela_test_traps(bad_context));
	assert(stela_test_traps(foreign));
	assert(stela_test_traps(mismatched_base));
	assert(stela_test_traps(outside_logical_extent));
	assert(stela_test_traps(offset_too_large));
	assert(stela_test_traps(early_callback));
	stela_linux_exit();
	printf("Canonical allocation: 129 lifetimes and six deferred-free refusals passed\n");
	return 0;
}
#endif
