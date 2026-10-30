/* SPDX-License-Identifier: MIT */
/* Original nonbatched RCU-free helpers over actual canonical C allocator and
 * RCU implementations. ELF wrappers observe real heap/queue routes, never
 * replace their effects. The hosted heap and CPU are explicit model peers. */
#include <linux/bottom_half.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <stela/allocation.h>
#include <stela/linux.h>
#include <stela/test.h>

void kvfree_rcu_cb(struct rcu_head *);
void *__real_stela_linux_heap_alloc(size_t, size_t);
void __real_stela_linux_heap_free(void *, size_t, size_t);
void __real_call_rcu(struct rcu_head *, rcu_callback_t);

static bool capture_allocation, forbid_free, forbid_enqueue;
static void *captured_base;
static const struct rcu_head *expected_callback;
static unsigned int captured_frees, queued;
static unsigned long required_cookie;

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

struct record {
	u8 prefix[64];
	struct rcu_head head;
	u8 payload[32];
};

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
	embedded(0);
	embedded(64);
	embedded(4080);
	headless();
	assert(stela_test_traps(bad_context));
	assert(stela_test_traps(foreign));
	assert(stela_test_traps(mismatched_base));
	assert(stela_test_traps(outside_logical_extent));
	assert(stela_test_traps(offset_too_large));
	assert(stela_test_traps(early_callback));
	stela_linux_exit();
	printf("Canonical RCU free: 129 live allocation lifetimes,3 embedded offsets, headless grace and6 before-effect refusals passed\n");
	return 0;
}
