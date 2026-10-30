// SPDX-License-Identifier: MIT
/* Serialized caches behind Linux's public opaque handle. Object storage is
 * retained catalog-backed RAM; neither an in-object free pointer nor a heap
 * wrapper may overwrite constructor/RCU-visible contents. No SLUB-private
 * layout, native interrupt execution, reserve or reclaim service is implied. */
#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <stela/cache.h>
#include <stela/allocation.h>
#include <stela/linux.h>
#include <stela/page.h>

#define CACHE_NO_SLOT SIZE_MAX

/* This service supplies neither memcg charging nor SLUB's private page
 * classification. Page descriptors remain the catalog's raw page grants. */
static_assert(!IS_ENABLED(CONFIG_MEMCG));
static_assert(MAX_PAGE_ORDER < BITS_PER_LONG - PAGE_SHIFT);

struct cache_slot {
	size_t next;
	bool allocated;
};

struct cache_slab {
	struct cache_slab *next;
	struct kmem_cache *cache;
	struct rcu_head rcu;
	struct page *pages;
	u8 *cpu;
	size_t count;
	size_t free_count;
	size_t free_head;
	size_t metadata_size;
	struct cache_slot slots[];
};

/* The public header intentionally forward-declares this type. No code using
 * Linux mm/slab.h's allocator-private definition may consume these handles. */
struct kmem_cache {
	struct kmem_cache *next;
	struct cache_slab *slabs;
	void (*ctor)(void *);
	slab_flags_t flags;
	unsigned int object_size;
	unsigned int order;
	size_t stride;
	size_t live;
	size_t pending;
	size_t growing;
	size_t descriptor_size;
	bool destroying;
	char name[];
};

static struct kmem_cache *caches;
static struct stela_linux_slab_pages slab_pages;

struct stela_linux_slab_pages stela_linux_slab_owned_pages(void)
{
	(void)stela_linux_owner();
	return slab_pages;
}

static size_t *slab_page_counter(const struct kmem_cache *cache)
{
	return cache->flags & SLAB_RECLAIM_ACCOUNT ?
		&slab_pages.reclaimable : &slab_pages.unreclaimable;
}

static bool charge_slab_pages(const struct kmem_cache *cache)
{
	size_t pages = (size_t)1 << cache->order;
	size_t *total = slab_page_counter(cache);
	if (pages > SIZE_MAX - *total)
		return false;
	*total += pages;
	return true;
}

#ifdef STELA_LINUX_CACHE_TEST
/* Acquisition failure injection is confined to the inline hosted harness. */
static size_t metadata_fail_after = SIZE_MAX;
static size_t metadata_live;
#endif

static void *allocate_metadata(size_t size, size_t align)
{
#ifdef STELA_LINUX_CACHE_TEST
	if (metadata_fail_after != SIZE_MAX) {
		if (!metadata_fail_after)
			return NULL;
		metadata_fail_after--;
	}
#endif
	void *object = stela_linux_heap_alloc(size, align);
#ifdef STELA_LINUX_CACHE_TEST
	if (object)
		metadata_live++;
#endif
	return object;
}

static void free_metadata(void *object, size_t size, size_t align)
{
#ifdef STELA_LINUX_CACHE_TEST
	if (!metadata_live)
		__builtin_trap();
	metadata_live--;
#endif
	stela_linux_heap_free(object, size, align);
}

static struct kmem_cache *require_cache(struct kmem_cache *cache)
{
	(void)stela_linux_owner();
	for (struct kmem_cache *entry = caches; entry; entry = entry->next)
		if (entry == cache)
			return cache;
	/* Reject stale/foreign handles without first dereferencing them. */
	__builtin_trap();
}

static struct kmem_cache *creation_failure(slab_flags_t flags, const char *reason,
					 bool unsupported)
{
	if (unsupported)
		stela_linux_unsupported(reason);
	if (flags & SLAB_PANIC) {
		pr_emerg("SLAB_PANIC: cache creation failed: %s\n", reason);
		__builtin_trap();
	}
	return NULL;
}

static bool power_of_two(size_t value)
{
	return value && !(value & (value - 1));
}

struct kmem_cache *__kmem_cache_create_args(const char *name, unsigned int object_size,
					    struct kmem_cache_args *args, slab_flags_t flags)
{
	(void)stela_linux_owner();
	const struct kmem_cache_args defaults = {0};
	const struct kmem_cache_args *options = args ? args : &defaults;
	slab_flags_t allowed = SLAB_HWCACHE_ALIGN | SLAB_TYPESAFE_BY_RCU | SLAB_PANIC |
		SLAB_NO_MERGE | SLAB_NO_SHEAVES | SLAB_RECLAIM_ACCOUNT;
	if (!stela_linux_quiescent())
		return creation_failure(flags, "cache creation context", true);
	if (flags & ~allowed)
		return creation_failure(flags, "cache creation flags", true);
	if (options->use_freeptr_offset || options->sheaf_capacity ||
	    (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && (options->usersize || options->useroffset)))
		return creation_failure(flags, "cache custom freelist, sheaves or hardened usercopy", true);
	/* With !HARDENED_USERCOPY the public fields are inert, as in the pinned
	 * slab_common.c. Never claim that configuration implements usercopy checks. */
	if (!name || !name[0] || !object_size ||
	    (options->align && !power_of_two(options->align)))
		return creation_failure(flags, "invalid cache name, size or alignment", false);
	size_t align = max_t(size_t, options->align, arch_slab_minalign());
	align = max_t(size_t, align, sizeof(void *));
	if (flags & SLAB_HWCACHE_ALIGN) {
		size_t line = cache_line_size();
		while (object_size <= line / 2)
			line /= 2;
		align = max(align, line);
	}
	if (!power_of_two(align) || object_size > SIZE_MAX - (align - 1))
		return creation_failure(flags, "cache slot overflow", false);
	size_t stride = ((size_t)object_size + align - 1) & ~(align - 1);
	size_t bytes = PAGE_SIZE;
	unsigned int order = 0;
	while (bytes < stride && order < MAX_PAGE_ORDER) {
		bytes <<= 1;
		order++;
	}
	if (bytes < stride)
		return creation_failure(flags, "cache slot exceeds supported page order", false);
	size_t length = strlen(name);
	if (length >= (size_t)SSIZE_MAX - sizeof(struct kmem_cache))
		return creation_failure(flags, "cache name overflow", false);
	size_t descriptor_size = sizeof(struct kmem_cache) + length + 1;
	struct kmem_cache *cache = allocate_metadata(descriptor_size, __alignof__(*cache));
	if (!cache)
		return creation_failure(flags, "cache descriptor/name exhausted", false);
	*cache = (struct kmem_cache){
		.next = caches, .ctor = options->ctor, .flags = flags,
		.object_size = object_size, .order = order, .stride = stride,
		.descriptor_size = descriptor_size,
	};
	memcpy(cache->name, name, length + 1);
	caches = cache;
	return cache;
}

/* Policy is checked even for an already retained slot. A ready slot cannot
 * justify silently accepting reserve, placement or forward-progress policy.
 * Nonblocking ordinary requests can use a ready slot, but never grow backing
 * or allocate metadata through the current process-only native provider. */
static bool request_supported(gfp_t flags)
{
	gfp_t allowed = GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN | __GFP_NOMEMALLOC |
		__GFP_ACCOUNT;
	if ((flags & ~allowed) ||
	    (gfpflags_allow_blocking(flags) && !stela_linux_quiescent())) {
		stela_linux_unsupported("cache allocation policy or context");
		return false;
	}
	return true;
}

static struct cache_slab *grow_cache(struct kmem_cache *cache, gfp_t flags)
{
	if (cache->growing == SIZE_MAX)
		return NULL;
	size_t bytes = (size_t)PAGE_SIZE << cache->order;
	size_t count = bytes / cache->stride;
	if (!count || count > ((size_t)SSIZE_MAX - sizeof(struct cache_slab)) /
				 sizeof(struct cache_slot))
		return NULL;
	size_t metadata_size = sizeof(struct cache_slab) + count * sizeof(struct cache_slot);
	cache->growing++;
	/* Canonical policy/provider validation precedes slab metadata acquisition.
	 * Compound ownership retains the entire extent if any tail is pinned.
	 * This internal bookkeeping adds COMP without dropping any caller bit. */
	gfp_t backing_flags = flags | __GFP_COMP;
	if (cache->flags & SLAB_RECLAIM_ACCOUNT)
		backing_flags |= __GFP_RECLAIMABLE;
	struct page *pages = alloc_pages_noprof(backing_flags, cache->order);
	if (!pages) {
		cache->growing--;
		return NULL;
	}
	struct cache_slab *slab = allocate_metadata(metadata_size, __alignof__(*slab));
	/* Whole backing, not occupied object bytes, becomes slab-owned only once
	 * both acquisitions succeed. Constructors can observe this charge. */
	if (!slab || !charge_slab_pages(cache)) {
		if (slab)
			free_metadata(slab, metadata_size, __alignof__(*slab));
		__free_pages(pages, cache->order);
		cache->growing--;
		stela_linux_pages_finish();
		return NULL;
	}
	*slab = (struct cache_slab){
		.cache = cache, .pages = pages, .cpu = page_address(pages),
		.count = count, .free_count = count, .free_head = 0,
		.metadata_size = metadata_size,
	};
	const struct stela_linux_owner *owner = stela_linux_owner();
	int nesting = preempt_count();
	unsigned long irq = arch_local_save_flags();
	for (size_t i = 0; i < count; i++) {
		slab->slots[i] = (struct cache_slot){
			.next = i + 1 < count ? i + 1 : CACHE_NO_SLOT,
		};
		if (cache->ctor) {
			cache->ctor(slab->cpu + i * cache->stride);
			if (stela_linux_owner() != owner || preempt_count() != nesting ||
			    arch_local_save_flags() != irq)
				__builtin_trap();
		}
	}
	/* Constructors may allocate from another (or this) cache. Publish only
	 * after every slot has been constructed, preserving any recursive growth. */
	slab->next = cache->slabs;
	cache->slabs = slab;
	cache->growing--;
	return slab;
}

void *kmem_cache_alloc_noprof(struct kmem_cache *cache, gfp_t flags)
{
	cache = require_cache(cache);
	if (!request_supported(flags))
		return NULL;
	if (cache->ctor && (flags & __GFP_ZERO)) {
		stela_linux_unsupported("zero allocation from a constructor cache");
		return NULL;
	}
	if (cache->destroying) {
		stela_linux_unsupported("allocation from a destroying cache");
		return NULL;
	}
	if (cache->live == SIZE_MAX)
		return NULL;
	struct cache_slab *slab = cache->slabs;
	while (slab && !slab->free_count)
		slab = slab->next;
	if (!slab) {
		if (!gfpflags_allow_blocking(flags))
			return NULL;
		slab = grow_cache(cache, flags);
		if (!slab)
			return NULL;
	}
	/* A constructor may have performed recursive allocations. */
	if (cache->live == SIZE_MAX)
		return NULL;
	size_t index = slab->free_head;
	if (!slab->free_count || index >= slab->count || slab->slots[index].allocated)
		__builtin_trap();
	struct cache_slot *slot = slab->slots + index;
	slab->free_head = slot->next;
	slab->free_count--;
	slot->allocated = true;
	slot->next = CACHE_NO_SLOT;
	cache->live++;
	void *object = slab->cpu + index * cache->stride;
	if (flags & __GFP_ZERO)
		memset(object, 0, cache->object_size);
	return object;
}

void *kmem_cache_alloc_lru_noprof(struct kmem_cache *cache, struct list_lru *lru,
				gfp_t flags)
{
	/* Pinned !MEMCG has no per-memcg list_lru allocation/charge here. */
	(void)lru;
	return kmem_cache_alloc_noprof(cache, flags);
}

void kmem_cache_free(struct kmem_cache *cache, void *object)
{
	cache = require_cache(cache);
	if (!object)
		return;
	unsigned long address = (unsigned long)object;
	for (struct cache_slab *slab = cache->slabs; slab; slab = slab->next) {
		unsigned long base = (unsigned long)slab->cpu;
		size_t used = slab->count * cache->stride;
		if (address < base || address - base >= used)
			continue;
		size_t offset = address - base;
		if (offset % cache->stride)
			__builtin_trap();
		struct cache_slot *slot = slab->slots + offset / cache->stride;
		if (!slot->allocated || !cache->live || slab->free_count >= slab->count)
			__builtin_trap();
		slot->allocated = false;
		slot->next = slab->free_head;
		slab->free_head = offset / cache->stride;
		slab->free_count++;
		cache->live--;
		/* Retention, including the final free slot, permits immediate
		 * same-cache reuse during an RCU reader without changing its bytes. */
		return;
	}
	__builtin_trap();
}

/* Resolve only actual allocated slots. Constructor bytes, stride padding,
 * retired slabs and unallocated storage grant no object ownership. Existing
 * live objects remain resolvable while cache destruction waits for them.
 */
bool stela_linux_cache_range(const void *pointer, size_t bytes,
                            struct stela_linux_allocation *out)
{
 (void)stela_linux_owner();
 unsigned long address = (unsigned long)pointer;
 for (struct kmem_cache *cache = caches; cache; cache = cache->next) {
  for (struct cache_slab *slab = cache->slabs; slab; slab = slab->next) {
   unsigned long base = (unsigned long)slab->cpu;
   size_t used = slab->count * cache->stride;
   if (address < base || address - base >= used) continue;
   size_t offset = address - base, index = offset / cache->stride;
   size_t inner = offset % cache->stride;
   if (!slab->slots[index].allocated || inner >= cache->object_size ||
       bytes > cache->object_size - inner) return false;
   *out = (struct stela_linux_allocation){
    .object = slab->cpu + index * cache->stride,
    .bytes = cache->object_size, .cache = cache,
   };
   return true;
  }
 }
 return false;
}

unsigned int kmem_cache_size(struct kmem_cache *cache)
{
	return require_cache(cache)->object_size;
}

static void release_slab(struct cache_slab *slab)
{
	struct kmem_cache *cache = slab->cache;
	size_t pages = (size_t)1 << cache->order;
	size_t *total = slab_page_counter(cache);
	if (slab->free_count != slab->count || page_ref_count(slab->pages) != 1 ||
	    *total < pages)
		__builtin_trap();
	/* In an RCU callback this only queues the native pin. The existing owner
	 * exit drains callbacks before process-context page-provider release. */
	__free_pages(slab->pages, cache->order);
	/* The slab relinquished its last whole page grant. The page catalog may
	 * still queue native pin release; that is no longer slab-owned storage. */
	*total -= pages;
	free_metadata(slab, slab->metadata_size, __alignof__(*slab));
}

static void release_slab_rcu(struct rcu_head *head)
{
	struct cache_slab *slab = container_of(head, struct cache_slab, rcu);
	struct kmem_cache *cache = require_cache(slab->cache);
	if (!cache->pending)
		__builtin_trap();
	/* A reader may have taken a page reference after shrink detached the
	 * empty slab. Keep its descriptor and cache alive as well as the pin;
	 * do not requeue forever while that external reference remains held. */
	if (page_ref_count(slab->pages) > 1) {
		slab->next = cache->slabs;
		cache->slabs = slab;
	} else {
		release_slab(slab);
	}
	cache->pending--;
}

static void detach_empty_slabs(struct kmem_cache *cache)
{
	struct cache_slab **link = &cache->slabs;
	while (*link) {
		struct cache_slab *slab = *link;
		if (slab->free_count != slab->count || page_ref_count(slab->pages) != 1) {
			link = &slab->next;
			continue;
		}
		*link = slab->next;
		if (cache->flags & SLAB_TYPESAFE_BY_RCU) {
			if (cache->pending == SIZE_MAX)
				__builtin_trap();
			cache->pending++;
			call_rcu(&slab->rcu, release_slab_rcu);
		} else {
			release_slab(slab);
		}
	}
}

int kmem_cache_shrink(struct kmem_cache *cache)
{
	cache = require_cache(cache);
	if (!stela_linux_quiescent()) {
		stela_linux_unsupported("cache shrink context");
		return -EOPNOTSUPP;
	}
	detach_empty_slabs(cache);
	/* Detached RCU backing still awaits its grace period, as in Linux.
	 * A zero result means no active slab remains in the cache. */
	return cache->slabs || cache->growing ? 1 : 0;
}

void kmem_cache_destroy(struct kmem_cache *cache)
{
	(void)stela_linux_owner();
	if (!cache)
		return;
	cache = require_cache(cache);
	if (!stela_linux_quiescent()) {
		stela_linux_unsupported("cache destroy context");
		return;
	}
	if (cache->growing || cache->destroying) {
		stela_linux_unsupported("cache destroy during construction or destruction");
		return;
	}
	cache->destroying = true;
	/* Caller callbacks may include deferred frees. Drain chains, without
	 * removing the handle needed by those frees or allocator callbacks. */
	stela_linux_rcu_finish();
	if (cache->live) {
		cache->destroying = false;
		stela_linux_unsupported("cache destroy with outstanding objects");
		return;
	}
	detach_empty_slabs(cache);
	stela_linux_rcu_finish();
	if (cache->pending || cache->live || cache->growing)
		__builtin_trap();
	if (cache->slabs) {
		cache->destroying = false;
		stela_linux_unsupported("cache destroy with outstanding page references");
		return;
	}
	stela_linux_pages_finish();
	struct kmem_cache **link = &caches;
	while (*link != cache) {
		if (!*link)
			__builtin_trap();
		link = &(*link)->next;
	}
	*link = cache->next;
	free_metadata(cache, cache->descriptor_size, __alignof__(*cache));
}

#ifdef STELA_LINUX_CACHE_TEST
#include <linux/bottom_half.h>
#include <linux/scatterlist.h>
#include <stela/test.h>

#define TEST_PAGES 32UL
#define TEST_BYTES (TEST_PAGES * PAGE_SIZE)
#define TEST_PHYSICAL 0x28000000ULL

struct test_pin {
	bool active;
	size_t first;
	size_t count;
	u64 physical[TEST_PAGES];
};

static struct {
	u8 *cpu;
	bool used[TEST_PAGES];
	struct test_pin pins[TEST_PAGES];
	unsigned int validations;
	unsigned int attempts;
	unsigned int allocations;
	unsigned int releases;
	unsigned int refusals;
	u32 seen_gfp;
	unsigned int seen_order;
	bool reclaimable_fallback;
	bool exhausted;
	bool refuse_policy;
	bool malformed;
} fixture;

static int test_validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
	assert(context == &fixture && !stela_linux_try_enter(&stela_linux_bare));
	fixture.validations++;
	fixture.seen_gfp = gfp;
	fixture.seen_order = order;
	assert(order <= MAX_PAGE_ORDER);
	assert(gfp & (__force u32)__GFP_COMP);
	bool policy = stela_linux_page_request_basic(gfp) ||
		(fixture.reclaimable_fallback && stela_linux_page_request_reclaimable(gfp));
	if (fixture.refuse_policy || atomic || !policy ||
	    !stela_linux_page_request_blocking(gfp))
		return -EOPNOTSUPP;
	return 0;
}

static int test_allocate(void *context, u32 gfp, unsigned int order, bool atomic,
			 struct stela_linux_page_allocation *allocation)
{
	assert(context == &fixture && !atomic);
	assert(gfp == fixture.seen_gfp && order == fixture.seen_order);
	assert(stela_linux_page_request_basic(gfp) ||
	       (fixture.reclaimable_fallback && stela_linux_page_request_reclaimable(gfp)));
	fixture.attempts++;
	if (fixture.exhausted || order > 5)
		return -ENOMEM;
	size_t count = (size_t)1 << order;
	size_t first = TEST_PAGES;
	for (size_t i = 0; i + count <= TEST_PAGES; i += count) {
		bool available = true;
		for (size_t j = 0; j < count; j++)
			available &= !fixture.used[i + j];
		if (available) {
			first = i;
			break;
		}
	}
	if (first == TEST_PAGES)
		return -ENOMEM;
	struct test_pin *pin = NULL;
	for (size_t i = 0; i < TEST_PAGES; i++) {
		if (!fixture.pins[i].active) {
			pin = fixture.pins + i;
			break;
		}
	}
	assert(pin);
	*pin = (struct test_pin){.active = true, .first = first, .count = count};
	for (size_t i = 0; i < count; i++) {
		fixture.used[first + i] = true;
		pin->physical[i] = TEST_PHYSICAL + (u64)(first + i) * PAGE_SIZE;
	}
	memset(fixture.cpu + first * PAGE_SIZE, 0xa7, count * PAGE_SIZE);
	*allocation = (struct stela_linux_page_allocation){
		.pin = pin, .cpu_base = fixture.cpu + first * PAGE_SIZE,
		.physical_pages = pin->physical, .page_count = count,
	};
	if (fixture.malformed)
		allocation->page_count++;
	fixture.allocations++;
	return 0;
}

static void test_release(void *context, void *token)
{
	struct test_pin *pin = token;
	assert(context == &fixture && stela_linux_quiescent());
	assert(!stela_linux_try_enter(&stela_linux_bare) && pin->active);
	for (size_t i = 0; i < pin->count; i++) {
		assert(fixture.used[pin->first + i]);
		fixture.used[pin->first + i] = false;
	}
	pin->active = false;
	fixture.releases++;
}

static void test_unsupported(void *context, const char *operation)
{
	assert(context == &fixture && operation && *operation);
	fixture.refusals++;
}

static const struct stela_linux_page_ops test_ops = {
	.validate = test_validate, .allocate = test_allocate, .release = test_release,
};

static void check_totals(size_t reclaimable, size_t unreclaimable)
{
	struct stela_linux_slab_pages totals = stela_linux_slab_owned_pages();
	assert(totals.reclaimable == reclaimable && totals.unreclaimable == unreclaimable);
}

static void check_clean(void)
{
	check_totals(0, 0);
	assert(!caches && !metadata_live && metadata_fail_after == SIZE_MAX);
	stela_linux_rcu_finish();
	stela_linux_pages_finish();
	assert(fixture.allocations == fixture.releases);
	for (size_t i = 0; i < TEST_PAGES; i++)
		assert(!fixture.used[i] && !fixture.pins[i].active);
}

struct old_object {
	u64 engine;
	u64 key;
	u64 lock;
	u8 trailing[73];
};

static size_t constructed;
static struct kmem_cache *constructing_cache;

static void old_object_ctor(void *pointer)
{
	struct old_object *object = pointer;
	memset(object, 0x31, sizeof(*object));
	object->engine = 0x123456789abcdef0ULL;
	object->key = 0x7766554433221100ULL;
	object->lock = 0x10fedcba98765432ULL;
	if (!constructed) {
		assert(constructing_cache && constructing_cache->growing == 1);
		assert(kmem_cache_shrink(constructing_cache) == 1);
		unsigned int refusals = fixture.refusals;
		kmem_cache_destroy(constructing_cache);
		assert(fixture.refusals == refusals + 1 && !constructing_cache->destroying);
	}
	constructed++;
}

static struct kmem_cache *trap_cache;
static void *trap_object;
static unsigned long trap_pfn;

static void stale_handle(void)
{
	(void)kmem_cache_size(trap_cache);
}

static void retired_page(void)
{
	(void)pfn_to_page(trap_pfn);
}

static void double_free(void)
{
	kmem_cache_free(trap_cache, trap_object);
}

static void interior_free(void)
{
	kmem_cache_free(trap_cache, (u8 *)trap_object + 1);
}

static void foreign_free(void)
{
	kmem_cache_free(trap_cache, &fixture);
}

static void metadata_is_not_payload(void)
{
	(void)__pa(trap_cache);
}

static void constructor_and_rcu_reuse(void)
{
	struct kmem_cache_args args = {.align = 64, .ctor = old_object_ctor};
	struct kmem_cache *cache = __kmem_cache_create_args("old-engine", sizeof(struct old_object),
							 &args, SLAB_TYPESAFE_BY_RCU | SLAB_HWCACHE_ALIGN);
	assert(cache && kmem_cache_size(cache) == sizeof(struct old_object));
	unsigned int initial_validations = fixture.validations;
	assert(!kmem_cache_zalloc(cache, GFP_KERNEL));
	assert(!cache->slabs && !constructed && fixture.validations == initial_validations);
	constructing_cache = cache;
	struct old_object *object = kmem_cache_alloc(cache, GFP_KERNEL);
	constructing_cache = NULL;
	assert(object && !((unsigned long)object & 63));
	assert(constructed == cache->slabs->count);
	size_t initial_constructors = constructed;
	struct page *page = virt_to_page(object);
	trap_pfn = page_to_pfn(page);
	assert(pfn_to_page(trap_pfn) == page && page_address(page) == object);
	assert(stela_linux_page_catalog_unregister(1) == -EBUSY);
	object->engine = 0xfeedbeef01234567ULL;
	object->key = 0x12345678;
	memset(object->trailing, 0x92, sizeof(object->trailing));
	u8 saved[sizeof(*object)];
	memcpy(saved, object, sizeof(saved));
	unsigned int validations = fixture.validations;
	rcu_read_lock();
	kmem_cache_free(cache, object);
	assert(!memcmp(object, saved, sizeof(saved)));
	struct old_object *reused = kmem_cache_alloc(cache, GFP_NOWAIT);
	assert(reused == object && !memcmp(reused, saved, sizeof(saved)));
	assert(constructed == initial_constructors && fixture.validations == validations);
	unsigned int refusals = fixture.refusals;
	assert(!kmem_cache_alloc(cache, GFP_NOWAIT | __GFP_ZERO));
	assert(fixture.refusals == refusals + 1 && !memcmp(object, saved, sizeof(saved)));
	kmem_cache_free(cache, reused);
	assert(!memcmp(object, saved, sizeof(saved)));
	rcu_read_unlock();
	assert(!kmem_cache_shrink(cache) && cache->pending == 1 && !cache->slabs);
	assert(pfn_to_page(trap_pfn) == page && !memcmp(object, saved, sizeof(saved)));
	unsigned int releases = fixture.releases;
	stela_linux_rcu_finish();
	assert(!cache->pending && metadata_live == 1 && fixture.releases == releases);
	assert(stela_test_traps(retired_page));
	stela_linux_pages_finish();
	assert(fixture.releases == releases + 1);
	trap_cache = cache;
	kmem_cache_destroy(cache);
	assert(stela_test_traps(stale_handle));
	check_clean();
}

static void alignment_and_zeroing(void)
{
	const struct {
		unsigned int size;
		unsigned int align;
		size_t expected;
	} cases[] = {
		{1, 0, 8}, {24, 0, 32}, {32, 0, 32}, {33, 0, 64},
		{64, 0, 64}, {65, 0, 64}, {96, 128, 128}, {192, 32, 64},
		{PAGE_SIZE - 1, PAGE_SIZE, PAGE_SIZE},
		{PAGE_SIZE + 573, 2 * PAGE_SIZE, 2 * PAGE_SIZE},
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct kmem_cache_args args = {.align = cases[i].align};
		struct kmem_cache *cache = __kmem_cache_create_args("zero-and-align", cases[i].size,
								 &args, SLAB_HWCACHE_ALIGN);
		assert(cache && cache->stride % cases[i].expected == 0);
		u8 *object = kmem_cache_alloc_lru(cache, NULL, GFP_KERNEL);
		assert(object && !((unsigned long)object & (cases[i].expected - 1)));
		for (size_t j = 0; j < cases[i].size; j++)
			assert(object[j] == 0xa7);
		memset(object, 0x67, cases[i].size);
		bool padding = cache->stride > cases[i].size;
		if (padding)
			object[cases[i].size] = 0x81;
		kmem_cache_free(cache, object);
		u8 *reused = kmem_cache_zalloc(cache, GFP_NOWAIT);
		assert(reused == object);
		for (size_t j = 0; j < cases[i].size; j++)
			assert(reused[j] == 0);
		if (padding)
			assert(reused[cases[i].size] == 0x81);
		kmem_cache_free(cache, reused);
		kmem_cache_destroy(cache);
		check_clean();
	}
}

static void page_and_sg_lifetime(void)
{
	struct kmem_cache_args args = {.align = 2 * PAGE_SIZE};
	struct kmem_cache *cache = __kmem_cache_create_args("inline-sg", PAGE_SIZE + 573, &args, 0);
	u8 *object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object && cache->order == 1);
	struct page *head = virt_to_page(object);
	struct page *tail = virt_to_page(object + PAGE_SIZE);
	assert(PageHead(head) && PageTail(tail) && compound_head(tail) == head);
	assert(page_to_pfn(tail) == page_to_pfn(head) + 1);
	assert(page_address(tail) == object + PAGE_SIZE);
	assert(__va(__pa(object + PAGE_SIZE + 572)) == object + PAGE_SIZE + 572);
	struct scatterlist sg;
	sg_init_one(&sg, object, PAGE_SIZE + 573);
	assert(sg_page(&sg) == head && sg.offset == 0 && sg.length == PAGE_SIZE + 573);
	struct sg_page_iter iterator;
	size_t seen = 0;
	for_each_sg_page(&sg, &iterator, 1, 0) {
		assert(sg_page_iter_page(&iterator) == head + seen);
		seen++;
	}
	assert(seen == 2);
	get_page(tail);
	assert(page_ref_count(head) == 2);
	kmem_cache_free(cache, object);
	unsigned int releases = fixture.releases;
	assert(kmem_cache_shrink(cache) == 1 && cache->slabs && !cache->pending);
	unsigned int refusals = fixture.refusals;
	kmem_cache_destroy(cache);
	assert(fixture.refusals == refusals + 1 && !cache->destroying);
	assert(kmem_cache_size(cache) == PAGE_SIZE + 573 && fixture.releases == releases);
	put_page(tail);
	assert(page_ref_count(head) == 1);
	kmem_cache_destroy(cache);
	assert(fixture.releases == releases + 1);
	check_clean();
}

static void reference_after_rcu_detach(void)
{
	struct kmem_cache *cache = __kmem_cache_create_args("detached-pin", PAGE_SIZE + 1,
							 NULL, SLAB_TYPESAFE_BY_RCU);
	void *object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	struct page *head = virt_to_page(object);
	struct page *tail = head + 1;
	unsigned int releases = fixture.releases;
	kmem_cache_free(cache, object);
	assert(!kmem_cache_shrink(cache) && cache->pending == 1 && !cache->slabs);
	rcu_read_lock();
	get_page(tail);
	rcu_read_unlock();
	unsigned int refusals = fixture.refusals;
	kmem_cache_destroy(cache);
	assert(fixture.refusals == refusals + 1 && cache->slabs && !cache->pending);
	assert(!cache->destroying && fixture.releases == releases && page_ref_count(head) == 2);
	assert(metadata_live == 2);
	void *reused = kmem_cache_alloc(cache, GFP_NOWAIT);
	assert(reused == object);
	kmem_cache_free(cache, reused);
	put_page(tail);
	assert(page_ref_count(head) == 1);
	/* Exercise head references separately from compound tail references. */
	get_page(head);
	assert(kmem_cache_shrink(cache) == 1);
	put_page(head);
	assert(!kmem_cache_shrink(cache) && cache->pending == 1);
	kmem_cache_destroy(cache);
	assert(fixture.releases == releases + 1);
	check_clean();
}

struct deferred_free {
	struct rcu_head head;
	struct kmem_cache *cache;
	void *object;
};

static void free_deferred(struct rcu_head *head)
{
	struct deferred_free *deferred = container_of(head, struct deferred_free, head);
	assert(in_serving_softirq());
	kmem_cache_free(deferred->cache, deferred->object);
}

static void destroy_and_misuse(void)
{
	struct kmem_cache *cache = __kmem_cache_create_args("deferred", 96, NULL, SLAB_TYPESAFE_BY_RCU);
	void *object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	trap_cache = cache;
	trap_object = object;
	assert(stela_test_traps(interior_free));
	assert(stela_test_traps(foreign_free));
	assert(stela_test_traps(metadata_is_not_payload));
	unsigned int refusals = fixture.refusals;
	kmem_cache_destroy(cache);
	assert(fixture.refusals == refusals + 1 && !cache->destroying && cache->live == 1);
	assert(kmem_cache_size(cache) == 96);
	struct deferred_free deferred = {.cache = cache, .object = object};
	call_rcu(&deferred.head, free_deferred);
	kmem_cache_destroy(cache);
	assert(stela_test_traps(stale_handle));
	check_clean();
	cache = __kmem_cache_create_args("double-free", 96, NULL, 0);
	object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	trap_cache = cache;
	trap_object = object;
	kmem_cache_free(cache, NULL);
	kmem_cache_free(cache, object);
	assert(stela_test_traps(double_free));
	kmem_cache_destroy(cache);
	kmem_cache_destroy(NULL);
	check_clean();
}

static void capacity_and_failures(void)
{
	metadata_fail_after = 0;
	assert(!__kmem_cache_create_args("descriptor-failure", 96, NULL, 0));
	assert(!metadata_live && !caches);
	metadata_fail_after = SIZE_MAX;
	struct kmem_cache *cache = __kmem_cache_create_args("capacity", 96, NULL, 0);
	assert(cache && metadata_live == 1);
	metadata_fail_after = 0;
	unsigned int releases = fixture.releases;
	assert(!kmem_cache_alloc(cache, GFP_KERNEL));
	assert(!cache->slabs && !cache->growing && metadata_live == 1);
	assert(fixture.releases == releases + 1);
	metadata_fail_after = SIZE_MAX;
	fixture.exhausted = true;
	assert(!kmem_cache_alloc(cache, GFP_KERNEL));
	fixture.exhausted = false;
	fixture.refuse_policy = true;
	unsigned int attempts = fixture.attempts;
	unsigned int refusals = fixture.refusals;
	assert(!kmem_cache_alloc(cache, GFP_KERNEL));
	assert(fixture.attempts == attempts && fixture.refusals == refusals + 1);
	fixture.refuse_policy = false;
	fixture.malformed = true;
	releases = fixture.releases;
	assert(!kmem_cache_alloc(cache, GFP_KERNEL));
	assert(fixture.releases == releases + 1 && metadata_live == 1 && !cache->slabs);
	fixture.malformed = false;
	void *objects[128];
	objects[0] = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(objects[0]);
	size_t count = cache->slabs->count;
	assert(count + 1 <= ARRAY_SIZE(objects));
	for (size_t i = 1; i < count; i++) {
		objects[i] = kmem_cache_alloc(cache, GFP_NOWAIT);
		assert(objects[i]);
		for (size_t j = 0; j < i; j++)
			assert(objects[i] != objects[j]);
	}
	unsigned int validations = fixture.validations;
	assert(!kmem_cache_alloc(cache, GFP_NOWAIT));
	assert(!kmem_cache_alloc(cache, 0));
	assert(fixture.validations == validations && cache->live == count);
	objects[count] = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(objects[count] && fixture.validations == validations + 1);
	assert(kmem_cache_shrink(cache) == 1);
	for (size_t i = 0; i <= count; i++)
		kmem_cache_free(cache, objects[i]);
	assert(!kmem_cache_shrink(cache));
	kmem_cache_destroy(cache);
	check_clean();
}

static void policy_and_creation(void)
{
	const slab_flags_t unsupported_flags[] = {
		SLAB_CACHE_DMA, SLAB_CACHE_DMA32,
		SLAB_POISON, (__force slab_flags_t)(1U << 31),
	};
	for (size_t i = 0; i < ARRAY_SIZE(unsupported_flags); i++) {
		unsigned int refusals = fixture.refusals;
		assert(!__kmem_cache_create_args("unsupported", 96, NULL, unsupported_flags[i]));
		assert(fixture.refusals == refusals + 1 && !metadata_live && !caches);
	}
	struct kmem_cache_args args = {.use_freeptr_offset = true};
	assert(!__kmem_cache_create_args("freeptr", 96, &args, 0));
	args = (struct kmem_cache_args){.sheaf_capacity = 1};
	assert(!__kmem_cache_create_args("sheaves", 96, &args, 0));
	args = (struct kmem_cache_args){.align = 3};
	assert(!__kmem_cache_create_args("bad-align", 96, &args, 0));
	args = (struct kmem_cache_args){.align = 1U << 31};
	assert(!__kmem_cache_create_args("oversize-align", 96, &args, 0));
	assert(!__kmem_cache_create_args("oversize-object", UINT_MAX, NULL, 0));
	assert(!__kmem_cache_create_args("zero", 0, NULL, 0));
	assert(!__kmem_cache_create_args(NULL, 96, NULL, 0));
	assert(!__kmem_cache_create_args("", 96, NULL, 0));
	/* The disabled hardened-usercopy configuration makes these fields inert. */
	static_assert(!IS_ENABLED(CONFIG_HARDENED_USERCOPY));
	args = (struct kmem_cache_args){.useroffset = 8, .usersize = 16};
	struct kmem_cache *cache = __kmem_cache_create_args("policy", 96, &args,
							 SLAB_NO_MERGE | SLAB_NO_SHEAVES);
	assert(cache);
	void *object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	kmem_cache_free(cache, object);
	const gfp_t unsupported_requests[] = {
		GFP_ATOMIC, GFP_KERNEL | __GFP_HIGH, GFP_KERNEL | __GFP_MEMALLOC,
		GFP_KERNEL | __GFP_NOFAIL, GFP_KERNEL | __GFP_RETRY_MAYFAIL,
		GFP_KERNEL | __GFP_NORETRY, GFP_KERNEL | __GFP_RECLAIMABLE,
		GFP_KERNEL | __GFP_MOVABLE, GFP_KERNEL | __GFP_DMA,
		GFP_KERNEL | __GFP_DMA32, GFP_KERNEL | __GFP_COMP,
		GFP_KERNEL | __GFP_THISNODE, GFP_KERNEL | (__force gfp_t)(1U << 31),
	};
	unsigned int validations = fixture.validations;
	for (size_t i = 0; i < ARRAY_SIZE(unsupported_requests); i++) {
		unsigned int refusals = fixture.refusals;
		assert(!kmem_cache_alloc(cache, unsupported_requests[i]));
		assert(fixture.refusals == refusals + 1 && !cache->live);
	}
	assert(fixture.validations == validations);
	for (unsigned int context = 0; context < 4; context++) {
		unsigned long irq = 0;
		switch (context) {
		case 0: preempt_disable(); break;
		case 1: rcu_read_lock(); break;
		case 2: local_bh_disable(); break;
		case 3: irq = arch_local_irq_save(); break;
		}
		unsigned int refusals = fixture.refusals;
		assert(!kmem_cache_alloc(cache, GFP_KERNEL));
		assert(kmem_cache_shrink(cache) == -EOPNOTSUPP);
		kmem_cache_destroy(cache);
		assert(!__kmem_cache_create_args("context", 96, NULL, 0));
		assert(fixture.refusals == refusals + 4);
		void *ready = kmem_cache_alloc(cache, GFP_NOWAIT);
		assert(ready == object);
		kmem_cache_free(cache, ready);
		switch (context) {
		case 0: preempt_enable(); break;
		case 1: rcu_read_unlock(); break;
		case 2: local_bh_enable(); break;
		case 3: arch_local_irq_restore(irq); break;
		}
	}
	const gfp_t supported_requests[] = {
		GFP_KERNEL, GFP_NOWAIT, 0, GFP_KERNEL_ACCOUNT,
		GFP_KERNEL | __GFP_NOWARN, GFP_KERNEL | __GFP_NOMEMALLOC,
	};
	for (size_t i = 0; i < ARRAY_SIZE(supported_requests); i++) {
		void *ready = kmem_cache_alloc(cache, supported_requests[i]);
		assert(ready == object);
		kmem_cache_free(cache, ready);
	}
	assert(fixture.validations == validations);
	kmem_cache_destroy(cache);
	check_clean();
}

static size_t accounting_constructors;

static void accounting_ctor(void *pointer)
{
	/* Backing is charged before any constructor, including unused slots. */
	check_totals(3, 1);
	memset(pointer, 0x34, 96);
	accounting_constructors++;
}

static void reclaim_accounting(void)
{
	struct kmem_cache *plain = __kmem_cache_create_args("plain-account", 96, NULL, 0);
	struct kmem_cache_args aligned = {.align = 2 * PAGE_SIZE};
	struct kmem_cache *reclaim = __kmem_cache_create_args("reclaim-account", PAGE_SIZE + 573,
							  &aligned, SLAB_RECLAIM_ACCOUNT);
	assert(plain && reclaim && reclaim->order == 1 && reclaim->stride == 2 * PAGE_SIZE);
	check_totals(0, 0);
	const gfp_t flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_NOMEMALLOC;
	void *ordinary = kmem_cache_alloc(plain, flags);
	assert(ordinary && fixture.seen_gfp == (__force u32)(flags | __GFP_COMP));
	check_totals(0, 1);
	void *object = kmem_cache_alloc(reclaim, flags);
	assert(object && fixture.seen_order == 1);
	assert(fixture.seen_gfp == (__force u32)(flags | __GFP_COMP | __GFP_RECLAIMABLE));
	check_totals(2, 1);
	for (size_t i = 0; i < PAGE_SIZE + 573; i++)
		assert(!((u8 *)object)[i]);
	struct kmem_cache_args args = {.ctor = accounting_ctor};
	struct kmem_cache *constructed = __kmem_cache_create_args("reclaim-constructor", 96,
							       &args, SLAB_RECLAIM_ACCOUNT);
	assert(constructed);
	void *with_ctor = kmem_cache_alloc(constructed, GFP_KERNEL);
	assert(with_ctor && accounting_constructors == PAGE_SIZE / constructed->stride);
	check_totals(3, 1);
	kmem_cache_free(plain, ordinary);
	kmem_cache_free(reclaim, object);
	kmem_cache_free(constructed, with_ctor);
	check_totals(3, 1);
	/* Cache backing and its accounting outlive each borrowed owner entry. */
	const struct stela_linux_owner *original_owner = stela_linux_owner();
	const struct stela_linux_owner next_owner = *original_owner;
	stela_linux_exit();
	stela_linux_enter(&next_owner);
	check_totals(3, 1);
	stela_linux_exit();
	stela_linux_enter(original_owner);
	check_totals(3, 1);
	unsigned int validations = fixture.validations;
	rcu_read_lock();
	void *ready = kmem_cache_alloc(reclaim, GFP_NOWAIT);
	assert(ready == object && fixture.validations == validations);
	kmem_cache_free(reclaim, ready);
	check_totals(3, 1);
	rcu_read_unlock();
	assert(!kmem_cache_shrink(reclaim));
	check_totals(1, 1);
	kmem_cache_destroy(reclaim);
	kmem_cache_destroy(plain);
	check_totals(1, 0);
	kmem_cache_destroy(constructed);
	check_clean();
}

static void reclaim_failure_rollback(void)
{
	for (unsigned int class = 0; class < 2; class++) {
		slab_flags_t flags = class ? SLAB_RECLAIM_ACCOUNT : 0;
		struct kmem_cache *cache = __kmem_cache_create_args("account-rollback", PAGE_SIZE + 1,
								 NULL, flags);
		assert(cache && cache->order == 1 && metadata_live == 1);
		unsigned int releases = fixture.releases;
		metadata_fail_after = 0;
		assert(!kmem_cache_alloc(cache, GFP_KERNEL));
		assert(fixture.releases == releases + 1 && metadata_live == 1 && !cache->slabs);
		metadata_fail_after = SIZE_MAX;
		check_totals(0, 0);
		fixture.exhausted = true;
		assert(!kmem_cache_alloc(cache, GFP_KERNEL));
		fixture.exhausted = false;
		check_totals(0, 0);
		fixture.malformed = true;
		assert(!kmem_cache_alloc(cache, GFP_KERNEL));
		fixture.malformed = false;
		check_totals(0, 0);
		/* Test-only exhausted counter injection: exercise the otherwise
		 * unreachable arithmetic edge after real page+metadata acquisition. */
		size_t *counter = slab_page_counter(cache);
		*counter = SIZE_MAX - 1;
		releases = fixture.releases;
		assert(!kmem_cache_alloc(cache, GFP_KERNEL));
		assert(*counter == SIZE_MAX - 1 && fixture.releases == releases + 1);
		assert(metadata_live == 1 && !cache->slabs && !cache->growing);
		*counter = 0;
		if (class) {
			fixture.reclaimable_fallback = false;
			unsigned int attempts = fixture.attempts;
			unsigned int refusals = fixture.refusals;
			assert(!kmem_cache_alloc(cache, GFP_KERNEL));
			assert(fixture.attempts == attempts && fixture.refusals == refusals + 1);
			assert(!cache->slabs && metadata_live == 1);
			check_totals(0, 0);
			fixture.reclaimable_fallback = true;
		}
		void *object = kmem_cache_alloc(cache, GFP_KERNEL);
		assert(object);
		check_totals(class ? 2 : 0, class ? 0 : 2);
		kmem_cache_free(cache, object);
		kmem_cache_destroy(cache);
		check_clean();
	}
}

static void reclaim_rcu_and_external_pins(void)
{
	for (unsigned int class = 0; class < 2; class++) {
		struct kmem_cache *cache = __kmem_cache_create_args("account-rcu", PAGE_SIZE + 1,
			NULL, SLAB_TYPESAFE_BY_RCU | (class ? SLAB_RECLAIM_ACCOUNT : 0));
		void *object = kmem_cache_alloc(cache, GFP_KERNEL);
		assert(object && cache->order == 1);
		struct page *head = virt_to_page(object);
		struct page *tail = head + 1;
		kmem_cache_free(cache, object);
		get_page(tail);
		assert(kmem_cache_shrink(cache) == 1);
		check_totals(class ? 2 : 0, class ? 0 : 2);
		put_page(tail);
		assert(!kmem_cache_shrink(cache) && cache->pending == 1 && !cache->slabs);
		check_totals(class ? 2 : 0, class ? 0 : 2);
		/* A reader pins the detached slab before its real grace period. */
		rcu_read_lock();
		get_page(tail);
		rcu_read_unlock();
		unsigned int releases = fixture.releases;
		stela_linux_rcu_finish();
		assert(cache->slabs && !cache->pending && fixture.releases == releases);
		check_totals(class ? 2 : 0, class ? 0 : 2);
		unsigned int refusals = fixture.refusals;
		kmem_cache_destroy(cache);
		assert(fixture.refusals == refusals + 1 && !cache->destroying);
		check_totals(class ? 2 : 0, class ? 0 : 2);
		put_page(tail);
		assert(!kmem_cache_shrink(cache) && cache->pending == 1);
		check_totals(class ? 2 : 0, class ? 0 : 2);
		stela_linux_rcu_finish();
		assert(!cache->pending && !cache->slabs && fixture.releases == releases);
		check_totals(0, 0);
		stela_linux_pages_finish();
		assert(fixture.releases == releases + 1);
		kmem_cache_destroy(cache);
		check_clean();
	}
}

static void accounting_outside_owner(void)
{
	(void)stela_linux_slab_owned_pages();
}

static void panic_failure(void)
{
	metadata_fail_after = 0;
	(void)__kmem_cache_create_args("panic", 96, NULL, SLAB_PANIC);
}

static void strict_refusal(void)
{
	stela_linux_enter(&stela_linux_bare);
	(void)__kmem_cache_create_args("strict", 96, NULL, SLAB_CACHE_DMA);
}

static void outside_owner(void)
{
	(void)__kmem_cache_create_args("outside", 96, NULL, 0);
}

static void canonical_deferred_cache_free(void)
{
	struct deferred_object {
		u8 prefix[64];
		struct rcu_head head;
		u8 payload[32];
	};
	struct kmem_cache_args args = {.align = 128};
	struct kmem_cache *cache = __kmem_cache_create_args("canonical-rcu", sizeof(struct deferred_object),
		&args, SLAB_TYPESAFE_BY_RCU);
	assert(cache);
	struct deferred_object *object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	memset(object->prefix, 0x49, sizeof(object->prefix));
	memset(object->payload, 0x92, sizeof(object->payload));
	struct stela_linux_allocation allocation;
	assert(stela_linux_allocation_range(&object->head, sizeof(object->head), &allocation));
	assert(allocation.object == object && allocation.cache == cache &&
	       allocation.bytes == sizeof(*object));
	assert(!stela_linux_allocation_range((u8 *)object + sizeof(*object) - 8, 16, &allocation));
	rcu_read_lock();
	kvfree_rcu(object, head);
	assert(cache->live == 1);
	for (size_t i = 0; i < sizeof(object->prefix); i++) assert(object->prefix[i] == 0x49);
	for (size_t i = 0; i < sizeof(object->payload); i++) assert(object->payload[i] == 0x92);
	rcu_read_unlock();
	/* Destruction sets its private destroying flag then drains real callbacks.
	 * Lookup must retain and resolve this actual live slot until that drain. */
	kmem_cache_destroy(cache);
	check_clean();

	cache = __kmem_cache_create_args("canonical-kfree", sizeof(struct deferred_object), &args, 0);
	assert(cache);
	object = kmem_cache_alloc(cache, GFP_KERNEL);
	assert(object);
	unsigned long address = (unsigned long)object;
	kfree(object); /* Original public kfree accepts kmem_cache objects too. */
	assert(!cache->live && !stela_linux_allocation_range((void *)address, 1, &allocation));
	kmem_cache_destroy(cache);
	check_clean();
}

int main(void)
{
	fixture.cpu = aligned_alloc(TEST_BYTES, TEST_BYTES);
	assert(fixture.cpu);
	const struct stela_linux_services services = {.unsupported = test_unsupported};
	const struct stela_linux_owner owner = {.services = &services, .context = &fixture};
	const struct stela_linux_page_reservation reservation = {
		.generation = 1, .physical_base = TEST_PHYSICAL,
		.cpu_base = fixture.cpu, .page_count = TEST_PAGES,
	};
	fixture.reclaimable_fallback = true;
	stela_linux_enter(&owner);
	assert(!stela_linux_page_catalog_register(&reservation, &test_ops, &fixture));
	canonical_deferred_cache_free();
	constructor_and_rcu_reuse();
	alignment_and_zeroing();
	page_and_sg_lifetime();
	reference_after_rcu_detach();
	destroy_and_misuse();
	capacity_and_failures();
	policy_and_creation();
	reclaim_accounting();
	reclaim_failure_rollback();
	reclaim_rcu_and_external_pins();
	assert(stela_test_traps(panic_failure));
	check_clean();
	assert(!stela_linux_page_catalog_unregister(1));
	stela_linux_exit();
	assert(stela_test_traps(strict_refusal));
	assert(stela_test_traps(outside_owner));
	assert(stela_test_traps(accounting_outside_owner));
	free(fixture.cpu);
	printf("Linux caches: page backing, reclaim accounting, constructors, RCU/reference lifetime and policy passed\n");
	return 0;
}
#endif
