// SPDX-License-Identifier: MIT
/* Linux's kmalloc over the platform heap. Each object keeps its size and
 * alignment just below it, as a slab keeps them in its cache. Alignment is
 * kmalloc's: at least the greatest power-of-two divisor of the size and
 * ARCH_KMALLOC_MINALIGN. Memory comes back zeroed, which
 * __GFP_ZERO asks for and plain kmalloc permits. These raw allocations use
 * one heap; their kmalloc_caches entries remain empty and the bucket a
 * constant size selects is not consulted. Explicit kmem_cache handles use
 * the separate page-backed public cache service. */
#include <linux/limits.h>
#include <linux/gfp.h>
#include <linux/minmax.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/log2.h>
#include <stela/allocation.h>
#include <linux/string.h>
#include <stela/linux.h>

/* The platform allocation's size and alignment; the object starts one
 * alignment into it. */
struct header {
 size_t size, align;
 struct rb_node node;
};

/* Only actual canonical allocations enter this index. No candidate pointer
 * is dereferenced to decide ownership; original Linux rbtree owns balancing.
 * The one entered UP owner excludes concurrent mutation and native ISR entry.
 */
static struct rb_root allocations = RB_ROOT;

static void index_allocation(struct header *header)
{
 struct rb_node **link = &allocations.rb_node, *parent = NULL;
 unsigned long address = (unsigned long)(header + 1);
 while (*link) {
  parent = *link;
  struct header *entry = rb_entry(parent, struct header, node);
  unsigned long key = (unsigned long)(entry + 1);
  if (address == key) __builtin_trap();
  link = address < key ? &parent->rb_left : &parent->rb_right;
 }
 rb_link_node(&header->node, parent, link);
 rb_insert_color(&header->node, &allocations);
}

bool stela_linux_kmalloc_range(const void *pointer, size_t bytes,
                              struct stela_linux_allocation *out)
{
 (void)stela_linux_owner();
 struct rb_node *node = allocations.rb_node;
 struct header *found = NULL;
 unsigned long address = (unsigned long)pointer;
 while (node) {
  struct header *entry = rb_entry(node, struct header, node);
  if (address < (unsigned long)(entry + 1)) node = node->rb_left;
  else { found = entry; node = node->rb_right; }
 }
 if (!found) return false;
 unsigned long base = (unsigned long)(found + 1);
 size_t logical = found->size - found->align, offset = address - base;
 if (offset >= logical || bytes > logical - offset) return false;
 *out = (struct stela_linux_allocation){.object = found + 1, .bytes = logical};
 return true;
}

kmem_buckets kmalloc_caches[NR_KMALLOC_TYPES];

static size_t alignment(size_t size)
{
	/* Unsigned negation isolates the lowest set bit without a size-class
	 * approximation. Power-of-two requests retain their complete alignment. */
	return max_t(size_t, size & -size, ARCH_KMALLOC_MINALIGN);
}

static bool request_supported(gfp_t flags)
{
	gfp_t allowed = GFP_USER | __GFP_HIGH | __GFP_ZERO | __GFP_NOWARN | __GFP_NOMEMALLOC |
		__GFP_NORETRY | __GFP_RETRY_MAYFAIL;
	if (!IS_ENABLED(CONFIG_MEMCG))
		allowed |= __GFP_ACCOUNT;
	bool quiescent = stela_linux_quiescent();
	bool may_block = gfpflags_allow_blocking(flags);
	if ((flags & ~allowed) || (may_block && !quiescent)) {
		stela_linux_unsupported("kmalloc allocation policy or context");
		return false;
	}
	if (!may_block && !stela_linux_heap_try_available()) {
		stela_linux_unsupported("kmalloc nonblocking canonical heap unavailable");
		return false;
	}
	return true;
}

static void *allocate(size_t size, gfp_t flags, size_t minimum_align)
{
	if (!size)
		return ZERO_SIZE_PTR;
	if (size > KMALLOC_MAX_SIZE)
		return NULL;
	if (!request_supported(flags))
		return NULL;
	size_t align = max(alignment(size), minimum_align);
	align = max(align, roundup_pow_of_two(sizeof(struct header)));
	if (size > SIZE_MAX - align)
		return NULL;
	u8 *base = gfpflags_allow_blocking(flags) ?
		stela_linux_heap_alloc(align + size, align) :
		stela_linux_heap_try_alloc(align + size, align);
	if (!base)
		return NULL;
	struct header *header = (struct header *)(base + align) - 1;
	*header = (struct header){.size = align + size, .align = align};
	index_allocation(header);
	return base + align;
}

void *__kmalloc_noprof(DECL_TOKEN_PARAMS(size, token), gfp_t flags)
{
	return allocate(size, flags, ARCH_KMALLOC_MINALIGN);
}

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t flags, size_t size)
{
	(void)s;
	return allocate(size, flags, ARCH_KMALLOC_MINALIGN);
}

void *__kmalloc_large_noprof(size_t size, gfp_t flags)
{
	/* kmalloc handles zero before selecting this internal entry. Its page
	 * alignment declaration cannot admit the ordinary ZERO_SIZE_PTR. */
	if (!size)
		return NULL;
	/* The public declaration lets the optimizer assume page alignment, even
	 * for a direct call whose size would ordinarily select a small bucket. */
	return allocate(size, flags, PAGE_SIZE);
}

/* This native raw allocator's bucket is its exact logical capacity, not
 * SLUB's private size-class table. No header/alignment padding is exposed. */
size_t kmalloc_size_roundup(size_t size)
{
 return size;
}

/* This is the genuine !NUMA, !profiling placement/debug policy. Zone,
 * reserve/no-fail and nonblocking requests still pass allocate's actual
 * canonical policy checks; no flags are masked away here. */
static_assert(!IS_ENABLED(CONFIG_NUMA));
static_assert(!IS_ENABLED(CONFIG_SLAB_BUCKETS));
static_assert(!IS_ENABLED(CONFIG_MEM_ALLOC_PROFILING));
void *__kmalloc_node_track_caller_noprof(DECL_KMALLOC_PARAMS(size, b, token),
                                       gfp_t flags, int node, unsigned long caller)
{
 (void)node;
 (void)caller;
 return allocate(size, flags, ARCH_KMALLOC_MINALIGN);
}

/* A fresh object unless the old one already fits, as mm/slub.c; a growing
 * __GFP_ZERO caller gets zeroes past the old bytes. */
void *krealloc_node_align_noprof(const void *object, DECL_TOKEN_PARAMS(new_size, token),
				 unsigned long align, gfp_t flags, int node)
{
	(void)node;
	if (!new_size) {
		kfree(object);
		return ZERO_SIZE_PTR;
	}
	if (WARN_ON_ONCE(align > ARCH_KMALLOC_MINALIGN))
		return NULL;
	size_t old_size = ksize(object);
	if (new_size <= old_size)
		return (void *)object;
	void *fresh = __kmalloc_noprof(PASS_TOKEN_PARAMS(new_size, token), flags);
	if (fresh && old_size) {
		memcpy(fresh, object, old_size);
		kfree(object);
	}
	return fresh;
}

size_t ksize(const void *object)
{
 if (ZERO_OR_NULL_PTR(object))
  return 0;
 struct stela_linux_allocation allocation;
 if ((!stela_linux_kmalloc_range(object, 1, &allocation) &&
      !stela_linux_cache_range(object, 1, &allocation)) || allocation.object != object) {
  /* The original API requires a live allocation. Refuse foreign, interior
   * and freed addresses without inspecting their preceding bytes. */
  WARN_ON_ONCE(1);
  return 0;
 }
 return allocation.bytes;
}

void kfree(const void *object)
{
	if (ZERO_OR_NULL_PTR(object))
		return;
 struct stela_linux_allocation allocation;
 if (!stela_linux_kmalloc_range(object, 1, &allocation) || allocation.object != object) {
  if (stela_linux_cache_range(object, 1, &allocation) && allocation.object == object) {
   kmem_cache_free(allocation.cache, allocation.object);
   return;
  }
  __builtin_trap();
 }
 struct header *header = (struct header *)allocation.object - 1;
 rb_erase(&header->node, &allocations);
 stela_linux_heap_free((u8 *)object - header->align, header->size, header->align);
}

/* The duplication helpers follow Linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8
 * mm/util.c. */
static char *duplicate_string(const char *s, size_t len, gfp_t gfp)
{
	char *copy = kmalloc(len + 1, gfp);
	if (!copy)
		return NULL;
	memcpy(copy, s, len);
	copy[len] = '\0';
	return copy;
}

char *kstrdup(const char *s, gfp_t gfp)
{
	return s ? duplicate_string(s, strlen(s), gfp) : NULL;
}

char *kstrndup(const char *s, size_t max, gfp_t gfp)
{
	return s ? duplicate_string(s, strnlen(s, max), gfp) : NULL;
}

char *kmemdup_nul(const char *s, size_t len, gfp_t gfp)
{
	return s ? duplicate_string(s, len, gfp) : NULL;
}

void *kmemdup_noprof(const void *src, size_t len, gfp_t gfp)
{
	void *copy = kmalloc(len, gfp);
	if (copy)
		memcpy(copy, src, len);
	return copy;
}

void *kmemdup_array(const void *src, size_t count, size_t element_size, gfp_t gfp)
{
	return kmemdup(src, size_mul(element_size, count), gfp);
}

#ifdef STELA_LINUX_SLAB_TEST
#include <linux/bottom_half.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <stela/test.h>

static unsigned int refusals;

static void unsupported(void *context, const char *operation)
{
	(void)context;
	assert(!strcmp(operation, "kmalloc allocation policy or context") ||
	       !strcmp(operation, "kmalloc nonblocking canonical heap unavailable"));
	refusals++;
}

static void check_refusal(gfp_t flags)
{
	unsigned int before = refusals;
	assert(!__kmalloc_noprof(96, flags));
	assert(!__kmalloc_cache_noprof(NULL, flags, 96));
	assert(!__kmalloc_large_noprof(96, flags));
	assert(refusals == before + 3);
}

static void policy_and_context(void)
{
	const gfp_t refused[] = {
		GFP_ATOMIC, GFP_NOWAIT, 0,
		GFP_KERNEL | __GFP_DMA, GFP_KERNEL | __GFP_DMA32,
		GFP_KERNEL | __GFP_RECLAIMABLE, GFP_KERNEL | __GFP_MOVABLE,
		GFP_KERNEL | __GFP_COMP, GFP_KERNEL | __GFP_MEMALLOC,
		GFP_KERNEL | __GFP_NOFAIL,
		GFP_KERNEL | __GFP_THISNODE,
		GFP_KERNEL | (__force gfp_t)(1U << 31),
	};
	for (size_t i = 0; i < ARRAY_SIZE(refused); i++)
		check_refusal(refused[i]);
	preempt_disable();
	check_refusal(GFP_KERNEL);
	preempt_enable();
	rcu_read_lock();
	check_refusal(GFP_KERNEL);
	rcu_read_unlock();
	local_bh_disable();
	check_refusal(GFP_KERNEL);
	local_bh_enable();
	unsigned long irq = arch_local_irq_save();
	check_refusal(GFP_KERNEL);
	arch_local_irq_restore(irq);
	const gfp_t admitted[] = {
		GFP_KERNEL, GFP_KERNEL | __GFP_ZERO, GFP_KERNEL | __GFP_NOWARN,
		GFP_KERNEL | __GFP_NOMEMALLOC, GFP_KERNEL | __GFP_NORETRY,
		GFP_KERNEL_ACCOUNT,
	};
	unsigned int before = refusals;
	for (size_t i = 0; i < ARRAY_SIZE(admitted); i++) {
		void *object = __kmalloc_noprof(96, admitted[i]);
		assert(object);
		kfree(object);
	}
	assert(refusals == before && stela_linux_quiescent());
}

static void strict_refusal(void)
{
	stela_linux_enter(&stela_linux_bare);
	void *object = __kmalloc_noprof(96, GFP_ATOMIC);
	kfree(object);
	stela_linux_exit();
}

static void check_nonblocking_allocation(void)
{
	unsigned int before = refusals;
	u8 *object = __kmalloc_noprof(128, GFP_NOWAIT | __GFP_ZERO);
	assert(object && stela_test_heap_try_contains(object));
	assert((unsigned long)object % 128 == 0);
	for (size_t i = 0; i < 128; i++)
		assert(!object[i]);
	memset(object, 0xa5, 128);
	/* The bounded model has one actual preallocated span. An ordinary heap
	 * fallback would incorrectly succeed and is caught by this failure. */
	assert(!__kmalloc_noprof(128, GFP_NOWAIT));
	assert(!__kmalloc_cache_noprof(NULL, GFP_NOWAIT, 128));
	assert(!__kmalloc_large_noprof(128, GFP_NOWAIT));
	assert(refusals == before);
	for (size_t i = 0; i < 128; i++)
		assert(object[i] == 0xa5);
	kfree(object);
	object = __kmalloc_cache_noprof(NULL, GFP_NOWAIT, 128);
	assert(object && stela_test_heap_try_contains(object));
	for (size_t i = 0; i < 128; i++)
		assert(!object[i]);
	kfree(object);
	object = __kmalloc_large_noprof(128, GFP_NOWAIT);
	assert(object && stela_test_heap_try_contains(object));
	assert((unsigned long)object % PAGE_SIZE == 0);
	kfree(object);
	assert(refusals == before);
}

static void nonblocking_policy_and_context(void)
{
	assert(!stela_linux_heap_try_available());
	stela_test_heap_try_enable(true);
	assert(stela_linux_heap_try_available());
	check_nonblocking_allocation();
	preempt_disable();
	check_nonblocking_allocation();
	preempt_enable();
	rcu_read_lock();
	check_nonblocking_allocation();
	rcu_read_unlock();
	local_bh_disable();
	check_nonblocking_allocation();
	local_bh_enable();
	unsigned long irq = arch_local_irq_save();
	check_nonblocking_allocation();
	arch_local_irq_restore(irq);
	unsigned int before = refusals;
	const gfp_t flags[] = {
		0, GFP_NOWAIT | __GFP_NOWARN | __GFP_NOMEMALLOC | __GFP_NORETRY,
		GFP_NOWAIT | __GFP_ACCOUNT, GFP_ATOMIC,
	};
	for (size_t i = 0; i < ARRAY_SIZE(flags); i++) {
		void *object = __kmalloc_noprof(128, flags[i]);
		assert(object && stela_test_heap_try_contains(object));
		kfree(object);
	}
	assert(refusals == before);
	check_refusal(GFP_NOWAIT | __GFP_RECLAIMABLE);
	check_refusal(GFP_NOWAIT | __GFP_MOVABLE);
	stela_test_heap_try_enable(false);
	assert(!stela_linux_heap_try_available() && stela_linux_quiescent());
	check_refusal(GFP_NOWAIT);
}

static void outside_owner(void)
{
	void *object = __kmalloc_noprof(96, GFP_KERNEL);
	kfree(object);
}

static void check_allocation(size_t size)
{
	void *objects[] = {
		__kmalloc_noprof(size, GFP_KERNEL),
		__kmalloc_cache_noprof(NULL, GFP_KERNEL, size),
		__kmalloc_large_noprof(size, GFP_KERNEL),
	};
	/* An independent divisibility calculation exercises actual addresses,
	 * rather than checking the alignment helper against itself. */
	size_t divisor = 1;
	for (size_t remaining = size; !(remaining & 1); remaining >>= 1)
		divisor *= 2;
	for (size_t i = 0; i < ARRAY_SIZE(objects); i++) {
		u8 *object = objects[i];
		assert(object && (unsigned long)object % divisor == 0);
		assert((unsigned long)object % ARCH_KMALLOC_MINALIGN == 0);
		if (i == 2)
			assert((unsigned long)object % PAGE_SIZE == 0);
		const struct header *metadata = (const struct header *)object - 1;
		assert(metadata->size == metadata->align + size);
		assert((unsigned long)(object - metadata->align) % metadata->align == 0);
		for (size_t j = 0; j < size; j++)
			assert(!object[j]);
		memset(object, (int)i + 1, size);
	}
	for (size_t i = 0; i < ARRAY_SIZE(objects); i++) {
		u8 *object = objects[i];
		for (size_t j = 0; j < size; j++)
			assert(object[j] == i + 1);
		kfree(object);
	}
}

int main(void)
{
	const struct stela_linux_services services = {.unsupported = unsupported};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	/* Includes 96/192-byte callers, both sides of every relevant power of
	 * two, and requests above the old PAGE_SIZE and cache-size caps. */
	for (size_t size = 1; size <= 256; size++)
		check_allocation(size);
	for (size_t power = 512; power <= KMALLOC_MAX_SIZE; power *= 2) {
		check_allocation(power - 1);
		check_allocation(power);
		if (power < KMALLOC_MAX_SIZE)
			check_allocation(power + 1);
	}
	assert(__kmalloc_noprof(0, GFP_KERNEL) == ZERO_SIZE_PTR);
	assert(__kmalloc_cache_noprof(NULL, GFP_KERNEL, 0) == ZERO_SIZE_PTR);
	assert(!__kmalloc_large_noprof(0, GFP_KERNEL));
	assert(!__kmalloc_noprof(KMALLOC_MAX_SIZE + 1, GFP_KERNEL));
	assert(!__kmalloc_noprof(SIZE_MAX, GFP_KERNEL));
	kfree(NULL);
	kfree(ZERO_SIZE_PTR);
	char *copy = kstrdup("alignment", GFP_KERNEL);
	assert(copy && !strcmp(copy, "alignment"));
	kfree(copy);
	assert(!kstrdup(NULL, GFP_KERNEL));
	copy = kstrndup("alignment", 5, GFP_KERNEL);
	assert(copy && !strcmp(copy, "align"));
	kfree(copy);
	copy = kstrndup("tail", 16, GFP_KERNEL);
	assert(copy && !strcmp(copy, "tail"));
	kfree(copy);
	assert(!kstrndup(NULL, 4, GFP_KERNEL));
	const char unterminated[3] = {'n', 'u', 'l'};
	copy = kmemdup_nul(unterminated, sizeof(unterminated), GFP_KERNEL);
	assert(copy && !strcmp(copy, "nul"));
	kfree(copy);
	const u8 bytes[5] = {1, 0, 2, 0, 3};
	u8 *duplicate = kmemdup(bytes, sizeof(bytes), GFP_KERNEL);
	assert(duplicate && !memcmp(duplicate, bytes, sizeof(bytes)));
	kfree(duplicate);
	const u16 words[] = {0x102, 0, 0x304};
	u16 *array = kmemdup_array(words, ARRAY_SIZE(words), sizeof(*words), GFP_KERNEL);
	assert(array && array != words && !memcmp(array, words, sizeof(words)));
	kfree(array);
	assert(kmemdup_array(words, 0, sizeof(*words), GFP_KERNEL) == ZERO_SIZE_PTR);
	assert(!kmemdup_array(words, SIZE_MAX, sizeof(*words), GFP_KERNEL));
	policy_and_context();
	nonblocking_policy_and_context();
	stela_linux_exit();
	assert(stela_test_traps(strict_refusal));
	assert(stela_test_traps(outside_owner));
	printf("Linux kmalloc: actual alignment, zeroing, live isolation, bounds and explicit policy/context refusal\n");
	return 0;
}
#endif
