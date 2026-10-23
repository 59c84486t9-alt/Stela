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
#include <linux/slab.h>
#include <linux/string.h>
#include <stela/linux.h>

/* The platform allocation's size and alignment; the object starts one
 * alignment into it. */
struct header {
	size_t size, align;
};

kmem_buckets kmalloc_caches[NR_KMALLOC_TYPES];

static size_t alignment(size_t size)
{
	/* Unsigned negation isolates the lowest set bit without a size-class
	 * approximation. Power-of-two requests retain their complete alignment. */
	return max_t(size_t, size & -size, ARCH_KMALLOC_MINALIGN);
}

static bool request_supported(gfp_t flags)
{
	gfp_t allowed = GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN | __GFP_NOMEMALLOC |
		__GFP_NORETRY;
	if (!IS_ENABLED(CONFIG_MEMCG))
		allowed |= __GFP_ACCOUNT;
	if (!stela_linux_quiescent() || !gfpflags_allow_blocking(flags) || (flags & ~allowed)) {
		stela_linux_unsupported("kmalloc allocation policy or context");
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
	align = max(align, sizeof(struct header));
	if (size > SIZE_MAX - align)
		return NULL;
	u8 *base = stela_linux_heap_alloc(align + size, align);
	if (!base)
		return NULL;
	struct header *header = (struct header *)(base + align) - 1;
	*header = (struct header){.size = align + size, .align = align};
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

void kfree(const void *object)
{
	if (ZERO_OR_NULL_PTR(object))
		return;
	const struct header *header = (const struct header *)object - 1;
	stela_linux_heap_free((u8 *)object - header->align, header->size, header->align);
}

char *kstrdup(const char *s, gfp_t gfp)
{
	if (!s)
		return NULL;
	size_t length = strlen(s) + 1;
	char *copy = kmalloc(length, gfp);
	if (copy)
		memcpy(copy, s, length);
	return copy;
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
	assert(!strcmp(operation, "kmalloc allocation policy or context"));
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
		GFP_KERNEL | __GFP_RETRY_MAYFAIL, GFP_KERNEL | __GFP_NOFAIL,
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
	policy_and_context();
	stela_linux_exit();
	assert(stela_test_traps(strict_refusal));
	assert(stela_test_traps(outside_owner));
	printf("Linux kmalloc: actual alignment, zeroing, live isolation, bounds and explicit policy/context refusal\n");
	return 0;
}
#endif
