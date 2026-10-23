// SPDX-License-Identifier: MIT
/* Linux's kmalloc over the platform heap. Each object keeps its size and
 * alignment just below it, as a slab keeps them in its cache. Alignment is
 * kmalloc's: at least the greatest power-of-two divisor of the size and
 * ARCH_KMALLOC_MINALIGN. Memory comes back zeroed, which
 * __GFP_ZERO asks for and plain kmalloc permits. Stela has one heap and no
 * caches, so every kmalloc_caches entry is empty and the cache a constant
 * size selects is not consulted. */
#include <linux/limits.h>
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

static void *allocate(size_t size)
{
	if (!size)
		return ZERO_SIZE_PTR;
	if (size > KMALLOC_MAX_SIZE)
		return NULL;
	size_t align = max(alignment(size), sizeof(struct header));
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
	(void)flags;
	return allocate(size);
}

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t flags, size_t size)
{
	(void)s;
	(void)flags;
	return allocate(size);
}

void *__kmalloc_large_noprof(size_t size, gfp_t flags)
{
	(void)flags;
	return allocate(size);
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
#include <stela/test.h>

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
	assert(__kmalloc_large_noprof(0, GFP_KERNEL) == ZERO_SIZE_PTR);
	assert(!__kmalloc_noprof(KMALLOC_MAX_SIZE + 1, GFP_KERNEL));
	assert(!__kmalloc_noprof(SIZE_MAX, GFP_KERNEL));
	kfree(NULL);
	kfree(ZERO_SIZE_PTR);
	char *copy = kstrdup("alignment", GFP_KERNEL);
	assert(copy && !strcmp(copy, "alignment"));
	kfree(copy);
	assert(!kstrdup(NULL, GFP_KERNEL));
	printf("Linux kmalloc: actual alignment, zeroing, live isolation and bounds\n");
	return 0;
}
#endif
