// SPDX-License-Identifier: MIT
/* Linux's kmalloc over the platform heap. Each object keeps its size and
 * alignment just below it, as a slab keeps them in its cache. Alignment is
 * kmalloc's: natural for power-of-two sizes, pages above the caches' largest
 * size and ARCH_KMALLOC_MINALIGN otherwise. Memory comes back zeroed, which
 * __GFP_ZERO asks for and plain kmalloc permits. Stela has one heap and no
 * caches, so every kmalloc_caches entry is empty and the cache a constant
 * size selects is not consulted. */
#include <linux/log2.h>
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
	if (size > KMALLOC_MAX_CACHE_SIZE)
		return PAGE_SIZE;
	if (is_power_of_2(size))
		return min_t(size_t, max_t(size_t, size, ARCH_KMALLOC_MINALIGN), PAGE_SIZE);
	return ARCH_KMALLOC_MINALIGN;
}

static void *allocate(size_t size)
{
	if (!size)
		return ZERO_SIZE_PTR;
	if (size > KMALLOC_MAX_SIZE)
		return NULL;
	size_t align = max(alignment(size), sizeof(struct header));
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
