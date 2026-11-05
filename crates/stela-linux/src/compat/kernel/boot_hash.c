// SPDX-License-Identifier: GPL-2.0-only
#include <linux/memblock.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <stela/page.h>
#include <system_hash.h>

/* The native catalogue supplies low memory and the owner supplies the
 * allocations, including calls from the original early VFS path. */
void *__init alloc_large_system_hash(const char *tablename, unsigned long bucketsize,
				     unsigned long numentries, int scale, int flags,
				     unsigned int *hash_shift, unsigned int *hash_mask,
				     unsigned long low_limit, unsigned long high_limit)
{
	if (!bucketsize || bucketsize > PAGE_SIZE || scale < 0 || scale >= BITS_PER_LONG - PAGE_SHIFT)
		panic("Invalid %s hash table geometry\n", tablename);

	unsigned long pages = stela_linux_page_boot_capacity();
	if (!pages)
		panic("No ordinary pages for %s hash table\n", tablename);
	unsigned long entries = system_hash_entries(bucketsize, min(numentries, 1UL << 31),
						    scale, low_limit, high_limit, pages, pages);
	if (!entries)
		panic("No memory budget for %s hash table\n", tablename);

	gfp_t gfp = GFP_KERNEL | ((flags & HASH_ZERO) ? __GFP_ZERO : 0);
	unsigned int shift = (unsigned int)ilog2(entries);
	for (;;) {
		size_t bytes;
		if (!check_mul_overflow(bucketsize, 1UL << shift, &bytes) && bytes <= INT_MAX) {
			void *table = kvmalloc(bytes, gfp);

			if (table) {
				if (hash_shift)
					*hash_shift = shift;
				if (hash_mask)
					*hash_mask = (unsigned int)((1UL << shift) - 1);
				pr_info("%s hash table entries: %lu (%zu bytes)\n",
					tablename, 1UL << shift, bytes);
				return table;
			}
			if (bytes <= PAGE_SIZE)
				break;
		}
		if (!shift)
			break;
		shift--;
	}
	panic("Failed to allocate %s hash table\n", tablename);
}
