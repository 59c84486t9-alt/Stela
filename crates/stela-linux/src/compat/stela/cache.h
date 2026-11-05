/* SPDX-License-Identifier: MIT */
#ifndef STELA_CACHE_H
#define STELA_CACHE_H
#include <linux/types.h>

/* Actual opaque-cache backing, in whole base pages, including unused slots
 * and padding. Retained empty/RCU/external-reference slabs stay charged until
 * the cache relinquishes its page grant. Metadata heap bytes, raw kmalloc,
 * other catalog pins and pending native releases are outside these totals.
 * This is not the full Linux VM statistics or allocator-private slab ABI. */
struct stela_linux_slab_pages {
	size_t reclaimable;
	size_t unreclaimable;
};

/* Requires an entered serialized Linux owner; no allocation or provider call.
 * Counts persist across owner exits while actual slab backing remains owned. */
struct stela_linux_slab_pages stela_linux_slab_owned_pages(void);
/* Ensure ordinary backing has an unused slot, growing only while quiescent. */
struct kmem_cache;
bool stela_linux_cache_prime(struct kmem_cache *cache);
#endif
