/* SPDX-License-Identifier: MIT */
#ifndef STELA_ALLOCATION_H
#define STELA_ALLOCATION_H
#include <linux/numa.h>
#include <linux/types.h>

/* The selected slab profile has one physical memory node. */
static inline bool stela_linux_slab_node_supported(int node)
{
 return node == NUMA_NO_NODE || node == 0;
}

struct kmem_cache;
struct rcu_head;
/* Borrowed only during the same serialized entered operation. Descriptors
 * come from actual live allocator metadata; constructing one grants nothing.
 * Logical bytes exclude allocator headers, alignment and cache-stride padding.
 */
struct stela_linux_allocation {
 void *object;
 size_t bytes;
 struct kmem_cache *cache;
};
bool stela_linux_kmalloc_range(const void *, size_t, struct stela_linux_allocation *);
bool stela_linux_cache_range(const void *, size_t, struct stela_linux_allocation *);
bool stela_linux_allocation_range(const void *, size_t, struct stela_linux_allocation *);
/* True only for the exact callback currently invoked after an actual grace
 * period by the private RCU drain. No caller can publish/reset this state. */
bool stela_linux_rcu_callback_current(const struct rcu_head *);
#endif
