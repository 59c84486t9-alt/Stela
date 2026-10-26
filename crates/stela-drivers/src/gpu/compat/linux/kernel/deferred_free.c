// SPDX-License-Identifier: MIT
/* Canonical native allocation lookup and actual RCU retirement. No Linux
 * allocator-private slab/page/vmalloc layout is assigned to native storage. */
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <stela/allocation.h>
#include <stela/linux.h>

void stela_original_kvfree_call_rcu(struct rcu_head *, void *);
void kvfree_rcu_cb(struct rcu_head *);

bool stela_linux_allocation_range(const void *pointer, size_t bytes,
                                 struct stela_linux_allocation *out)
{
 return stela_linux_kmalloc_range(pointer, bytes, out) ||
        stela_linux_cache_range(pointer, bytes, out);
}

void kvfree(const void *pointer)
{
 /* kfree resolves actual canonical raw-heap and opaque-cache allocations.
  * There is no native vmalloc producer or fabricated page classification. */
 kfree(pointer);
}

void kvfree_rcu_cb(struct rcu_head *head)
{
 struct stela_linux_allocation allocation;
 if (!stela_linux_rcu_callback_current(head) ||
     !stela_linux_allocation_range(head, sizeof(*head), &allocation) ||
     (unsigned long)head - (unsigned long)allocation.object >= 4096)
  __builtin_trap();
 kvfree(allocation.object);
}

void kvfree_call_rcu(struct rcu_head *head, void *pointer)
{
 (void)stela_linux_owner();
 if (head) {
  struct stela_linux_allocation allocation;
  if (!stela_linux_allocation_range(head, sizeof(*head), &allocation) ||
      allocation.object != pointer ||
      (unsigned long)head - (unsigned long)pointer >= 4096)
   __builtin_trap();
 } else {
  /* might_sleep is diagnostic in a non-debug Linux image; the native boundary
   * must reject an actual reader/atomic callback before grace/free effects. */
  if (!stela_linux_quiescent()) __builtin_trap();
  if (!ZERO_OR_NULL_PTR(pointer)) {
   struct stela_linux_allocation allocation;
   if (!stela_linux_allocation_range(pointer, 1, &allocation) ||
       allocation.object != pointer) __builtin_trap();
  }
 }
 stela_original_kvfree_call_rcu(head, pointer);
}
