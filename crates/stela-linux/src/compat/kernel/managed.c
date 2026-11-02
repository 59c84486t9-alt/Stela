/* SPDX-License-Identifier: MIT */
/* Owned transport for original kthread_create_info. No scheduler or WQ policy. */
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <stela/linux.h>
#include <stela/task.h>
#include <stela/managed.h>
#include <stela/managed_source.h>
struct stela_linux_managed_lease {
    const struct stela_linux_owner *owner;
    void *context;
    refcount_t refs;
    spinlock_t lock;
    bool queued, resolved, caller_returned, closed;
};
/* Supplied by the ORIGINAL derivative's one actual __kthread_create_on_node
 * implementation, not a separate worker/creator implementation. */
struct task_struct *stela_linux_original_managed_create(
    struct stela_linux_managed_lease *, int (*)(void *), void *);
static void notify(struct stela_linux_managed_lease *lease, unsigned int event, int result)
{
    stela_linux_managed_source_event(lease->context, lease, lease->owner, event, result);
}
bool stela_linux_managed_lease_get(struct stela_linux_managed_lease *lease,
    const struct stela_linux_owner *owner)
{
    unsigned long flags;
    bool got = false;
    if (!lease || lease->owner != owner)
        return false;
    spin_lock_irqsave(&lease->lock, flags);
    if (!lease->closed)
        got = refcount_inc_not_zero(&lease->refs);
    spin_unlock_irqrestore(&lease->lock, flags);
    return got;
}
void stela_linux_managed_lease_put(struct stela_linux_managed_lease *lease,
    const struct stela_linux_owner *owner)
{
    unsigned long flags;
    bool joined = false;
    if (!lease || lease->owner != owner)
        __builtin_trap();
    spin_lock_irqsave(&lease->lock, flags);
    /* Only Rust's actual initial owner may consume the final reference in the
     * checked source release below. Producer put never frees a context inline. */
    if (refcount_read(&lease->refs) <= 1)
        __builtin_trap();
    refcount_dec(&lease->refs);
    if (refcount_read(&lease->refs) == 1 && lease->resolved &&
        lease->caller_returned && !lease->closed) {
        lease->closed = true;
        joined = true;
    }
    spin_unlock_irqrestore(&lease->lock, flags);
    if (joined)
        notify(lease, STELA_MANAGED_PRODUCERS_JOINED, 0);
}
void *stela_linux_managed_lease_context(struct stela_linux_managed_lease *lease,
    const struct stela_linux_owner *owner)
{
    if (!lease || lease->owner != owner || !refcount_read(&lease->refs))
        __builtin_trap();
    return lease->context;
}
void stela_linux_managed_native_retired(struct stela_linux_managed_lease *lease,
    const struct stela_linux_owner *owner)
{
    if (!lease || lease->owner != owner)
        __builtin_trap();
    /* Actual source-side native record release, not a taskptr/PID inference. */
    notify(lease, STELA_MANAGED_NATIVE_RETIRED, 0);
}
void stela_linux_managed_source_get(struct stela_linux_managed_lease *lease)
{
    if (!stela_linux_managed_lease_get(lease, lease->owner))
        __builtin_trap();
}
void stela_linux_managed_source_put(struct stela_linux_managed_lease *lease)
{
    stela_linux_managed_lease_put(lease, lease->owner);
}
void stela_linux_managed_source_queued(struct stela_linux_managed_lease *lease)
{
    unsigned long flags;
    spin_lock_irqsave(&lease->lock, flags);
    if (lease->queued || lease->closed)
        __builtin_trap();
    lease->queued = true;
    spin_unlock_irqrestore(&lease->lock, flags);
}
void stela_linux_managed_source_outcome(struct stela_linux_managed_lease *lease,
    unsigned int event, int result)
{
    unsigned long flags;
    spin_lock_irqsave(&lease->lock, flags);
    if (lease->closed)
        __builtin_trap();
    if (event == STELA_MANAGED_CREATE_FAILED || event == STELA_MANAGED_CHILD_ABANDONED)
        lease->resolved = true;
    spin_unlock_irqrestore(&lease->lock, flags);
    notify(lease, event, result);
}
int stela_linux_managed_create(const struct stela_linux_owner *owner, void *context,
    int (*threadfn)(void *), struct stela_linux_managed_lease **output)
{
    struct stela_linux_managed_lease *lease;
    struct task_struct *task;
    unsigned long flags;
    int result;
    if (!output)
        __builtin_trap();
    *output = NULL;
    if (!context || !threadfn || stela_linux_require_current(owner) ||
        !stela_linux_quiescent())
        return -EPERM;
    lease = kzalloc_obj(*lease);
    if (!lease)
        return -ENOMEM; /* exact no C owner/create_info accepted */
    lease->owner = owner;
    lease->context = context;
    refcount_set(&lease->refs, 1); /* retained Rust-owned context */
    spin_lock_init(&lease->lock);
    *output = lease; /* before ANY actual source constructor/callback */
    stela_linux_managed_source_get(lease); /* real calling source frame */
    task = stela_linux_original_managed_create(lease, threadfn, context);
    /* IS_ERR restricts PTR_ERR to Linux's representable -MAX_ERRNO..-1. */
    result = IS_ERR(task) ? (int)PTR_ERR(task) : 0;
    if (!IS_ERR(task)) {
        /* Borrowed ORIGINAL create_info result, never Rust task adoption.
         * Child is parked before its first wake; pin only through real wake. */
        get_task_struct(task);
        spin_lock_irqsave(&lease->lock, flags);
        lease->resolved = true;
        spin_unlock_irqrestore(&lease->lock, flags);
        wake_up_process(task);
        put_task_struct(task); /* do NOT retain this across source_freed join */
    } else {
        spin_lock_irqsave(&lease->lock, flags);
        /* Source prequeue branch, not errno->NoChild. EINTR with queued=true
         * leaves late kthreadd/child outcomes and refs fully retained. */
        if (!lease->queued)
            lease->resolved = true;
        spin_unlock_irqrestore(&lease->lock, flags);
    }
    spin_lock_irqsave(&lease->lock, flags);
    lease->caller_returned = true;
    spin_unlock_irqrestore(&lease->lock, flags);
    notify(lease, STELA_MANAGED_CALLER_RETURNED, result);
    stela_linux_managed_source_put(lease); /* event only after real frame close */
    return result;
}
int stela_linux_managed_lease_release(struct stela_linux_managed_lease *lease,
    const struct stela_linux_owner *owner)
{
    unsigned long flags;
    if (stela_linux_require_current(owner) || !stela_linux_quiescent())
        return -EPERM;
    if (!lease || lease->owner != owner)
        return -EINVAL;
    spin_lock_irqsave(&lease->lock, flags);
    /* Actual one-shot source closure AND initial-owner uniqueness; the count
     * alone proves neither no child nor native/source callback completion. */
    if (!lease->closed || !lease->resolved || !lease->caller_returned ||
        refcount_read(&lease->refs) != 1) {
        spin_unlock_irqrestore(&lease->lock, flags);
        return -EAGAIN;
    }
    refcount_set(&lease->refs, 0);
    spin_unlock_irqrestore(&lease->lock, flags);
    kfree(lease); /* caller has independently joined any actual native child */
    return 0;
}
