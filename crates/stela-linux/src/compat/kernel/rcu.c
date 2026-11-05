// SPDX-License-Identifier: MIT
/* Context/lifetime checks around the selected original TinyRCU engine. */
#include <linux/interrupt.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <stela/atomic_callback.h>
#include <stela/allocation.h>
#include <stela/linux.h>
#include <stela/rcu.h>
#include <stela/task.h>

static_assert(IS_ENABLED(CONFIG_TINY_RCU));
static_assert(IS_ENABLED(CONFIG_TINY_SRCU));
static_assert(IS_ENABLED(CONFIG_PREEMPT_NONE));
static_assert(IS_ENABLED(CONFIG_PREEMPT_COUNT));
static_assert(!IS_ENABLED(CONFIG_SMP));
static_assert(!IS_ENABLED(CONFIG_PREEMPT_RT));

/* The original callback may free head. Save identity only; end never reads it.
 * The process/stack/lease and loaded callback image remain owned by the actual
 * Initial/Managed task and canonical KernelOwner, not this borrowed observer. */
static struct {
	const struct rcu_head *head;
	struct task_struct *task;
	struct stela_linux_lease lease;
	int count;
} callback;

bool stela_linux_rcu_callback_active(void)
{
	return callback.head != NULL;
}

bool stela_linux_rcu_callback_current(const struct rcu_head *head)
{
	return head && callback.head == head &&
	       stela_linux_atomic_softirq_dispatch_active() &&
	       stela_linux_current() == callback.task &&
	       preempt_count() == callback.count &&
	       stela_linux_lease_matches(&callback.lease);
}

void stela_linux_rcu_require_process(void)
{
	if (stela_linux_require_current(stela_linux_owner()) ||
	    !stela_linux_quiescent())
		__builtin_trap();
}

void stela_linux_rcu_callback_begin(const struct rcu_head *head)
{
	if (!head || callback.head ||
	    !stela_linux_atomic_softirq_dispatch_active() ||
	    ((unsigned int)preempt_count() & ~PREEMPT_MASK) != SOFTIRQ_OFFSET ||
	    irqs_disabled() || stela_linux_require_current(stela_linux_owner()))
		__builtin_trap();
	callback.head = head;
	callback.task = stela_linux_current();
	callback.count = preempt_count();
	stela_linux_lease_snapshot(&callback.lease);
}

void stela_linux_rcu_callback_end(const struct rcu_head *head)
{
	if (!stela_linux_rcu_callback_current(head))
		__builtin_trap();
	callback = (typeof(callback)){};
}

void stela_linux_rcu_finish(void)
{
	/* Explicit destruction boundary only. This is the original sentinel join
	 * of callbacks already queued, NOT all future self-enqueued generations.
	 * Stop/join every callback producer and retain callback data/code until its
	 * actual last callback completes. Scheduler/owner exit must not call this:
	 * the real completion wait may suspend this same retained source stack. */
	stela_linux_rcu_require_process();
	rcu_barrier();
}
