// SPDX-License-Identifier: MIT
/* Linux's irq_work, with the claiming of kernel/irq_work.c. Stela's drivers
 * have no self-interrupt, so queued work runs on a worker. It keeps what hard
 * interrupt context promises the function: no sleeping, and an RCU read side
 * that outlives the function's final reference to its own irq_work. */
#include <linux/irq_work.h>
#include <linux/llist.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>

static LLIST_HEAD(queued);

static void run_queued(struct work_struct *runner)
{
	(void)runner;
	struct llist_node *first = llist_del_all(&queued);
	struct irq_work *work, *next;

	llist_for_each_entry_safe(work, next, first, node.llist) {
		int flags = atomic_read(&work->node.a_flags) & ~IRQ_WORK_PENDING;

		atomic_set(&work->node.a_flags, flags);
		rcu_read_lock();
		work->func(work);
		atomic_cmpxchg(&work->node.a_flags, flags, flags & ~IRQ_WORK_BUSY);
		rcu_read_unlock();
	}
}

static DECLARE_WORK(runner, run_queued);

bool irq_work_queue(struct irq_work *work)
{
	if (atomic_fetch_or(IRQ_WORK_CLAIMED, &work->node.a_flags) & IRQ_WORK_PENDING)
		return false;
	llist_add(&work->node.llist, &queued);
	schedule_work(&runner);
	return true;
}
