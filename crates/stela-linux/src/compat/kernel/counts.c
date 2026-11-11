// SPDX-License-Identifier: GPL-2.0-or-later
/* Counts of the timers, work items and timeout wakes that run in the
 * environment, by function, for the host's heartbeat: which source keeps
 * waking it. Observation only; no Linux code reads them back. */
#include <linux/kthread.h>
#include <linux/sched.h>
#include <stela/counts.h>
#include "workqueue_internal.h"

struct stela_linux_counts stela_linux_counts;

void stela_linux_count(struct stela_linux_count_kind *kind, unsigned long key)
{
	/* A free slot holds zero, so one stands for no function. */
	if (!key)
		key = 1;
	for (unsigned int i = 0; i < STELA_LINUX_COUNT_SLOTS; i++) {
		struct stela_linux_count *slot = &kind->slots[i];
		unsigned long claimed = __atomic_load_n(&slot->function, __ATOMIC_RELAXED);
		if (!claimed) {
			unsigned long expected = 0;
			if (__atomic_compare_exchange_n(&slot->function, &expected, key, false,
							__ATOMIC_RELAXED, __ATOMIC_RELAXED))
				claimed = key;
			else
				claimed = expected;
		}
		if (claimed == key) {
			__atomic_fetch_add(&slot->count, 1, __ATOMIC_RELAXED);
			return;
		}
	}
	__atomic_fetch_add(&kind->other, 1, __ATOMIC_RELAXED);
}

/* The work item a worker task runs, or else its thread function. */
static unsigned long task_function(struct task_struct *task)
{
	if (task->flags & PF_WQ_WORKER) {
		const struct worker *worker = kthread_data(task);
		return worker ? (unsigned long)worker->current_func : 0;
	}
	if (task->flags & PF_KTHREAD)
		return (unsigned long)kthread_func(task);
	return 0;
}

void stela_linux_count_timeout(struct task_struct *task, bool woke)
{
	if (!woke)
		return;
	__atomic_fetch_add(&stela_linux_counts.timeouts, 1, __ATOMIC_RELAXED);
	stela_linux_count(&stela_linux_counts.sleepers, task_function(task));
}

void stela_linux_count_work(void)
{
	const struct worker *worker = current_wq_worker();
	if (worker && worker->current_func)
		stela_linux_count(&stela_linux_counts.works, (unsigned long)worker->current_func);
}
