// SPDX-License-Identifier: GPL-2.0-or-later
/* Linux's current task follows the native dispatcher on its one CPU. */
#include <linux/jiffies.h>
#include <linux/sched/loadavg.h>
#include <sched/sched.h>
#include <stela/linux.h>
#include <stela/task.h>

static_assert(NR_CPUS == 1);
static_assert(!IS_ENABLED(CONFIG_SMP));
static_assert(!IS_ENABLED(CONFIG_SCHED_PROXY_EXEC));

DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues) = {
	.__lock = __RAW_SPIN_LOCK_UNLOCKED(runqueues.__lock),
};

void stela_linux_rq_switch(struct task_struct *previous, struct task_struct *next)
{
	struct rq *rq = this_rq();

	/* The binding proved CPU, stack and native switch exclusion before
	 * committing. Linux can have no current on the dispatcher stack. */
	if (rcu_access_pointer(rq->curr) != previous)
		__builtin_trap();
	rcu_assign_pointer(rq->curr, next);
}

int stela_linux_rq_init_queues(const struct stela_linux_owner *owner)
{
	int error = stela_linux_require_current(owner);
	if (error)
		return error;
	if (current != &init_task || !stela_linux_quiescent())
		return -EPERM;

	struct rq *rq = this_rq();
	if (rcu_access_pointer(rq->curr) != &init_task)
		__builtin_trap();
	if (rq->cfs_tasks.next)
		return -EALREADY;

	struct rq_flags flags;
	rq_lock_irqsave(rq, &flags);
	rq->cpu = smp_processor_id();
	rq->cpu_capacity = SCHED_CAPACITY_SCALE;
	rq->calc_load_update = jiffies + LOAD_FREQ;
	rq->next_balance = jiffies;
	init_cfs_rq(&rq->cfs);
	init_rt_rq(&rq->rt);
	init_dl_rq(&rq->dl);
	INIT_LIST_HEAD(&rq->cfs_tasks);
	atomic_set(&rq->nr_iowait, 0);
	update_rq_clock(rq);
	rq_unlock_irqrestore(rq, &flags);
	return 0;
}
