// SPDX-License-Identifier: GPL-2.0-or-later
/* Share one measured runtime between Linux scheduler classes and Runtime. */
#include <sched/sched.h>
#include <stela/linux.h>
#include <stela/task.h>

/* The native profile has one task entity and no group, trace, or cache
 * accounting side effects from fair.c's update_se(). */
static_assert(!IS_ENABLED(CONFIG_SCHED_PROXY_EXEC));
static_assert(!IS_ENABLED(CONFIG_FAIR_GROUP_SCHED));
static_assert(!IS_ENABLED(CONFIG_SCHED_CACHE));
static_assert(!IS_ENABLED(CONFIG_TRACEPOINTS));
static_assert(!IS_ENABLED(CONFIG_POSIX_TIMERS));
static_assert(!IS_ENABLED(CONFIG_CGROUPS));
static_assert(!IS_ENABLED(CONFIG_SCHEDSTATS));

s64 update_curr_common(struct rq *rq)
{
	if (rq != this_rq())
		stela_linux_fatal("class accounting on a foreign runqueue");
	lockdep_assert_rq_held(rq);
	s64 delta = stela_linux_task_account_class(rq->curr);
	/* exec_start uses the Linux runqueue clock. The Runtime sample's
	 * accounted-through timestamp belongs to the native clock. */
	if (delta > 0)
		rq->curr->se.exec_start = rq_clock_task(rq);
	return delta;
}
