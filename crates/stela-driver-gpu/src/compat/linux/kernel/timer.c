// SPDX-License-Identifier: MIT
/* Linux's timer lists and timed sleeps, following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/time/timer.c and
 * kernel/time/sleep_timeout.c. Pending timers are kept in expiry order. The
 * owner's service runs the expired ones (stela_linux_timers_run) when its
 * clock reaches the earliest expiry (stela_linux_timers_next) or a tick
 * passes, each in a soft-timer callback scope, as Linux's timer softirq runs
 * them. Callbacks never sleep and Linux code runs in one context at a time,
 * so no callback is ever running while another task deletes its timer: each
 * delete is also a synchronous one. */
#include <linux/jiffies.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/timer.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/timer.h>

static HLIST_HEAD(pending);

void timer_init_key(struct timer_list *timer, void (*func)(struct timer_list *),
		    unsigned int flags, const char *name, struct lock_class_key *key)
{
	(void)name;
	(void)key;
	timer->entry.pprev = NULL;
	timer->function = func;
	if (WARN_ON_ONCE(flags & ~(unsigned int)TIMER_INIT_FLAGS))
		flags &= (unsigned int)TIMER_INIT_FLAGS;
	timer->flags = flags;
}

static bool detach(struct timer_list *timer)
{
	if (!timer_pending(timer))
		return false;
	hlist_del_init(&timer->entry);
	return true;
}

/* After every pending timer that expires no later, so equal expiries run in
 * the order they were armed. */
static void enqueue(struct timer_list *timer, unsigned long expires)
{
	struct timer_list *before = NULL, *entry;
	timer->expires = expires;
	hlist_for_each_entry(entry, &pending, entry) {
		if (time_before(expires, entry->expires))
			break;
		before = entry;
	}
	if (before)
		hlist_add_behind(&timer->entry, &before->entry);
	else
		hlist_add_head(&timer->entry, &pending);
}

enum modify {
	ANY,
	ONLY_PENDING,
	ONLY_EARLIER,
};

/* Whether the timer was pending. A shut-down timer stays inactive. */
static int modify(struct timer_list *timer, unsigned long expires, enum modify how)
{
	bool was_pending = timer_pending(timer);
	if ((how == ONLY_PENDING && !was_pending) ||
	    (how == ONLY_EARLIER && was_pending && !time_before(expires, timer->expires)))
		return was_pending;
	if (!timer->function)
		return 0;
	detach(timer);
	enqueue(timer, expires);
	return was_pending;
}

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	return modify(timer, expires, ANY);
}

int mod_timer_pending(struct timer_list *timer, unsigned long expires)
{
	return modify(timer, expires, ONLY_PENDING);
}

int timer_reduce(struct timer_list *timer, unsigned long expires)
{
	return modify(timer, expires, ONLY_EARLIER);
}

void add_timer(struct timer_list *timer)
{
	if (WARN_ON_ONCE(timer_pending(timer)))
		return;
	modify(timer, timer->expires, ANY);
}

/* One CPU runs Linux code: every timer is local, and global, to it. */
void add_timer_local(struct timer_list *timer)
{
	add_timer(timer);
}

void add_timer_global(struct timer_list *timer)
{
	add_timer(timer);
}

void add_timer_on(struct timer_list *timer, int cpu)
{
	WARN_ON_ONCE(cpu != 0);
	add_timer(timer);
}

int timer_delete(struct timer_list *timer)
{
	return detach(timer);
}

int timer_delete_sync_try(struct timer_list *timer)
{
	return detach(timer);
}

int timer_delete_sync(struct timer_list *timer)
{
	return detach(timer);
}

int timer_shutdown(struct timer_list *timer)
{
	int was_pending = detach(timer);
	timer->function = NULL;
	return was_pending;
}

int timer_shutdown_sync(struct timer_list *timer)
{
	return timer_shutdown(timer);
}

bool stela_linux_timers_next(unsigned long *expires)
{
	(void)stela_linux_owner();
	bool found = stela_linux_hrtimers_next(expires);
	if (hlist_empty(&pending))
		return found;
	unsigned long first = hlist_entry(pending.first, struct timer_list, entry)->expires;
	if (!found || time_before(first, *expires))
		*expires = first;
	return true;
}

/* Like Linux's expiry, a timer a callback arms for an expiry already past
 * runs on the next pass, not this one. */
void stela_linux_timers_run(void)
{
	HLIST_HEAD(expired);
	struct hlist_node *last = NULL;
	unsigned long now = jiffies;
	while (!hlist_empty(&pending)) {
		struct timer_list *timer = hlist_entry(pending.first, struct timer_list, entry);
		if (time_before(now, timer->expires))
			break;
		hlist_del(&timer->entry);
		if (last)
			hlist_add_behind(&timer->entry, last);
		else
			hlist_add_head(&timer->entry, &expired);
		last = &timer->entry;
	}
	/* A callback may delete or rearm any timer still waiting here. */
	while (!hlist_empty(&expired)) {
		struct timer_list *timer = hlist_entry(expired.first, struct timer_list, entry);
		void (*function)(struct timer_list *) = timer->function;
		hlist_del_init(&timer->entry);
		struct stela_linux_atomic_callback scope;
		stela_linux_atomic_callback_begin_soft(&scope);
		function(timer);
		stela_linux_atomic_callback_end(&scope);
	}
	stela_linux_hrtimers_run();
}

struct process_timer {
	struct timer_list timer;
	struct task_struct *task;
};

static void process_timeout(struct timer_list *timer)
{
	wake_up_process(container_of(timer, struct process_timer, timer)->task);
}

long schedule_timeout(long timeout)
{
	if (timeout == MAX_SCHEDULE_TIMEOUT) {
		schedule();
		return timeout;
	}
	if (timeout < 0) {
		pr_err("%s: wrong timeout value %lx\n", __func__, timeout);
		dump_stack();
		__set_current_state(TASK_RUNNING);
		return 0;
	}
	unsigned long expire = (unsigned long)timeout + jiffies;
	struct process_timer timer = {.task = current};
	timer_setup_on_stack(&timer.timer, process_timeout, 0);
	timer.timer.expires = expire;
	add_timer(&timer.timer);
	schedule();
	timer_delete_sync(&timer.timer);
	timer_destroy_on_stack(&timer.timer);
	timeout = (long)(expire - jiffies);
	return timeout < 0 ? 0 : timeout;
}

long schedule_timeout_interruptible(long timeout)
{
	__set_current_state(TASK_INTERRUPTIBLE);
	return schedule_timeout(timeout);
}

long schedule_timeout_killable(long timeout)
{
	__set_current_state(TASK_KILLABLE);
	return schedule_timeout(timeout);
}

long schedule_timeout_uninterruptible(long timeout)
{
	__set_current_state(TASK_UNINTERRUPTIBLE);
	return schedule_timeout(timeout);
}

long schedule_timeout_idle(long timeout)
{
	__set_current_state(TASK_IDLE);
	return schedule_timeout(timeout);
}

/* As kernel/sched/core.c accounts it. */
long io_schedule_timeout(long timeout)
{
	int token = io_schedule_prepare();
	long ret = schedule_timeout(timeout);
	io_schedule_finish(token);
	return ret;
}
