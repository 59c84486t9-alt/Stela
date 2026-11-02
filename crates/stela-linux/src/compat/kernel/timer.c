// SPDX-License-Identifier: MIT
/* Timer-list API of original Linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8
 * kernel/time/timer.c and sleep_timeout.c. The qualified real service source
 * runs due callbacks in original softirq nesting. Selected !NO_HZ_COMMON uses
 * one timer base, including deferrable timers; real HZ_PERIODIC tick delivery
 * and original accounting remain required producers, not a queue/idle bool.
 * Serialized nonblocking callback delivery makes a running self-join explicit
 * rather than fabricating a synchronous cancellation receipt. */
#include <linux/jiffies.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/timer.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/timer.h>
#include <stela/time.h>
#include <linux/limits.h>

static HLIST_HEAD(pending);
static const struct timer_list *running_timer;

void timer_init_key(struct timer_list *timer, void (*func)(struct timer_list *),
		    unsigned int flags, const char *name, struct lock_class_key *key)
{
    stela_linux_timer_queue_current();
    if ((flags & TIMER_DEFERRABLE) && IS_ENABLED(CONFIG_NO_HZ_COMMON)) {
        stela_linux_unsupported("NO_HZ deferrable timer requires actual original idle/base producer");
        stela_linux_fatal("missing NO_HZ timer producer; original timer retained");
    }
    if (flags & TIMER_IRQSAFE) {
        stela_linux_unsupported("IRQ-safe timer requires original softirq callback with IRQs disabled");
        stela_linux_fatal("missing IRQ-safe timer callback producer; original timer retained");
    }
    /* With selected !NO_HZ_COMMON, original Linux uses one base, including
     * TIMER_DEFERRABLE. Genuine HZ_PERIODIC tick delivery remains a required
     * runtime producer; an idle-suppression bool is not its substitute. */
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
    stela_linux_timer_queue_current();
	bool was_pending = timer_pending(timer);
	if ((how == ONLY_PENDING && !was_pending) ||
	    (how == ONLY_EARLIER && was_pending && !time_before(expires, timer->expires)))
		return was_pending;
	if (!timer->function)
		return 0;
    detach(timer);
    enqueue(timer, expires);
    stela_linux_timers_changed();
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
    stela_linux_timer_queue_current();
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
    stela_linux_timer_queue_current();
    if (cpu != 0) {
        stela_linux_unsupported("timer target CPU without original online CPU producer");
        stela_linux_fatal("unsupported timer CPU; original timer retained");
    }
    add_timer(timer);
}

int timer_delete(struct timer_list *timer)
{
    stela_linux_timer_queue_current();
    int removed = detach(timer);
    if (removed)
        stela_linux_timers_changed();
    return removed;
}

int timer_delete_sync_try(struct timer_list *timer)
{
    stela_linux_timer_queue_current();
    if (timer == running_timer)
        return -1;
    return timer_delete(timer);
}

int timer_delete_sync(struct timer_list *timer)
{
    stela_linux_timer_queue_current();
    if (timer == running_timer) {
        stela_linux_unsupported("timer_delete_sync on its running callback");
        stela_linux_fatal("running timer cannot synchronously join itself; owner retained");
    }
    return timer_delete(timer);
}

int timer_shutdown(struct timer_list *timer)
{
    stela_linux_timer_queue_current();
	int was_pending = detach(timer);
    timer->function = NULL;
    if (was_pending)
        stela_linux_timers_changed();
    return was_pending;
}

int timer_shutdown_sync(struct timer_list *timer)
{
    stela_linux_timer_queue_current();
    if (timer == running_timer) {
        stela_linux_unsupported("timer_shutdown_sync on its running callback");
        stela_linux_fatal("running timer cannot synchronously join itself; owner retained");
    }
    return timer_shutdown(timer);
}

bool stela_linux_timers_next(unsigned long *expires)
{
    stela_linux_timer_queue_current();
    if (hlist_empty(&pending))
        return false;
    *expires = hlist_entry(pending.first, struct timer_list, entry)->expires;
    return true;
}

/* Like Linux's expiry, a timer a callback arms for an expiry already past
 * runs on the next pass, not this one. */
void stela_linux_timers_run(const struct stela_linux_timer_delivery *delivery)
{
    stela_linux_timer_delivery_require(delivery);
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
        running_timer = timer;
        function(timer);
        running_timer = NULL;
        stela_linux_atomic_callback_end(&scope);
	}
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
    if (!timeout) {
        /* Exact original zero-timeout scheduler/wakeup ordering. There is no
         * positive physical minimum to mint, and a sleeping caller still needs
         * its original wake source before entering schedule. */
        struct process_timer timer = {.task = current};
        timer_setup_on_stack(&timer.timer, process_timeout, 0);
        timer.timer.expires = jiffies;
        add_timer(&timer.timer);
        schedule();
        timer_delete_sync(&timer.timer);
        timer_destroy_on_stack(&timer.timer);
        return 0;
    }
    _Static_assert(USEC_PER_SEC % HZ == 0, "relative physical jiffy conversion");
    u64 quantum_us = USEC_PER_SEC / HZ;
    if ((u64)timeout > U64_MAX / quantum_us)
        stela_linux_fatal("physical schedule timeout conversion overflow");
    unsigned int state = READ_ONCE(current->__state);
    u64 remaining = stela_linux_minimum_sleep((u64)timeout * quantum_us,
        state, STELA_MINIMUM_EARLY, quantum_us);
    if (remaining > LONG_MAX)
        stela_linux_fatal("physical schedule timeout remainder overflow");
    return (long)remaining;
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
