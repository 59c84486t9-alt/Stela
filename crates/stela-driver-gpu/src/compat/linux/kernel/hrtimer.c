// SPDX-License-Identifier: MIT
/* Linux's high-resolution timers, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/time/hrtimer.c. Every timer
 * counts in the owner's monotonic clock. The timer service delivers them, as
 * soft-timer callbacks, when it runs Linux's timers: a timer never fires
 * early, and fires within a jiffy of its expiry. */
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/timerqueue.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/timer.h>

static struct timerqueue_linked_head pending = {.rb_root = RB_ROOT_LINKED};
static const struct hrtimer *running;

ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs)
{
	ktime_t sum = (ktime_t)ktime_add_unsafe(lhs, rhs);

	return sum < 0 || sum < lhs || sum < rhs ? KTIME_MAX : sum;
}

void hrtimer_setup(struct hrtimer *timer, enum hrtimer_restart (*function)(struct hrtimer *),
		   clockid_t clock_id, enum hrtimer_mode mode)
{
	(void)mode;
	WARN_ON_ONCE(clock_id != CLOCK_MONOTONIC);
	memset(timer, 0, sizeof(*timer));
	timerqueue_linked_init(&timer->node);
	ACCESS_PRIVATE(timer, function) = function;
}

static void enqueue(struct hrtimer *timer)
{
	timer->is_queued = true;
	timerqueue_linked_add(&pending, &timer->node);
}

static void dequeue(struct hrtimer *timer)
{
	timerqueue_linked_del(&pending, &timer->node);
	timer->is_queued = false;
}

void hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim, u64 delta_ns,
			    const enum hrtimer_mode mode)
{
	if (timer->is_queued)
		dequeue(timer);
	if (mode & HRTIMER_MODE_REL)
		tim = ktime_add_safe(ktime_get(), tim);
	hrtimer_set_expires_range_ns(timer, tim, delta_ns);
	enqueue(timer);
}

bool hrtimer_active(const struct hrtimer *timer)
{
	return timer->is_queued || timer == running;
}

/* Linux code runs in one context at a time, so a running callback can only
 * be the caller. */
int hrtimer_try_to_cancel(struct hrtimer *timer)
{
	if (timer == running)
		return -1;
	if (!timer->is_queued)
		return 0;
	dequeue(timer);
	return 1;
}

int hrtimer_cancel(struct hrtimer *timer)
{
	int result = hrtimer_try_to_cancel(timer);

	WARN_ON_ONCE(result < 0);
	return result > 0;
}

ktime_t hrtimer_cb_get_time(const struct hrtimer *timer)
{
	(void)timer;
	return ktime_get();
}

u64 hrtimer_forward(struct hrtimer *timer, ktime_t now, ktime_t interval)
{
	ktime_t delta = ktime_sub(now, hrtimer_get_expires(timer));
	u64 overruns = 1;

	if (delta < 0 || WARN_ON(timer->is_queued))
		return 0;
	if (interval < hrtimer_resolution)
		interval = hrtimer_resolution;
	if (delta >= interval) {
		s64 increment = ktime_to_ns(interval);

		overruns = (u64)ktime_divns(delta, increment);
		hrtimer_add_expires_ns(timer, (u64)increment * overruns);
		if (hrtimer_get_expires(timer) > now)
			return overruns;
		overruns++;
	}
	hrtimer_add_expires(timer, interval);
	return overruns;
}

bool stela_linux_hrtimers_next(unsigned long *expires)
{
	const struct timerqueue_linked_node *first = timerqueue_linked_first(&pending);

	if (!first)
		return false;
	ktime_t left = ktime_sub(first->expires, ktime_get());
	*expires = jiffies + (left > 0 ? nsecs_to_jiffies((u64)left) + 1 : 0);
	return true;
}

void stela_linux_hrtimers_run(void)
{
	struct timerqueue_linked_node *first = timerqueue_linked_first(&pending);

	if (!first)
		return;
	ktime_t now = ktime_get();

	while ((first = timerqueue_linked_first(&pending)) && first->expires <= now) {
		struct hrtimer *timer = container_of(first, struct hrtimer, node);
		struct stela_linux_atomic_callback scope;

		dequeue(timer);
		running = timer;
		stela_linux_atomic_callback_begin_soft(&scope);
		enum hrtimer_restart restart = ACCESS_PRIVATE(timer, function)(timer);
		stela_linux_atomic_callback_end(&scope);
		running = NULL;
		if (restart != HRTIMER_NORESTART && !timer->is_queued)
			enqueue(timer);
	}
}

struct sleeper {
	struct hrtimer timer;
	struct task_struct *task;
};

static enum hrtimer_restart wake_sleeper(struct hrtimer *timer)
{
	struct sleeper *sleeper = container_of(timer, struct sleeper, timer);
	struct task_struct *task = sleeper->task;

	sleeper->task = NULL;
	wake_up_process(task);
	return HRTIMER_NORESTART;
}

int schedule_hrtimeout(ktime_t *expires, const enum hrtimer_mode mode)
{
	if (!expires) {
		schedule();
		return -EINTR;
	}
	if (!*expires) {
		__set_current_state(TASK_RUNNING);
		return 0;
	}
	struct sleeper sleeper = {.task = current};

	hrtimer_setup(&sleeper.timer, wake_sleeper, CLOCK_MONOTONIC, mode);
	hrtimer_start(&sleeper.timer, *expires, mode);
	schedule();
	hrtimer_cancel(&sleeper.timer);
	__set_current_state(TASK_RUNNING);
	return sleeper.task ? -EINTR : 0;
}
