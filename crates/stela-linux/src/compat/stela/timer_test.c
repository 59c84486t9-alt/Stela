// SPDX-License-Identifier: MIT
/* Original timer and wait APIs on a source child, with delivery owned by
 * the mounted Initial's regular service loop. */
#include <linux/completion.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/timekeeping.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/wait_bit.h>
#include <stela/linux.h>
#include <stela/test.h>
#include <stela/timer.h>

void stela_linux_timer_test_sleeper(void);

static unsigned int counted;
static struct timer_list first, second, waker, completer, clearer;
static DECLARE_WAIT_QUEUE_HEAD(queue);
static bool ready;
static struct completion done;
static unsigned long word;

static void count(struct timer_list *timer)
{
	assert(timer == &first && in_serving_softirq());
	counted++;
}

static void wake_queue(struct timer_list *timer)
{
	(void)timer;
	WRITE_ONCE(ready, true);
	wake_up(&queue);
}

static void complete_done(struct timer_list *timer)
{
	(void)timer;
	complete_all(&done);
}

static void clear_bit_zero(struct timer_list *timer)
{
	(void)timer;
	clear_and_wake_up_bit(0, &word);
}

static void timer_list_waits(void)
{
	unsigned long expires;
	assert(!stela_linux_timers_next(&expires));
	timer_setup(&first, count, 0);
	timer_setup(&second, count, 0);
	/* Pending timers stay in expiry order through every change. */
	assert(!mod_timer(&second, jiffies + 20) && !mod_timer(&first, jiffies + 30));
	assert(stela_linux_timers_next(&expires) && expires == second.expires);
	assert(timer_reduce(&first, jiffies + 10) == 1);
	assert(stela_linux_timers_next(&expires) && expires == first.expires);
	unsigned long reduced = first.expires;
	assert(timer_reduce(&first, jiffies + 40) == 1 && first.expires == reduced);
	assert(mod_timer_pending(&second, jiffies + 50) == 1);
	assert(timer_delete(&second) == 1 && !timer_delete(&second));
	assert(!mod_timer_pending(&second, jiffies + 1) && !timer_pending(&second));
	assert(!timer_shutdown_sync(&second) && !mod_timer(&second, jiffies + 1));
	assert(!timer_pending(&second));
	/* A timed sleep lasts its jiffies; the earlier timer fires meanwhile. */
	unsigned long start = jiffies;
	assert(!schedule_timeout_uninterruptible((long)(first.expires - start) + 2));
	assert(time_after_eq(jiffies, start + 2) && counted == 1 && !timer_pending(&first));
	assert(!stela_linux_timers_next(&expires));
	/* Waits a timer ends early, and one it does not. */
	timer_setup(&waker, wake_queue, 0);
	mod_timer(&waker, jiffies + 2);
	assert(wait_event_timeout(queue, READ_ONCE(ready), 1000) > 0);
	init_completion(&done);
	start = jiffies;
	assert(!wait_for_completion_timeout(&done, 3) && time_after_eq(jiffies, start + 3));
	timer_setup(&completer, complete_done, 0);
	mod_timer(&completer, jiffies + 2);
	assert(wait_for_completion_timeout(&done, 1000) > 0 && completion_done(&done));
	set_bit(0, &word);
	timer_setup(&clearer, clear_bit_zero, 0);
	mod_timer(&clearer, jiffies + 2);
	assert(!wait_on_bit(&word, 0, TASK_UNINTERRUPTIBLE) && !test_bit(0, &word));
}

static DECLARE_COMPLETION(high_fired);
static unsigned int fires;

static enum hrtimer_restart once(struct hrtimer *timer)
{
	assert(ktime_get() >= hrtimer_get_softexpires(timer));
	fires++;
	complete(&high_fired);
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart periodic(struct hrtimer *timer)
{
	fires++;
	assert(hrtimer_active(timer) && hrtimer_try_to_cancel(timer) == -1);
	const ktime_t period = ms_to_ktime(100);
	ktime_t expiry = hrtimer_get_expires(timer);
	/* Observe at least two missed periods and leave room for the waiting
	 * task to cancel the restart after the real dispatcher resumes it. */
	ktime_t sample = max(ktime_get(), expiry + ms_to_ktime(250));
	u64 periods = (u64)((sample - expiry) / period) + 1;
	assert(hrtimer_forward(timer, sample, period) == periods);
	assert(hrtimer_get_expires(timer) > sample);
	complete(&high_fired);
	return HRTIMER_RESTART;
}

static void hrtimer_waits(void)
{
	struct hrtimer timer, earlier;

	hrtimer_setup(&timer, once, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	assert(!hrtimer_active(&timer));
	hrtimer_start(&timer, ms_to_ktime(5), HRTIMER_MODE_REL);
	assert(hrtimer_active(&timer) && !fires);
	wait_for_completion(&high_fired);
	assert(fires == 1 && !hrtimer_active(&timer));
	assert(!hrtimer_cancel(&timer));

	/* An already-expired timer runs, and cancelling a different timer
	 * leaves that expiry intact. */
	hrtimer_setup(&earlier, once, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	hrtimer_start(&earlier, ktime_get() - 1, HRTIMER_MODE_ABS);
	hrtimer_start(&timer, ms_to_ktime(50), HRTIMER_MODE_REL);
	assert(hrtimer_cancel(&timer) && hrtimer_active(&earlier));
	wait_for_completion(&high_fired);
	assert(fires == 2 && !hrtimer_active(&earlier));

	fires = 0;
	hrtimer_setup(&timer, periodic, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer_start(&timer, ms_to_ktime(10), HRTIMER_MODE_REL);
	wait_for_completion(&high_fired);
	assert(fires == 1 && hrtimer_active(&timer));
	assert(hrtimer_cancel(&timer) && !hrtimer_active(&timer));

	ktime_t timeout = ms_to_ktime(2);
	set_current_state(TASK_UNINTERRUPTIBLE);
	assert(!schedule_hrtimeout(&timeout, HRTIMER_MODE_REL));
}

void stela_linux_timer_test_sleeper(void)
{
	timer_list_waits();
	hrtimer_waits();
}
