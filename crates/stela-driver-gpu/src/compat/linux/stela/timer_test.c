// SPDX-License-Identifier: MIT
/* Linux's timers, timed sleeps, wait queues, completions and bit waits on
 * the existing fixture's real Runtime tasks. A service task delivers expired
 * timers as the owner's service does; the fixture publishes jiffies from its
 * clock as the platform's tick does. */
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/wait_bit.h>
#include <stela/linux.h>
#include <stela/test.h>
#include <stela/timer.h>

void stela_linux_timer_test_service(void *context);
void stela_linux_timer_test_sleeper(void *context);

struct timer_service_call {
	void *context;
	/* Begin the service's next due batch; false when none is due. */
	bool (*begin)(void *context);
	/* Finish it with the earliest pending expiry, when one is armed. */
	void (*finish)(void *context, bool armed, unsigned long expires);
	bool (*done)(void *context);
};

void stela_linux_timer_test_service(void *context)
{
	const struct timer_service_call *call = context;
	stela_linux_enter(&stela_linux_bare);
	while (!call->done(call->context)) {
		if (!call->begin(call->context)) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule();
			continue;
		}
		stela_linux_timers_run();
		unsigned long expires;
		bool armed = stela_linux_timers_next(&expires);
		call->finish(call->context, armed, expires);
	}
	stela_linux_exit();
}

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

void stela_linux_timer_test_sleeper(void *context)
{
	(void)context;
	stela_linux_enter(&stela_linux_bare);
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
	stela_linux_exit();
}
