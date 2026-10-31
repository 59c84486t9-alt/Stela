// SPDX-License-Identifier: MIT
/* An owner's service task, which is what Linux's interrupt return and tick do:
 * each pass runs the raised lines' handlers, brings jiffies up to the clock, runs
 * what expired and says when to come back. Linux's tick is periodic; this one
 * is not, so an idle machine stays idle. */
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/typecheck.h>
#include <linux/sched.h>
#include <stela/irq.h>
#include <stela/linux.h>
#include <stela/service.h>
#include <stela/timer.h>
#include <stela/workqueue.h>

static bool started;
static u64 start;

static void update_jiffies(void)
{
	u64 now = ktime_get_ns();

	if (!started) {
		started = true;
		start = now;
	}
	WRITE_ONCE(jiffies_64, INITIAL_JIFFIES + nsecs_to_jiffies64(now - start));
}

s64 stela_linux_service_run(void)
{
	update_jiffies();
	stela_linux_timers_run();
	stela_linux_hrtimers_run();

	unsigned long timer, hrtimer;
	bool armed = stela_linux_timers_next(&timer);

	if (stela_linux_hrtimers_next(&hrtimer) && (!armed || time_before(hrtimer, timer))) {
		timer = hrtimer;
		armed = true;
	}
	if (!armed)
		return S64_MAX;
	/* The pass itself took time, so ask for the next tick at the earliest. */
	long left = (long)(timer - jiffies);

	return (s64)(ktime_get_ns() + (u64)(left > 0 ? left : 1) * (NSEC_PER_SEC / HZ));
}

void stela_linux_service_loop(const struct stela_linux_service_call *call)
{
	stela_linux_enter(call->owner);
	/* Done only once no batch is due, as stopping itself raises one. */
	for (;;) {
		if (!call->begin(call->context)) {
			if (call->done(call->context))
				break;
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule();
			continue;
		}
		for (int irq; (irq = call->next_irq(call->context)) >= 0;)
			stela_linux_irq_run((unsigned int)irq);
		call->finish(call->context, stela_linux_service_run());
	}
	stela_linux_exit();
}

void stela_linux_sleep_us(u64 minimum)
{
	ktime_t expires = ns_to_ktime(minimum * NSEC_PER_USEC);

	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule_hrtimeout(&expires, HRTIMER_MODE_REL);
}

void stela_linux_worker_main(void *owner)
{
	stela_linux_enter(owner);
	stela_linux_workers_run();
	stela_linux_exit();
}

#ifdef STELA_LINUX_SERVICE_TEST
#include <linux/timer.h>
#include <stela/test.h>

static s64 clock;

static s64 now_ns(void *context)
{
	(void)context;
	return clock;
}

static void expired(struct timer_list *timer)
{
	(void)timer;
	assert(false);
}

int main(void)
{
	static const struct stela_linux_services services = {.now_ns = now_ns};
	static const struct stela_linux_owner owner = {.services = &services};
	static struct timer_list timer;

	clock = 5 * NSEC_PER_SEC;
	stela_linux_enter(&owner);
	assert(stela_linux_service_run() == S64_MAX);
	assert(jiffies == INITIAL_JIFFIES);

	/* The clock moves jiffies from where the first pass found it. */
	clock += NSEC_PER_SEC;
	assert(stela_linux_service_run() == S64_MAX);
	assert(jiffies == INITIAL_JIFFIES + HZ);

	timer_setup(&timer, expired, 0);
	mod_timer(&timer, jiffies + HZ);
	s64 deadline = stela_linux_service_run();

	assert(deadline == clock + NSEC_PER_SEC);
	clock = deadline - NSEC_PER_SEC / HZ;
	assert(stela_linux_service_run() == clock + NSEC_PER_SEC / HZ);
	timer_delete(&timer);
	assert(stela_linux_service_run() == S64_MAX);

	stela_linux_exit();
	printf("Linux service passes passed\n");
	return 0;
}
#endif
