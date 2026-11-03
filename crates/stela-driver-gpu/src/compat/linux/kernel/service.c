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
#include <stela/atomic_callback.h>
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

static s64 timer_deadline(u64 base, long left)
{
	const u64 quantum = NSEC_PER_SEC / HZ;
	u64 ticks = left > 0 ? (u64)left : 1;

	/* S64_MAX is reserved for an empty timer queue. */
	if (ticks > (S64_MAX - 1 - base) / quantum)
		stela_linux_fatal("nominal service deadline overflow");
	return (s64)(base + ticks * quantum);
}

static s64 hrtimer_deadline(s64 now, s64 expires)
{
	if (expires > now)
		return expires;
	/* S64_MAX is reserved for no deadline. */
	return now == S64_MAX - 1 ? now : now + 1;
}

s64 stela_linux_service_run(void)
{
	update_jiffies();
	stela_linux_timers_run();

	unsigned long timer;
	s64 hrtimer;
	bool armed = stela_linux_timer_list_next(&timer);
	bool high_armed = stela_linux_hrtimers_next_ns(&hrtimer);

	if (!armed && !high_armed)
		return S64_MAX;

	/* Callbacks can cross ticks. Recompute the timer-list deadline on
	 * the same jiffy clock without publishing new jiffies in this pass. */
	_Static_assert(NSEC_PER_SEC % HZ == 0, "nominal jiffy duration");
	const u64 quantum = NSEC_PER_SEC / HZ;
	u64 now = ktime_get_ns();
	if (now < start || now >= S64_MAX)
		stela_linux_fatal("nominal service clock outside signed timer range");
	s64 next = S64_MAX;
	if (armed) {
		u64 elapsed = now - start;
		unsigned long sample = INITIAL_JIFFIES + nsecs_to_jiffies64(elapsed);
		long left = (long)(timer - sample);
		next = timer_deadline(left > 0 ? now - elapsed % quantum : now, left);
	}
	if (high_armed) {
		s64 high = hrtimer_deadline((s64)now, hrtimer);
		if (high < next)
			next = high;
	}
	return next;
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
		struct stela_linux_atomic_callback leaf;
		stela_linux_atomic_process_leaf_begin(&leaf);
		call->drain(call->context);
		stela_linux_atomic_process_leaf_end(&leaf);
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

void stela_linux_worker_main(void *context)
{
	const struct stela_linux_worker_call *call = context;
	stela_linux_enter(call->owner);
	stela_linux_workers_run(call->kind);
	stela_linux_exit();
}

#ifdef STELA_LINUX_SERVICE_TEST
#include <linux/timer.h>
#include <stela/test.h>

static s64 clock;
static s64 advance_after_sample;

static s64 now_ns(void *context)
{
	(void)context;
	s64 sampled = clock;
	clock += advance_after_sample;
	advance_after_sample = 0;
	return sampled;
}

static void expired(struct timer_list *timer)
{
	(void)timer;
	assert(false);
}

static enum hrtimer_restart high_expired(struct hrtimer *timer)
{
	(void)timer;
	assert(false);
	return HRTIMER_NORESTART;
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
	/* Model time spent in a pass across a tick and into the next one. */
	advance_after_sample = 3 * (NSEC_PER_SEC / HZ) / 2;
	assert(stela_linux_service_run() == deadline);
	clock = deadline - NSEC_PER_SEC / HZ;
	assert(stela_linux_service_run() == clock + NSEC_PER_SEC / HZ);
	timer_delete(&timer);
	assert(stela_linux_service_run() == S64_MAX);

	struct hrtimer high;
	hrtimer_setup(&high, high_expired, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	hrtimer_start(&high, clock + 17, HRTIMER_MODE_ABS);
	assert(stela_linux_service_run() == clock + 17);
	hrtimer_cancel(&high);
	assert(stela_linux_service_run() == S64_MAX);

	assert(hrtimer_deadline(clock, clock) == clock + 1);
	assert(hrtimer_deadline(S64_MAX - 2, S64_MAX - 2) == S64_MAX - 1);
	assert(hrtimer_deadline(S64_MAX - 1, S64_MAX - 1) == S64_MAX - 1);

	stela_linux_exit();
	printf("Linux service passes passed\n");
	return 0;
}
#endif
