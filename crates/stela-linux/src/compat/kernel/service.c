// SPDX-License-Identifier: MIT
/* One bounded service pass from the SAME real owned Domain batch. Nominal
 * jiffies/deadline inspection is not an original periodic tick producer:
 * selected HZ_PERIODIC accounting/RCU/workqueue/clockevent integration remains
 * a distinct required runtime source. No timer callback permission follows
 * from a numeric now/deadline or an unowned batch pointer. */
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
#include <stela/task.h>

static bool started;
static s64 start;

/* Original ktime_to_ns returns s64. Validate that actual MONOTONIC domain
 * before any jiffy state/queue effect; do not wrap a u64 read into signed time. */
static s64 service_now_ns(void)
{
    s64 now = ktime_to_ns(ktime_get());
    if (now < 0 || now == S64_MAX)
        stela_linux_fatal("nominal service clock outside signed timer range");
    return now;
}

static void update_jiffies(void)
{
    s64 now = service_now_ns();

	if (!started) {
		started = true;
		start = now;
	}
    if (now < start)
        stela_linux_fatal("nominal service clock precedes its retained origin");
    /* Both samples are in [0,S64_MAX), so this difference is nonnegative and
     * cannot overflow signed time. Only then convert to the original unsigned
     * elapsed-nanoseconds input of nsecs_to_jiffies64. */
    WRITE_ONCE(jiffies_64, INITIAL_JIFFIES + nsecs_to_jiffies64((u64)(now - start)));
}

void stela_linux_timer_queue_current(void)
{
    const struct stela_linux_owner *owner = stela_linux_owner();
    /* Bounded original current provenance admits logical C IRQ callbacks,
     * but never a Bare context, physical native ISR or global phase flag. */
    if (stela_linux_require_current(owner))
        stela_linux_fatal("timer queue without actual original current");
}

void stela_linux_timers_changed(void)
{
    const struct stela_linux_owner *owner = stela_linux_owner();
    if (!owner->services->timer_changed)
        stela_linux_fatal("timer queue changed without actual Environment wake producer");
    owner->services->timer_changed(owner->context);
}

void stela_linux_timer_delivery_require(const struct stela_linux_timer_delivery *delivery)
{
    const struct stela_linux_owner *owner = stela_linux_owner();
    if (!delivery || stela_linux_require_current(owner) || !stela_linux_quiescent() ||
        stela_linux_atomic_callback_active() || stela_linux_timer_delivery_check(delivery, owner))
        stela_linux_fatal("timer delivery without genuine current/service/owned batch");
}

s64 stela_linux_service_run(const struct stela_linux_timer_delivery *delivery)
{
    stela_linux_timer_delivery_require(delivery);
    update_jiffies();
    stela_linux_hrtimers_run_hard(delivery);
    stela_linux_timers_run(delivery);
    stela_linux_hrtimers_run_soft(delivery);
    /* Every callback returned before selecting the original remaining queue
     * minima. No mutable queue/Domain borrow spans foreign delivery. */
    s64 now = service_now_ns();
    s64 next = S64_MAX, high;
    unsigned long timer;
    if (stela_linux_timers_next(&timer)) {
        long left = (long)(timer - jiffies);
        u64 ticks = left > 0 ? (u64)left : 1;
        u64 quantum = NSEC_PER_SEC / HZ;
        if (ticks > (u64)(S64_MAX - now) / quantum)
            stela_linux_fatal("nominal timer-list deadline overflow");
        next = now + (s64)(ticks * quantum);
    }
    if (stela_linux_hrtimers_next_ns(&high)) {
        /* A due timer remaining AFTER its original phase needs another pass.
         * Same-phase hrtimer restart semantics are preserved by run_queue.
         * Keep exact ns instead of converting expiry to a whole jiffy. */
        if (high <= now)
            high = now + 1;
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
		for (int irq; (irq = call->next_irq(call->context)) >= 0;) {
			stela_linux_irq_run((unsigned int)irq);
			call->complete_irq(call->context);
		}
		call->finish(call->context);
	}
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
