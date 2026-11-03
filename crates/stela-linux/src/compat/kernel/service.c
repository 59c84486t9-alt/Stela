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

static bool sample_jiffies(s64 now, u64 *sample)
{
    if (!started) {
        started = true;
        start = now;
    }
    if (now < start)
        return false;
    /* Both samples are in [0,S64_MAX), so this difference is nonnegative and
     * cannot overflow signed time. Only then convert to the original unsigned
     * elapsed-nanoseconds input of nsecs_to_jiffies64. */
    *sample = INITIAL_JIFFIES + nsecs_to_jiffies64((u64)(now - start));
    return true;
}

static void update_jiffies(void)
{
    u64 sample;
    if (!sample_jiffies(service_now_ns(), &sample))
        stela_linux_fatal("nominal service clock precedes its retained origin");
    WRITE_ONCE(jiffies_64, sample);
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

/* Translate a future expiry to its boundary on the retained jiffy clock.
 * Already-due entries wait one quantum before the next delivery pass. */
static bool timer_list_deadline(s64 now, unsigned long expires, unsigned long current_jiffies,
                                s64 *deadline)
{
    _Static_assert(NSEC_PER_SEC % HZ == 0, "nominal jiffy duration");
    const s64 quantum = NSEC_PER_SEC / HZ;
    long left = (long)(expires - current_jiffies);
    s64 base = left > 0 ? now - (now - start) % quantum : now;
    s64 ticks = left > 0 ? left : 1;

    /* S64_MAX is reserved for an empty timer queue. */
    if (ticks > (S64_MAX - 1 - base) / quantum)
        return false;
    *deadline = base + ticks * quantum;
    return true;
}

/* A due timer left by a completed phase needs another pass. S64_MAX is
 * reserved for no deadline, so a retry at the last usable tick is immediate. */
static s64 hrtimer_deadline(s64 now, s64 expires)
{
    if (expires > now)
        return expires;
    return now == S64_MAX - 1 ? now : now + 1;
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
        u64 sample;
        /* Callbacks can cross jiffy boundaries. Resample for the deadline
         * without changing the jiffies seen by the completed pass. */
        if (!sample_jiffies(now, &sample))
            stela_linux_fatal("nominal service clock precedes its retained origin");
        if (!timer_list_deadline(now, timer, (unsigned long)sample, &next))
            stela_linux_fatal("nominal timer-list deadline overflow");
    }
    if (stela_linux_hrtimers_next_ns(&high)) {
        /* Same-phase restarts are handled by run_queue. Keep the remaining
         * hard deadline in ns without rounding it to a whole jiffy. */
        high = hrtimer_deadline(now, high);
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
#include <stela/test.h>

int main(void)
{
    s64 clock = 5 * NSEC_PER_SEC;
    u64 sample;
    assert(sample_jiffies(clock, &sample) && sample == INITIAL_JIFFIES);

    clock += NSEC_PER_SEC;
    assert(sample_jiffies(clock, &sample) && sample == INITIAL_JIFFIES + HZ);

    unsigned long expires = (unsigned long)sample + HZ;
    s64 deadline, next;
    assert(timer_list_deadline(clock, expires, (unsigned long)sample, &deadline));
    assert(deadline == clock + NSEC_PER_SEC);
    clock = deadline - NSEC_PER_SEC / HZ;
    assert(sample_jiffies(clock, &sample));
    assert(timer_list_deadline(clock, expires, (unsigned long)sample, &next) && next == deadline);

    /* Callback time can cross ticks and end between jiffy boundaries. */
    clock += NSEC_PER_SEC / HZ / 2;
    assert(sample_jiffies(clock, &sample));
    assert(timer_list_deadline(clock, expires, (unsigned long)sample, &next) && next == deadline);
    clock = deadline + NSEC_PER_SEC / HZ / 2;
    assert(sample_jiffies(clock, &sample));
    assert(timer_list_deadline(clock, expires, (unsigned long)sample, &next));
    assert(next == clock + NSEC_PER_SEC / HZ);
    clock = deadline;

    /* Linux compares jiffies modulo unsigned long, including wrap. */
    assert(timer_list_deadline(clock, 1, ULONG_MAX, &next));
    assert(next == clock + 2 * (NSEC_PER_SEC / HZ));
    assert(timer_list_deadline(clock, 0, 1, &next));
    assert(next == clock + NSEC_PER_SEC / HZ);
    assert(!timer_list_deadline(S64_MAX - NSEC_PER_SEC / HZ, 0, 0, &next));
    assert(!timer_list_deadline(S64_MAX - 1, 0, 0, &next));
    assert(!sample_jiffies(0, &sample));

    /* A due high-resolution timer must not become the empty-queue sentinel. */
    assert(hrtimer_deadline(clock, clock + 17) == clock + 17);
    assert(hrtimer_deadline(clock, clock) == clock + 1);
    assert(hrtimer_deadline(S64_MAX - 2, S64_MAX - 3) == S64_MAX - 1);
    assert(hrtimer_deadline(S64_MAX - 1, S64_MAX - 1) == S64_MAX - 1);

    printf("Linux nominal service deadline checks passed\n");
    return 0;
}
#endif
