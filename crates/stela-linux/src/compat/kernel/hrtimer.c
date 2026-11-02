// SPDX-License-Identifier: MIT
/* Linux's high-resolution timers, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/time/hrtimer.c. Every timer
 * counts in an actual supplied clock domain. Qualified service delivery uses
 * the original hard/default or explicit soft callback context. Nominal expiry
 * labels never grant physical minimum readiness or an upper-latency promise. */
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/timerqueue.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/timer.h>

/* The original hard phase precedes softirq delivery. Separate original
 * expiry queues prevent soft entries from blocking a due hard callback. */
static struct timerqueue_linked_head pending_hard = {.rb_root = RB_ROOT_LINKED};
static struct timerqueue_linked_head pending_soft = {.rb_root = RB_ROOT_LINKED};
static struct timerqueue_linked_head *timer_queue(const struct hrtimer *timer)
{
    return timer->is_soft ? &pending_soft : &pending_hard;
}
static const struct hrtimer *running;

ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs)
{
	ktime_t sum = (ktime_t)ktime_add_unsafe(lhs, rhs);

	return sum < 0 || sum < lhs || sum < rhs ? KTIME_MAX : sum;
}

static void unsupported_clock(clockid_t clock_id)
{
    switch (clock_id) {
    case CLOCK_REALTIME:
        stela_linux_unsupported("absolute CLOCK_REALTIME hrtimer requires genuine wall-time domain");
        break;
    case CLOCK_BOOTTIME:
        stela_linux_unsupported("CLOCK_BOOTTIME hrtimer requires genuine suspend/PM domain");
        break;
    case CLOCK_TAI:
        stela_linux_unsupported("CLOCK_TAI hrtimer requires genuine TAI domain");
        break;
    default:
        stela_linux_unsupported("hrtimer clock domain without actual source producer");
        break;
    }
    stela_linux_fatal("unsupported hrtimer clock domain; original timer retained");
}
static void check_mode(enum hrtimer_mode mode)
{
    const unsigned int known = HRTIMER_MODE_REL | HRTIMER_MODE_PINNED |
        HRTIMER_MODE_SOFT | HRTIMER_MODE_HARD | HRTIMER_MODE_LAZY_REARM;
    if ((unsigned int)mode & ~known) {
        stela_linux_unsupported("hrtimer unknown mode bits");
        stela_linux_fatal("unsupported hrtimer mode; original timer retained");
    }
}
void hrtimer_setup(struct hrtimer *timer, enum hrtimer_restart (*function)(struct hrtimer *),
                   clockid_t clock_id, enum hrtimer_mode mode)
{
    stela_linux_timer_queue_current();
    check_mode(mode);
    /* Original POSIX normalization: relative REALTIME is unaffected by wall
     * clock updates and uses MONOTONIC. Absolute UTC/PM/TAI are not faked. */
    if (clock_id == CLOCK_REALTIME && mode & HRTIMER_MODE_REL)
        clock_id = CLOCK_MONOTONIC;
    if (clock_id != CLOCK_MONOTONIC)
        unsupported_clock(clock_id);
    if (!function) {
        stela_linux_unsupported("hrtimer setup without original callback");
        stela_linux_fatal("missing hrtimer callback; original timer retained");
    }
    memset(timer, 0, sizeof(*timer));
    timer->is_soft = !!(mode & HRTIMER_MODE_SOFT);
    if (IS_ENABLED(CONFIG_PREEMPT_RT) && !(mode & HRTIMER_MODE_HARD))
        timer->is_soft = true;
    timer->is_hard = !!(mode & HRTIMER_MODE_HARD);
    timer->is_lazy = !!(mode & HRTIMER_MODE_LAZY_REARM);
    timerqueue_linked_init(&timer->node);
    ACCESS_PRIVATE(timer, function) = function;
}

static void enqueue(struct hrtimer *timer)
{
	timer->is_queued = true;
	timerqueue_linked_add(timer_queue(timer), &timer->node);
}

static void dequeue(struct hrtimer *timer)
{
	timerqueue_linked_del(timer_queue(timer), &timer->node);
	timer->is_queued = false;
}

void hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim, u64 delta_ns,
			    const enum hrtimer_mode mode)
{
    stela_linux_timer_queue_current();
    check_mode(mode);
    if (!IS_ENABLED(CONFIG_PREEMPT_RT))
        WARN_ON_ONCE(!(mode & HRTIMER_MODE_SOFT) ^ !timer->is_soft);
    else
        WARN_ON_ONCE(!(mode & HRTIMER_MODE_HARD) ^ !timer->is_hard);
    if (timer->is_queued)
        dequeue(timer);
    timer->is_rel = !!(mode & HRTIMER_MODE_REL);
    if (timer->is_rel) {
        tim = ktime_add_safe(ktime_get(), tim);
        /* Original low-resolution relative adjustment; nominal only. */
        if (IS_ENABLED(CONFIG_TIME_LOW_RES))
            tim = ktime_add_safe(tim, hrtimer_resolution);
    }
    hrtimer_set_expires_range_ns(timer, tim, delta_ns);
    enqueue(timer);
    stela_linux_timers_changed();
}

bool hrtimer_active(const struct hrtimer *timer)
{
	return timer->is_queued || timer == running;
}

/* Linux code runs in one context at a time, so a running callback can only
 * be the caller. */
int hrtimer_try_to_cancel(struct hrtimer *timer)
{
    stela_linux_timer_queue_current();
	if (timer == running)
		return -1;
	if (!timer->is_queued)
		return 0;
    dequeue(timer);
    stela_linux_timers_changed();
    return 1;
}

int hrtimer_cancel(struct hrtimer *timer)
{
	int result = hrtimer_try_to_cancel(timer);

    if (result < 0) {
        stela_linux_unsupported("hrtimer_cancel on its running callback");
        stela_linux_fatal("running hrtimer cannot synchronously join itself; owner retained");
    }
    return result;
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

bool stela_linux_hrtimers_next_ns(s64 *expires)
{
    stela_linux_timer_queue_current();
    const struct timerqueue_linked_node *hard = timerqueue_linked_first(&pending_hard);
    const struct timerqueue_linked_node *soft = timerqueue_linked_first(&pending_soft);
    if (!hard && !soft)
        return false;
    *expires = ktime_to_ns(!soft || (hard && hard->expires <= soft->expires) ?
        hard->expires : soft->expires);
    return true;
}

static void run_queue(const struct stela_linux_timer_delivery *delivery,
                      struct timerqueue_linked_head *queue)
{
    stela_linux_timer_delivery_require(delivery);
    ktime_t now = ktime_get();
    struct timerqueue_linked_node *first;
    while ((first = timerqueue_linked_first(queue))) {
        struct hrtimer *timer = container_of(first, struct hrtimer, node);
        /* Exact original __hrtimer_run_queues: hard-expiry ordered head,
         * eligible at soft expiry on an actual service wake. A due same-phase
         * callback restart may run again, as in the original source. */
        if (now < hrtimer_get_softexpires(timer))
            break;
        struct stela_linux_atomic_callback scope;
        dequeue(timer);
        running = timer;
        if (IS_ENABLED(CONFIG_TIME_LOW_RES))
            timer->is_rel = false;
        /* Original mode data chooses logical callback nesting only AFTER the
         * genuine service/batch/current producer has authenticated delivery. */
        if (timer->is_soft)
            stela_linux_atomic_callback_begin_soft(&scope);
        else
            stela_linux_atomic_callback_begin(&scope);
        enum hrtimer_restart restart = ACCESS_PRIVATE(timer, function)(timer);
        stela_linux_atomic_callback_end(&scope);
        running = NULL;
        if (restart == HRTIMER_RESTART && !timer->is_queued)
            enqueue(timer);
    }
}

void stela_linux_hrtimers_run_hard(const struct stela_linux_timer_delivery *delivery)
{
    run_queue(delivery, &pending_hard);
}

void stela_linux_hrtimers_run_soft(const struct stela_linux_timer_delivery *delivery)
{
    run_queue(delivery, &pending_soft);
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
