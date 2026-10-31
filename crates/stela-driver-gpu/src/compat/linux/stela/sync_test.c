// SPDX-License-Identifier: MIT
/* Linux's sleeping locks, SRCU, kthread workers and high-resolution timers on
 * the fixture's real Runtime tasks, which their waits need, and irq_work on
 * its worker. */
#include <linux/completion.h>
#include <linux/hrtimer.h>
#include <linux/irq_work.h>
#include <linux/kthread.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/srcu.h>
#include <linux/workqueue.h>
#include <stela/test.h>
#include <stela/timer.h>

void stela_linux_sync_test(void);
extern s64 stela_linux_test_now;

static DECLARE_RWSEM(lock);
static struct work_struct writer_work;
static DECLARE_COMPLETION(writer_started);
static bool readers_left, writer_done;

static void writer(struct work_struct *work)
{
	(void)work;
	complete(&writer_started);
	down_write(&lock);
	assert(readers_left);
	writer_done = true;
	up_write(&lock);
}

static void rwsem(void)
{
	down_read(&lock);
	assert(down_read_trylock(&lock) && !down_write_trylock(&lock));
	INIT_WORK(&writer_work, writer);
	assert(schedule_work(&writer_work));
	wait_for_completion(&writer_started);
	up_read(&lock);
	readers_left = true;
	up_read(&lock);
	assert(flush_work(&writer_work) && writer_done);

	assert(down_write_trylock(&lock) && !down_read_trylock(&lock));
	downgrade_write(&lock);
	assert(down_read_trylock(&lock) && !down_write_trylock(&lock));
	up_read(&lock);
	up_read(&lock);
}

DEFINE_STATIC_SRCU(readers);
static struct work_struct grace_work;
static DECLARE_COMPLETION(grace_started);
static bool reader_left;

static void grace_period(struct work_struct *work)
{
	(void)work;
	complete(&grace_started);
	synchronize_srcu(&readers);
	assert(reader_left);
}

static void srcu(void)
{
	synchronize_srcu(&readers);
	int index = srcu_read_lock(&readers);

	INIT_WORK(&grace_work, grace_period);
	assert(schedule_work(&grace_work));
	wait_for_completion(&grace_started);
	reader_left = true;
	srcu_read_unlock(&readers, index);
	assert(flush_work(&grace_work));
}

static struct kthread_work steps[2], blocked;
static char order[3];
static unsigned int order_length;
static DECLARE_COMPLETION(blocked_started);
static DECLARE_COMPLETION(blocked_release);

static void step(struct kthread_work *work)
{
	order[order_length++] = (char)('0' + (work - steps));
}

static void block(struct kthread_work *work)
{
	(void)work;
	complete(&blocked_started);
	wait_for_completion(&blocked_release);
}

static void workers(void)
{
	struct kthread_worker *worker = kthread_run_worker(0, "test-%d", 1);

	assert(!IS_ERR(worker));
	sched_set_fifo(worker->task);
	kthread_init_work(&blocked, block);
	kthread_init_work(&steps[0], step);
	kthread_init_work(&steps[1], step);
	assert(kthread_queue_work(worker, &blocked));
	wait_for_completion(&blocked_started);

	/* While the worker is busy: a queued item, and one cancelled unrun. */
	assert(kthread_queue_work(worker, &steps[0]));
	assert(!kthread_queue_work(worker, &steps[0]));
	assert(kthread_queue_work(worker, &steps[1]));
	assert(kthread_cancel_work_sync(&steps[1]));
	assert(!kthread_cancel_work_sync(&steps[1]));
	assert(kthread_queue_work(worker, &steps[1]));
	complete(&blocked_release);
	kthread_flush_work(&steps[1]);
	assert(order_length == 2 && !memcmp(order, "01", 2));
	kthread_flush_worker(worker);
	kthread_destroy_worker(worker);
}

static unsigned int fires;

static enum hrtimer_restart once(struct hrtimer *timer)
{
	(void)timer;
	fires++;
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart periodic(struct hrtimer *timer)
{
	fires++;
	assert(hrtimer_active(timer) && hrtimer_try_to_cancel(timer) == -1);
	hrtimer_forward(timer, hrtimer_cb_get_time(timer), ms_to_ktime(10));
	return HRTIMER_RESTART;
}

static struct work_struct expire_work;

static void expire(struct work_struct *work)
{
	(void)work;
	stela_linux_test_now += 3 * NSEC_PER_MSEC;
	stela_linux_timers_run();
}

static void hrtimers(void)
{
	struct hrtimer timer;
	unsigned long next;

	assert(!stela_linux_hrtimers_next(&next));
	hrtimer_setup(&timer, once, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	assert(!hrtimer_active(&timer));
	hrtimer_start(&timer, ms_to_ktime(5), HRTIMER_MODE_REL);
	assert(hrtimer_active(&timer));
	assert(stela_linux_timers_next(&next) && time_after(next, jiffies));
	stela_linux_test_now += 4 * NSEC_PER_MSEC;
	stela_linux_timers_run();
	assert(!fires);
	stela_linux_test_now += NSEC_PER_MSEC;
	stela_linux_timers_run();
	assert(fires == 1 && !hrtimer_active(&timer));
	assert(!hrtimer_cancel(&timer));

	/* An earlier timer runs first, and cancelling leaves the other alone. */
	struct hrtimer late;

	hrtimer_setup(&late, once, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	hrtimer_start(&late, ms_to_ktime(1), HRTIMER_MODE_ABS);
	hrtimer_start(&timer, ms_to_ktime(50), HRTIMER_MODE_REL);
	assert(hrtimer_cancel(&timer) && hrtimer_active(&late));
	stela_linux_timers_run();
	assert(fires == 2 && !hrtimer_active(&late));

	/* A periodic timer, 25 ms late: forward skips the missed periods. */
	fires = 0;
	hrtimer_setup(&timer, periodic, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer_start(&timer, ms_to_ktime(10), HRTIMER_MODE_REL);
	stela_linux_test_now += 25 * NSEC_PER_MSEC;
	stela_linux_timers_run();
	assert(fires == 1 && hrtimer_active(&timer));
	assert(hrtimer_get_expires(&timer) > ktime_get());
	assert(hrtimer_cancel(&timer) && !stela_linux_hrtimers_next(&next));

	/* A sleeper, woken by the timer service on another task. */
	ktime_t timeout = ms_to_ktime(2);

	INIT_WORK(&expire_work, expire);
	assert(schedule_work(&expire_work));
	set_current_state(TASK_UNINTERRUPTIBLE);
	assert(!schedule_hrtimeout(&timeout, HRTIMER_MODE_REL));
	flush_work(&expire_work);
}

static DECLARE_COMPLETION(deferred_ran);

static void deferred(struct irq_work *work)
{
	assert(irq_work_is_busy(work) && !irq_work_is_pending(work));
	complete(&deferred_ran);
}

static void irq_works(void)
{
	static struct irq_work work;

	init_irq_work(&work, deferred);
	assert(irq_work_queue(&work) && !irq_work_queue(&work));
	wait_for_completion(&deferred_ran);
	/* A running work may be queued again. */
	assert(irq_work_queue(&work));
	wait_for_completion(&deferred_ran);
}

void stela_linux_sync_test(void)
{
	rwsem();
	srcu();
	workers();
	hrtimers();
	irq_works();
}
