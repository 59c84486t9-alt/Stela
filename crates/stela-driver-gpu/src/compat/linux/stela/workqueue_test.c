// SPDX-License-Identifier: MIT
/* Linux's workqueues on the existing fixture's real Runtime tasks: the owner
 * starts each requested worker as a General job. */
#include <linux/interrupt.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <stela/irq.h>
#include <stela/linux.h>
#include <stela/test.h>
#include <stela/workqueue.h>

void stela_linux_workqueue_test_bind(void *context, int (*start_worker)(void *context));
void stela_linux_workqueue_test_worker(void *context);
void stela_linux_workqueue_test_main(void *context);
void stela_linux_i2c_test(void);

struct start {
	void *context;
	int (*start_worker)(void *context);
};

static struct start start;
static unsigned int started;

static int start_worker(void *context)
{
	(void)context;
	started++;
	return start.start_worker(start.context);
}

static bool forced;

static void shutdown(void *context, bool force)
{
	(void)context;
	forced = force;
}

static unsigned int line_enables, line_disables;

static int irq_enable(void *context, unsigned int irq)
{
	(void)context;
	assert(irq == 7);
	line_enables++;
	return 0;
}

static void irq_disable(void *context, unsigned int irq)
{
	(void)context;
	assert(irq == 7);
	line_disables++;
}

static const struct stela_linux_services services = {
	.start_worker = start_worker,
	.shutdown = shutdown,
	.irq_enable = irq_enable,
	.irq_disable = irq_disable,
};
static const struct stela_linux_owner owner = {.services = &services};

void stela_linux_workqueue_test_bind(void *context, int (*start_worker_fn)(void *context))
{
	start = (struct start){.context = context, .start_worker = start_worker_fn};
}

void stela_linux_workqueue_test_worker(void *context)
{
	(void)context;
	stela_linux_enter(&owner);
	stela_linux_workers_run();
	stela_linux_exit();
}

static struct workqueue_struct *wq, *ordered;
static struct work_struct outer, inner, steps[3], cancelled, shared;
static struct delayed_work later;
static bool outer_done, inner_done, shared_done, later_done, cancelled_ran;
static char order[4];
static unsigned int order_length;

static void run_inner(struct work_struct *work)
{
	assert(work == &inner && current_work() == &inner);
	inner_done = true;
}

/* Waits for another item, which needs a second worker. */
static void run_outer(struct work_struct *work)
{
	assert(work == &outer && !work_pending(work));
	assert(queue_work(wq, &inner) && !queue_work(wq, &inner));
	assert(flush_work(&inner) && inner_done);
	outer_done = true;
}

static void run_step(struct work_struct *work)
{
	order[order_length++] = (char)('0' + (work - steps));
}

static void run_forbidden(struct work_struct *work)
{
	(void)work;
	cancelled_ran = true;
}

static void run_shared(struct work_struct *work)
{
	(void)work;
	shared_done = true;
}

static void run_later(struct work_struct *work)
{
	(void)work;
	later_done = true;
}

static unsigned int hard_runs, other_runs, thread_runs;

static irqreturn_t hard_handler(int irq, void *dev_id)
{
	assert(irq == 7 && dev_id == &hard_runs && in_hardirq());
	hard_runs++;
	return IRQ_WAKE_THREAD;
}

static irqreturn_t other_handler(int irq, void *dev_id)
{
	(void)irq;
	(void)dev_id;
	other_runs++;
	return IRQ_NONE;
}

static irqreturn_t thread_handler(int irq, void *dev_id)
{
	assert(irq == 7 && dev_id == &hard_runs && !in_interrupt());
	thread_runs++;
	return IRQ_HANDLED;
}

void stela_linux_workqueue_test_main(void *context)
{
	(void)context;
	stela_linux_enter(&owner);
	wq = alloc_workqueue("stela-test-%d", WQ_UNBOUND, 2, 1);
	ordered = alloc_ordered_workqueue("stela-ordered", 0);
	assert(wq && ordered && !current_work());
	INIT_WORK(&outer, run_outer);
	INIT_WORK(&inner, run_inner);
	assert(queue_work(wq, &outer));
	assert(flush_work(&outer) && outer_done && inner_done && !flush_work(&outer));
	assert(started >= 2);
	for (int i = 0; i < 3; i++) {
		INIT_WORK(&steps[i], run_step);
		assert(queue_work(ordered, &steps[i]));
	}
	INIT_WORK(&cancelled, run_forbidden);
	assert(queue_work(ordered, &cancelled) && cancel_work_sync(&cancelled));
	assert(!work_pending(&cancelled) && !cancel_work(&cancelled));
	flush_workqueue(ordered);
	assert(order_length == 3 && !memcmp(order, "012", 3) && !cancelled_ran);
	INIT_WORK(&shared, run_shared);
	assert(schedule_work(&shared) && flush_work(&shared) && shared_done);
	INIT_DELAYED_WORK(&later, run_later);
	assert(queue_delayed_work(wq, &later, 100) && delayed_work_pending(&later));
	assert(cancel_delayed_work_sync(&later) && !later_done);
	assert(queue_delayed_work(wq, &later, 100));
	assert(flush_delayed_work(&later) && later_done);
	destroy_workqueue(ordered);
	destroy_workqueue(wq);

	orderly_poweroff(true);
	flush_workqueue(system_wq);
	assert(forced);

	/* Two sharers: the oneshot's thread keeps the line masked until it ends. */
	assert(!request_threaded_irq(7, hard_handler, thread_handler,
				     IRQF_SHARED | IRQF_ONESHOT, "threaded", &hard_runs));
	assert(line_enables == 1);
	assert(request_irq(7, other_handler, 0, "refused", NULL) == -EBUSY);
	assert(!request_irq(7, other_handler, IRQF_SHARED, "other", &forced));
	assert(line_enables == 1);
	stela_linux_irq_run(7);
	flush_workqueue(system_highpri_wq);
	assert(hard_runs == 1 && other_runs == 1 && thread_runs == 1);
	assert(line_disables == 1 && line_enables == 2);
	assert(!strcmp(free_irq(7, &hard_runs), "threaded") && line_disables == 1);
	assert(!strcmp(free_irq(7, &forced), "other") && line_disables == 2);
	stela_linux_i2c_test();
	stela_linux_exit();
}
