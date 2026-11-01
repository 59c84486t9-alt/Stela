// SPDX-License-Identifier: MIT
/* Linux's workqueues on the existing fixture's real Runtime tasks: the owner
 * starts each requested worker as a General job. */
#include <linux/interrupt.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <stela/irq.h>
#include <stela/linux.h>
#include <stela/test.h>
#include <stela/workqueue.h>

void stela_linux_workqueue_test_bind(void *context, int (*start_worker)(void *context, unsigned int kind));
void stela_linux_workqueue_test_worker(void *context, unsigned int kind);
void stela_linux_workqueue_test_main(void *context);
void stela_linux_i2c_test(void);
void stela_linux_sync_test(void);

/* The owner's clock, which the sync test moves. */
s64 stela_linux_test_now = NSEC_PER_SEC;

static s64 now_ns(void *context)
{
	(void)context;
	return stela_linux_test_now;
}

struct start {
	void *context;
	int (*start_worker)(void *context, unsigned int kind);
};

static struct start start;
static unsigned int started;
static struct kthread_worker *dedicated;
static struct kthread_work dedicated_work, dedicated_cancelled;
static unsigned int dedicated_runs;

static void run_dedicated(struct kthread_work *work)
{
	assert(work == &dedicated_work && current == dedicated->task);
	assert(!current_work() && !kthread_should_stop());
	if (++dedicated_runs == 1)
		assert(kthread_queue_work(dedicated, work));
}

static void forbidden_dedicated(struct kthread_work *work)
{
	(void)work;
	assert(false);
}

static void dedicated_identity_and_join(void)
{
	dedicated = kthread_create_worker(0, "stela-dedicated");
	assert(!IS_ERR(dedicated) && dedicated->task && dedicated->task != current);
	kthread_init_work(&dedicated_work, run_dedicated);
	kthread_init_work(&dedicated_cancelled, forbidden_dedicated);
	assert(kthread_queue_work(dedicated, &dedicated_cancelled));
	assert(kthread_cancel_work_sync(&dedicated_cancelled));
	assert(kthread_queue_work(dedicated, &dedicated_work));
	kthread_flush_worker(dedicated);
	/* A requeue from the running item follows the first flush boundary. */
	kthread_flush_worker(dedicated);
	assert(dedicated_runs == 2);
	kthread_destroy_worker(dedicated);
}

static void dedicated_exhaustion_preserves_both_workqueue_pools(void);
static int start_worker(void *context, unsigned int kind)
{
	(void)context;
	started++;
	return start.start_worker(start.context, kind);
}

static bool forced;

static void shutdown(void *context, bool force)
{
	(void)context;
	forced = force;
}

static unsigned int line_enables, line_disables;
static bool enable_notify, enable_refuse;
static unsigned int enable_primary_calls;

static int irq_enable(void *context, unsigned int irq, bool *unexposed)
{
	(void)context;
	assert(irq == 7);
	*unexposed = false;
	if (enable_refuse) {
		/* Actual bounded software peer: no route/event/callback was issued. */
		*unexposed = true;
		return -ENOSYS;
	}
	line_enables++;
	if (enable_notify)
		stela_linux_irq_run(irq);
	return 0;
}

static irqreturn_t initial_enable_handler(int irq, void *dev_id)
{
	assert(irq == 7 && dev_id == &enable_primary_calls && in_hardirq());
	enable_primary_calls++;
	return IRQ_HANDLED;
}

static int irq_disable(void *context, unsigned int irq)
{
	(void)context;
	assert(irq == 7);
	line_disables++;
	return 0;
}
static int irq_retire(void *context, unsigned int irq)
{
	(void)context;
	assert(irq == 7 && stela_linux_irq_actions_joined(irq));
	return 0;
}

static const struct stela_linux_services services = {
	.now_ns = now_ns,
	.start_worker = start_worker,
	.shutdown = shutdown,
	.irq_enable = irq_enable,
	.irq_disable = irq_disable,
	.irq_retire = irq_retire,
};
static const struct stela_linux_owner owner = {.services = &services};

const struct stela_linux_owner *stela_linux_workqueue_test_owner(void) { return &owner; }

void stela_linux_workqueue_test_bind(void *context, int (*start_worker_fn)(void *context, unsigned int kind))
{
	start = (struct start){.context = context, .start_worker = start_worker_fn};
}

void stela_linux_workqueue_test_worker(void *context, unsigned int kind)
{
	(void)context;
	stela_linux_enter(&owner);
	stela_linux_workers_run(kind);
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

static struct work_struct nice_ordinary, nice_highpri;
static struct task_struct *nice_ordinary_task;
static bool nice_highpri_done;

static void run_nice_highpri(struct work_struct *work)
{
	assert(work == &nice_highpri && current != nice_ordinary_task);
	assert(current->policy == SCHED_NORMAL && task_nice(current) == MIN_NICE);
	assert(current->normal_prio == NICE_TO_PRIO(MIN_NICE));
	nice_highpri_done = true;
}

static void run_nice_ordinary(struct work_struct *work)
{
	assert(work == &nice_ordinary);
	assert(current->policy == SCHED_NORMAL && !task_nice(current));
	nice_ordinary_task = current;
	assert(queue_work(system_highpri_wq, &nice_highpri));
	/* A sleeping ordinary worker must not prevent the independent nice -20
	 * pool from acquiring a real task and completing this dependency. */
	assert(flush_work(&nice_highpri) && nice_highpri_done);
	assert(current == nice_ordinary_task && !task_nice(current));
}

static void highpri_normal_nice_and_independent_pool(void)
{
	INIT_WORK(&nice_ordinary, run_nice_ordinary);
	INIT_WORK(&nice_highpri, run_nice_highpri);
	assert(schedule_work(&nice_ordinary));
	assert(flush_work(&nice_ordinary) && nice_highpri_done);
}

/* Native pool profile: eight General continuations, four permanently
 * reserved for the two nice pools. The main owner occupies one of the other
 * four, so exactly three dedicated workers can be retained simultaneously. */
static void dedicated_exhaustion_preserves_both_workqueue_pools(void)
{
	struct kthread_worker *held[8];
	unsigned int count = 0;
	for (;;) {
		struct kthread_worker *next = kthread_create_worker(0, "stela-capacity");
		if (IS_ERR(next)) {
			assert(PTR_ERR(next) == -ENOMEM || PTR_ERR(next) == -ENOSPC);
			break;
		}
		assert(count < ARRAY_SIZE(held));
		held[count++] = next;
	}
	assert(count == 3);
	/* These execute with all dedicated credits occupied, including a normal
	 * callback waiting on its separately scheduled high-priority dependency. */
	nice_highpri_done = false;
	highpri_normal_nice_and_independent_pool();
	for (unsigned int slot = 0; slot < count; slot++)
		kthread_destroy_worker(held[slot]);
	for (unsigned int pass = 0; pass < 3; pass++) {
		struct kthread_worker *recreated = kthread_create_worker(0, "stela-recreated");
		assert(!IS_ERR(recreated) && recreated->task != current);
		kthread_destroy_worker(recreated);
	}
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
	assert(current->policy == SCHED_NORMAL && task_nice(current) == MIN_NICE);
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

	highpri_normal_nice_and_independent_pool();
	orderly_poweroff(true);
	flush_workqueue(system_wq);
	assert(forced);

	/* Two sharers: the oneshot's thread keeps the line masked until it ends. */
	/* A truly unexposed refusal removes only this initialized action; retry
	 * proves there is no phantom list member. The next native enable delivers
	 * synchronously while request_irq still holds its request mutex. */
	enable_refuse = true;
	assert(request_irq(7, initial_enable_handler, 0, "initial-refused", &enable_primary_calls) == -ENOSYS);
	assert(!enable_primary_calls && !line_enables);
	enable_refuse = false;
	enable_notify = true;
	assert(!request_irq(7, initial_enable_handler, 0, "initial-visible", &enable_primary_calls));
	assert(enable_primary_calls == 1);
	enable_notify = false;
	free_irq(7, &enable_primary_calls);
	line_enables = line_disables = 0;

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
	dedicated_identity_and_join();
	dedicated_exhaustion_preserves_both_workqueue_pools();
	stela_linux_sync_test();
	stela_linux_exit();
}
