// SPDX-License-Identifier: MIT
/* Linux's workqueues on the original worker tasks. */
#include <linux/backing-dev.h>
#include <linux/interrupt.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <stela/catalogue.h>
#include <stela/irq.h>
#include <stela/linux.h>
#include <stela/test.h>

void stela_linux_workqueue_test_main(void);
void stela_linux_workqueue_test_shutdown(bool force);
int stela_linux_workqueue_test_irq_enable(unsigned int irq, bool *unexposed);
int stela_linux_workqueue_test_irq_disable(unsigned int irq);
int stela_linux_workqueue_test_irq_retire(unsigned int irq);
void stela_linux_i2c_test(void);
void stela_linux_sync_test(void);

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
static bool forced;
static DECLARE_COMPLETION(shutdown_done);

void stela_linux_workqueue_test_shutdown(bool force)
{
	forced = force;
	complete(&shutdown_done);
}

static unsigned int line_enables, line_disables;
static bool enable_notify, enable_refuse;
static unsigned int enable_primary_calls;

int stela_linux_workqueue_test_irq_enable(unsigned int irq, bool *unexposed)
{
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

int stela_linux_workqueue_test_irq_disable(unsigned int irq)
{
	assert(irq == 7);
	line_disables++;
	return 0;
}
int stela_linux_workqueue_test_irq_retire(unsigned int irq)
{
	assert(irq == 7 && stela_linux_irq_actions_joined(irq));
	return 0;
}

static struct workqueue_struct *wq, *ordered;
static struct work_struct outer, inner, steps[3], cancelled, shared;
static struct delayed_work later;
static DECLARE_COMPLETION(later_ran);
static struct task_struct *outer_task;
static bool outer_done, inner_done, shared_done, later_done, cancelled_ran;
static char order[4];
static unsigned int order_length;

static void run_inner(struct work_struct *work)
{
	assert(work == &inner && current_work() == &inner && current != outer_task);
	inner_done = true;
}

/* Waits for another item, which needs a second worker. */
static void run_outer(struct work_struct *work)
{
	assert(work == &outer && !work_pending(work));
	outer_task = current;
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
	complete(&later_ran);
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
	nice_highpri_done = false;
	INIT_WORK(&nice_ordinary, run_nice_ordinary);
	INIT_WORK(&nice_highpri, run_nice_highpri);
	assert(schedule_work(&nice_ordinary));
	assert(flush_work(&nice_ordinary) && nice_highpri_done);
}

/* Keep allocating original workers until the mounted runtime refuses a fork.
 * The original workqueue pools already have their own retained workers. */
static void dedicated_exhaustion_preserves_both_workqueue_pools(void)
{
	struct kthread_worker *held[16];
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
	assert(count >= 3);
	/* These execute with the remaining stacks occupied, including a normal
	 * callback waiting on its separately scheduled high-priority dependency. */
	highpri_normal_nice_and_independent_pool();
	for (unsigned int slot = 0; slot < count; slot++)
		kthread_destroy_worker(held[slot]);
	rcu_barrier();
	for (unsigned int slot = 0; slot < 3; slot++) {
		held[slot] = kthread_create_worker(0, "stela-recreated");
		assert(!IS_ERR(held[slot]) && held[slot]->task != current);
	}
	for (unsigned int slot = 0; slot < 3; slot++)
		kthread_destroy_worker(held[slot]);
	rcu_barrier();
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

void stela_linux_workqueue_test_main(void)
{
	/* PID1 publishes the writeback queue only after the original workqueue
	 * startup and topology passes have returned. Early system queues alone
	 * do not permit flush_work. */
	for (unsigned int tick = 0; tick < HZ && !READ_ONCE(bdi_wq); tick++)
		schedule_timeout_uninterruptible(1);
	assert(READ_ONCE(bdi_wq));
	highpri_normal_nice_and_independent_pool();
	dedicated_exhaustion_preserves_both_workqueue_pools();
	wq = alloc_workqueue("stela-test-%d", WQ_UNBOUND, 2, 1);
	ordered = alloc_ordered_workqueue("stela-ordered", 0);
	assert(wq && ordered && !current_work());
	const struct stela_linux_owner *owner = stela_linux_owner();
	assert(stela_linux_kernel_claim(owner) == -EALREADY);
	assert(!stela_linux_kernel_catalogue_active());
	INIT_WORK(&outer, run_outer);
	INIT_WORK(&inner, run_inner);
	assert(queue_work(wq, &outer));
	assert(flush_work(&outer) && outer_done && inner_done && !flush_work(&outer));
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
	later_done = false;
	reinit_completion(&later_ran);
	assert(queue_delayed_work(wq, &later, 2) && !later_done);
	assert(wait_for_completion_timeout(&later_ran, HZ) && later_done);
	flush_delayed_work(&later);
	destroy_workqueue(ordered);
	destroy_workqueue(wq);
	assert(stela_linux_kernel_claim(owner) == -EALREADY);
	assert(!stela_linux_kernel_catalogue_active());

	orderly_poweroff(true);
	assert(wait_for_completion_timeout(&shutdown_done, HZ) && forced);

	/* Two sharers: the oneshot's thread keeps the line masked until it ends. */
	/* A truly unexposed refusal removes only this initialized action; retry
	 * proves there is no phantom list member. The software peer then delivers
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
	stela_linux_sync_test();
}
