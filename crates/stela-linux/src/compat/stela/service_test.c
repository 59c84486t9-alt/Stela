// SPDX-License-Identifier: MIT
/* A task sleeping on a service task's timer, then waiting for what a raised
 * line's handler queued for a worker. */
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/irq.h>
#include <stela/test.h>

#define LINE 7

struct service_test {
	const struct stela_linux_owner *owner;
	void *context;
	void (*raise)(void *context, unsigned int line);
	bool (*masked)(void *context, unsigned int line);
};

void stela_linux_service_test_leaf_context(void);
void stela_linux_service_test_leaf_context(void)
{
	assert(stela_linux_atomic_callback_active());
	assert(!in_interrupt() && !preempt_count() && !irqs_disabled());
	assert(stela_linux_owner());
}

void stela_linux_service_test_body(void *context);

static DECLARE_COMPLETION(done);
static struct work_struct work;
static unsigned int handled;

static void finish_work(struct work_struct *item)
{
	assert(item == &work && handled >= 1 && handled <= 2);
	complete(&done);
}

static irqreturn_t handle(int irq, void *data)
{
	assert(irq == LINE && data == &handled && in_hardirq());
	handled++;
	schedule_work(&work);
	return IRQ_HANDLED;
}

static DECLARE_COMPLETION(shared_a_done);
static DECLARE_COMPLETION(shared_b_entered);
static DECLARE_COMPLETION(shared_b_gate);
static DECLARE_COMPLETION(shared_b_done);
static int shared_a, shared_b;
static bool wake_b = true;
static unsigned int shared_a_runs;
static irqreturn_t shared_primary(int irq, void *data)
{
	assert(irq == LINE && (data == &shared_a || data == &shared_b));
	return data == &shared_a || wake_b ? IRQ_WAKE_THREAD : IRQ_HANDLED;
}
static irqreturn_t shared_thread(int irq, void *data)
{
	assert(irq == LINE);
	if (data == &shared_a) {
		shared_a_runs++;
		complete(&shared_a_done);
	} else {
		assert(data == &shared_b);
		complete(&shared_b_entered);
		wait_for_completion(&shared_b_gate);
		complete(&shared_b_done);
	}
	return IRQ_HANDLED;
}
static void shared_oneshot_controls(const struct service_test *test)
{
	unsigned long flags = IRQF_SHARED | IRQF_ONESHOT;
	assert(!request_threaded_irq(LINE, shared_primary, shared_thread, flags, "A", &shared_a));
	assert(!request_threaded_irq(LINE, shared_primary, shared_thread, flags, "B", &shared_b));
	test->raise(test->context, LINE);
	wait_for_completion(&shared_a_done);
	wait_for_completion(&shared_b_entered);
	msleep(2);
	assert(test->masked(test->context, LINE));
	complete(&shared_b_gate);
	wait_for_completion(&shared_b_done);
	assert(!test->masked(test->context, LINE));
	free_irq(LINE, &shared_a);
	free_irq(LINE, &shared_b);

	/* Cancel queued masked A while live B does not need its thread. */
	wake_b = false;
	assert(!request_threaded_irq(LINE, shared_primary, shared_thread, flags, "A", &shared_a));
	assert(!request_threaded_irq(LINE, shared_primary, shared_thread, flags, "B", &shared_b));
	stela_linux_irq_run(LINE);
	assert(test->masked(test->context, LINE));
	free_irq(LINE, &shared_a);
	assert(shared_a_runs == 1);
	assert(!test->masked(test->context, LINE));
	free_irq(LINE, &shared_b);
}

void stela_linux_service_test_body(void *context)
{
	const struct service_test *test = context;

	stela_linux_enter(test->owner);
	INIT_WORK(&work, finish_work);
	assert(!request_irq(LINE, handle, 0, "test", &handled));
	msleep(2);
	test->raise(test->context, LINE);
	wait_for_completion(&done);
	/* A raised notification from the old action must not become work for
	 * a replacement action at the same logical IRQ/configuration epoch. */
	test->raise(test->context, LINE);
	free_irq(LINE, &handled);
	assert(!request_irq(LINE, handle, 0, "replacement", &handled));
	msleep(2);
	assert(handled == 1);
	test->raise(test->context, LINE);
	wait_for_completion(&done);
	assert(handled == 2);
	free_irq(LINE, &handled);
	shared_oneshot_controls(test);
	stela_linux_exit();
}
