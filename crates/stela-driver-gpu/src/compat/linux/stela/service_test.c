// SPDX-License-Identifier: MIT
/* A task sleeping on a service task's timer, then waiting for what a raised
 * line's handler queued for a worker. */
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <stela/linux.h>
#include <stela/test.h>

#define LINE 7

struct service_test {
	const struct stela_linux_owner *owner;
	void *context;
	void (*raise)(void *context, unsigned int line);
};

void stela_linux_service_test_body(void *context);

static DECLARE_COMPLETION(done);
static struct work_struct work;
static unsigned int handled;

static void finish_work(struct work_struct *item)
{
	assert(item == &work && handled == 1);
	complete(&done);
}

static irqreturn_t handle(int irq, void *data)
{
	assert(irq == LINE && data == &handled && in_hardirq());
	handled++;
	schedule_work(&work);
	return IRQ_HANDLED;
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
	free_irq(LINE, &handled);
	stela_linux_exit();
}
