// SPDX-License-Identifier: MIT
/* Linux's interrupt requests, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/irq/manage.c. A platform
 * ISR runs no Linux code: it raises the line on the owner's service, which
 * calls stela_linux_irq_run in process context, and the handlers run in a
 * hard-IRQ scope there. Threaded handlers run as work, which may sleep as an
 * IRQ thread does. The owner routes each line (irq_enable, irq_disable). */
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <stela/atomic_callback.h>
#include <stela/irq.h>
#include <stela/linux.h>

struct requested {
	struct list_head node;
	struct irqaction action;
	struct work_struct thread;
};

static LIST_HEAD(requests);

static bool line_requested(unsigned int irq)
{
	struct requested *request;

	list_for_each_entry(request, &requests, node)
		if (request->action.irq == irq)
			return true;
	return false;
}

static int enable_line(unsigned int irq)
{
	const struct stela_linux_owner *owner = stela_linux_owner();

	if (!owner->services->irq_enable) {
		stela_linux_unsupported("interrupt lines");
		return -ENOSYS;
	}
	return owner->services->irq_enable(owner->context, irq);
}

static void disable_line(unsigned int irq)
{
	const struct stela_linux_owner *owner = stela_linux_owner();

	if (owner->services->irq_disable)
		owner->services->irq_disable(owner->context, irq);
}

/* A threaded action's handler; a oneshot line stays masked until it ends. */
static void run_thread(struct work_struct *work)
{
	struct requested *request = container_of(work, struct requested, thread);
	struct irqaction *action = &request->action;

	action->thread_fn((int)action->irq, action->dev_id);
	if (action->flags & IRQF_ONESHOT)
		WARN_ON(enable_line(action->irq));
}

/* The primary handler of an action with only a threaded one. */
static irqreturn_t wake_thread(int irq, void *dev_id)
{
	(void)irq;
	(void)dev_id;
	return IRQ_WAKE_THREAD;
}

int request_threaded_irq(unsigned int irq, irq_handler_t handler, irq_handler_t thread_fn,
			 unsigned long flags, const char *name, void *dev)
{
	if (irq == IRQ_NOTCONNECTED)
		return -ENOTCONN;
	if ((flags & IRQF_SHARED) && !dev)
		return -EINVAL;
	if (!handler && !thread_fn)
		return -EINVAL;
	struct requested *other;
	bool first = true;
	list_for_each_entry(other, &requests, node) {
		if (other->action.irq != irq)
			continue;
		if (!(flags & other->action.flags & IRQF_SHARED))
			return -EBUSY;
		first = false;
	}
	struct requested *request = kzalloc_obj(*request);
	if (!request)
		return -ENOMEM;
	request->action = (struct irqaction){
		.handler = handler ? handler : wake_thread,
		.thread_fn = thread_fn,
		.dev_id = dev,
		.irq = irq,
		.flags = (unsigned int)flags,
		.name = name,
	};
	INIT_WORK(&request->thread, run_thread);
	if (first && !(flags & IRQF_NO_AUTOEN)) {
		int error = enable_line(irq);
		if (error) {
			kfree(request);
			return error;
		}
	}
	list_add_tail(&request->node, &requests);
	return 0;
}

const void *free_irq(unsigned int irq, void *dev_id)
{
	struct requested *request;

	list_for_each_entry(request, &requests, node) {
		if (request->action.irq != irq || request->action.dev_id != dev_id)
			continue;
		const char *name = request->action.name;
		list_del(&request->node);
		if (!line_requested(irq))
			disable_line(irq);
		cancel_work_sync(&request->thread);
		kfree(request);
		return name;
	}
	WARN(1, "Trying to free already-free IRQ %u\n", irq);
	return NULL;
}

void stela_linux_irq_run(unsigned int irq)
{
	struct stela_linux_atomic_callback scope;
	struct requested *request;

	stela_linux_atomic_callback_begin(&scope);
	list_for_each_entry(request, &requests, node) {
		struct irqaction *action = &request->action;
		if (action->irq != irq ||
		    !(action->handler((int)irq, action->dev_id) & IRQ_WAKE_THREAD))
			continue;
		if (WARN_ON_ONCE(!action->thread_fn))
			continue;
		if (action->flags & IRQF_ONESHOT)
			disable_line(irq);
		queue_work(system_highpri_wq, &request->thread);
	}
	stela_linux_atomic_callback_end(&scope);
}
