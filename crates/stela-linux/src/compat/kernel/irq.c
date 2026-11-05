// SPDX-License-Identifier: MIT
/* Linux's interrupt requests, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/irq/manage.c. A platform
 * ISR runs no Linux code: it raises the line on the owner's service, which
 * calls stela_linux_irq_run in process context, and the handlers run in a
 * hard-IRQ scope there. Threaded handlers run as work, which may sleep as an
 * IRQ thread does. The owner routes each line (irq_enable, irq_disable). */
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <stela/atomic_callback.h>
#include <stela/irq.h>
#include <stela/linux.h>

struct irq_line;
struct requested {
	struct list_head node;
	struct irqaction action;
	struct irq_line *line;
	struct work_struct thread;
	bool closing;
	bool thread_active;
	bool thread_joined;
};

static LIST_HEAD(requests);
/* Like the selected original irq_desc request mutex, this serializes only
 * one logical line across real sleeping action-thread joins. Global line
 * metadata remains with the one canonical C image for kernel lifetime. */
struct irq_line {
	struct list_head node;
	unsigned int irq;
	struct mutex request_mutex;
	bool oneshot_masked;
};
static LIST_HEAD(lines);
static DEFINE_MUTEX(lines_mutex);
static struct irq_line *line_owner(unsigned int irq, bool create)
{
	struct irq_line *line;
	mutex_lock(&lines_mutex);
	list_for_each_entry(line, &lines, node)
		if (line->irq == irq) {
			mutex_unlock(&lines_mutex);
			return line;
		}
	line = create ? kzalloc_obj(*line) : NULL;
	if (line) {
		line->irq = irq;
		mutex_init(&line->request_mutex);
		list_add_tail(&line->node, &lines);
	}
	mutex_unlock(&lines_mutex);
	return line;
}

static int enable_line(unsigned int irq, bool *unexposed)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	*unexposed = false;
	if (!owner->services->irq_enable) {
		/* No native callback was invoked or route published. */
		*unexposed = true;
		stela_linux_unsupported("interrupt lines");
		return -ENOSYS;
	}
	return owner->services->irq_enable(owner->context, irq, unexposed);
}

static void disable_line(unsigned int irq)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!owner->services->irq_disable ||
	    owner->services->irq_disable(owner->context, irq))
		stela_linux_fatal("IRQ source mask unavailable; request retained");
}

static void retire_line(unsigned int irq)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!owner->services->irq_retire ||
	    owner->services->irq_retire(owner->context, irq))
		/* Existing no-return fatal/trap boundary: no normal C return,
		 * request unlink/free or caller dev_id reclamation before the trap.
		 * Trap disposition itself is not task cancellation/join evidence. */
		stela_linux_fatal("IRQ action retirement unavailable; request retained");
}

/* Checked by the exact native service epoch join, after free_irq canceled
 * each closing action's real work. A mask/root fence alone never sets this. */
bool stela_linux_irq_actions_joined(unsigned int irq)
{
	struct requested *request;
	bool found = false;
	list_for_each_entry(request, &requests, node)
		if (request->action.irq == irq) {
			found = true;
			if (!request->closing || !request->thread_joined)
				return false;
		}
	return found;
}

/* Every outstanding shared ONESHOT action, including one being canceled,
 * keeps the physical line masked. A closing thread ceases to count only after
 * its real callback returns or cancel_work_sync actually joins/removes it. */
static void maybe_rearm(struct irq_line *line)
{
	struct requested *request;
	bool live = false;
	if (!READ_ONCE(line->oneshot_masked))
		return;
	list_for_each_entry(request, &requests, node) {
		if (request->action.irq != line->irq)
			continue;
		if (!READ_ONCE(request->closing))
			live = true;
		if ((request->action.flags & IRQF_ONESHOT) &&
			READ_ONCE(request->thread_active))
			return;
	}
	if (live) {
		bool unexposed = false;
		if (enable_line(line->irq, &unexposed))
			stela_linux_fatal("IRQ oneshot rearm unavailable; action retained");
		WRITE_ONCE(line->oneshot_masked, false);
	}
}

/* A threaded action's handler; a oneshot line stays masked until it ends. */
static void run_thread(struct work_struct *work)
{
	struct requested *request = container_of(work, struct requested, thread);
	struct irqaction *action = &request->action;

	action->thread_fn((int)action->irq, action->dev_id);
	WRITE_ONCE(request->thread_active, false);
	if (action->flags & IRQF_ONESHOT)
		maybe_rearm(request->line);
}

/* The primary handler of an action with only a threaded one. */
static irqreturn_t wake_thread(int irq, void *dev_id)
{
	(void)irq;
	(void)dev_id;
	return IRQ_WAKE_THREAD;
}

static int request_irq_locked(struct irq_line *line, unsigned int irq, irq_handler_t handler, irq_handler_t thread_fn,
			 unsigned long flags, const char *name, void *dev)
{
	if (in_interrupt())
		return -EINVAL;
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
	request->line = line;
	request->action = (struct irqaction){
		.handler = handler ? handler : wake_thread,
		.thread_fn = thread_fn,
		.dev_id = dev,
		.irq = irq,
		.flags = (unsigned int)flags,
		.name = name,
	};
	INIT_WORK(&request->thread, run_thread);
	/* Publish the fully initialized action before enable can deliver a
	 * synchronous notification or yield to this owner's real service task. */
	list_add_tail(&request->node, &requests);
	if (first && !(flags & IRQF_NO_AUTOEN)) {
		bool unexposed = false;
		int error = enable_line(irq, &unexposed);
		if (error) {
			if (!unexposed)
				stela_linux_fatal("IRQ enable uncertain; published request retained");
			/* Only the exact unused native owners/service epoch proof permits
			 * returning an error that lets the caller reclaim dev_id. */
			list_del(&request->node);
			kfree(request);
			return error;
		}
	}
	return 0;
}

int request_threaded_irq(unsigned int irq, irq_handler_t handler, irq_handler_t thread_fn,
						unsigned long flags, const char *name, void *dev)
{
	if (in_interrupt())
		return -EINVAL;
	struct irq_line *line = line_owner(irq, true);
	if (!line)
		return -ENOMEM;
	mutex_lock(&line->request_mutex);
	int result = request_irq_locked(line, irq, handler, thread_fn, flags, name, dev);
	mutex_unlock(&line->request_mutex);
	return result;
}

static const void *free_irq_locked(unsigned int irq, void *dev_id)
{
	struct requested *request;
	/* Primary callbacks are atomic, and joining one's own IRQ work would
	 * deadlock. Never turn either invalid caller into a completed free. */
	if (in_interrupt())
		stela_linux_fatal("free_irq in interrupt context");
	list_for_each_entry(request, &requests, node) {
		if (request->action.irq != irq || request->action.dev_id != dev_id)
			continue;
		if (current_work() == &request->thread)
			stela_linux_fatal("free_irq from its own IRQ thread");
		const char *name = request->action.name;
		bool last = true;
		struct requested *other;
		list_for_each_entry(other, &requests, node)
			if (other != request && other->action.irq == irq)
				last = false;
		/* Canonical single-owner service CPU serializes primary callbacks.
		 * Keep the node/dev_id through real thread and native epoch joins. */
		WRITE_ONCE(request->closing, true);
		if (last)
			disable_line(irq);
		cancel_work_sync(&request->thread);
		WRITE_ONCE(request->thread_active, false);
		WRITE_ONCE(request->thread_joined, true);
		if (last)
			retire_line(irq);
		struct irq_line *line = request->line;
		list_del(&request->node);
		kfree(request);
		if (last)
			WRITE_ONCE(line->oneshot_masked, false);
		else
			maybe_rearm(line);
		return name;
	}
	WARN(1, "Trying to free already-free IRQ %u\n", irq);
	return NULL;
}

const void *free_irq(unsigned int irq, void *dev_id)
{
	struct requested *request;
	if (in_interrupt())
		stela_linux_fatal("free_irq in interrupt context");
	/* Check self-join before acquiring a mutex another free_irq may hold
	 * while cancel_work_sync waits for this very IRQ thread. */
	list_for_each_entry(request, &requests, node)
		if (request->action.irq == irq && request->action.dev_id == dev_id &&
			current_work() == &request->thread)
			stela_linux_fatal("free_irq from its own IRQ thread");
	struct irq_line *line = line_owner(irq, false);
	if (!line) {
		WARN(1, "Trying to free already-free IRQ %u\n", irq);
		return NULL;
	}
	mutex_lock(&line->request_mutex);
	const void *name = free_irq_locked(irq, dev_id);
	mutex_unlock(&line->request_mutex);
	return name;
}

void stela_linux_irq_run(unsigned int irq)
{
	struct stela_linux_atomic_callback scope;
	struct requested *request;

	stela_linux_atomic_callback_begin(&scope);
	list_for_each_entry(request, &requests, node) {
		struct irqaction *action = &request->action;
		if (action->irq != irq || READ_ONCE(request->closing) ||
		    ((action->flags & IRQF_ONESHOT) && READ_ONCE(request->thread_active)) ||
		    !(action->handler((int)irq, action->dev_id) & IRQ_WAKE_THREAD))
			continue;
		if (WARN_ON_ONCE(!action->thread_fn))
			continue;
		if (action->flags & IRQF_ONESHOT) {
			disable_line(irq);
			WRITE_ONCE(request->line->oneshot_masked, true);
		}
		WRITE_ONCE(request->thread_active, true);
		queue_work(system_highpri_wq, &request->thread);
	}
	stela_linux_atomic_callback_end(&scope);
}
