// SPDX-License-Identifier: MIT
/* Linux's kthread workers, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/kthread.c. A worker's items
 * run in order on an ordered workqueue, whose tasks the owner starts. It has
 * no task of its own: worker->task is its creator, which Linux's callers only
 * wake and prioritize. */
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

struct stela_worker {
	struct kthread_worker worker;
	struct workqueue_struct *queue;
	struct work_struct pump;
};

static struct stela_worker *stela_worker(struct kthread_worker *worker)
{
	return container_of(worker, struct stela_worker, worker);
}

/* Items run with the lock released; each may queue more. */
static void run_items(struct work_struct *pump)
{
	struct kthread_worker *worker = &container_of(pump, struct stela_worker, pump)->worker;
	unsigned long flags;

	raw_spin_lock_irqsave(&worker->lock, flags);
	while (!list_empty(&worker->work_list)) {
		struct kthread_work *work =
			list_first_entry(&worker->work_list, struct kthread_work, node);

		list_del_init(&work->node);
		worker->current_work = work;
		raw_spin_unlock_irqrestore(&worker->lock, flags);
		work->func(work);
		raw_spin_lock_irqsave(&worker->lock, flags);
		worker->current_work = NULL;
	}
	raw_spin_unlock_irqrestore(&worker->lock, flags);
}

struct kthread_worker *kthread_create_worker_on_node(unsigned int flags, int node,
						     const char namefmt[], ...)
{
	(void)node;
	struct stela_worker *worker = kzalloc_obj(*worker);
	char name[32];
	va_list arguments;

	if (!worker)
		return ERR_PTR(-ENOMEM);
	va_start(arguments, namefmt);
	vsnprintf(name, sizeof(name), namefmt, arguments);
	va_end(arguments);
	__kthread_init_worker(&worker->worker, "stela", NULL);
	worker->worker.flags = flags;
	worker->worker.task = current;
	INIT_WORK(&worker->pump, run_items);
	worker->queue = alloc_ordered_workqueue("%s", 0, name);
	if (!worker->queue) {
		kfree(worker);
		return ERR_PTR(-ENOMEM);
	}
	return &worker->worker;
}

void __kthread_init_worker(struct kthread_worker *worker, const char *name,
			   struct lock_class_key *key)
{
	(void)name;
	(void)key;
	memset(worker, 0, sizeof(*worker));
	raw_spin_lock_init(&worker->lock);
	INIT_LIST_HEAD(&worker->work_list);
	INIT_LIST_HEAD(&worker->delayed_work_list);
}

/* Before position in the worker's list. */
static void insert(struct kthread_worker *worker, struct kthread_work *work, struct list_head *pos)
{
	list_add_tail(&work->node, pos);
	work->worker = worker;
	queue_work(stela_worker(worker)->queue, &stela_worker(worker)->pump);
}

bool kthread_queue_work(struct kthread_worker *worker, struct kthread_work *work)
{
	unsigned long flags;
	bool queued = false;

	raw_spin_lock_irqsave(&worker->lock, flags);
	if (list_empty(&work->node) && !work->canceling) {
		insert(worker, work, &worker->work_list);
		queued = true;
	}
	raw_spin_unlock_irqrestore(&worker->lock, flags);
	return queued;
}

struct flush {
	struct kthread_work work;
	struct completion done;
};

static void flushed(struct kthread_work *work)
{
	complete(&container_of(work, struct flush, work)->done);
}

void kthread_flush_worker(struct kthread_worker *worker)
{
	struct flush flush = {
		KTHREAD_WORK_INIT(flush.work, flushed),
		COMPLETION_INITIALIZER_ONSTACK(flush.done),
	};

	kthread_queue_work(worker, &flush.work);
	wait_for_completion(&flush.done);
}

/* Waits for work, queued or running, by a flush item right behind it. */
void kthread_flush_work(struct kthread_work *work)
{
	struct kthread_worker *worker = work->worker;
	struct flush flush = {
		KTHREAD_WORK_INIT(flush.work, flushed),
		COMPLETION_INITIALIZER_ONSTACK(flush.done),
	};
	unsigned long flags;
	bool waiting = true;

	if (!worker)
		return;
	raw_spin_lock_irqsave(&worker->lock, flags);
	if (!list_empty(&work->node))
		insert(worker, &flush.work, work->node.next);
	else if (worker->current_work == work)
		insert(worker, &flush.work, worker->work_list.next);
	else
		waiting = false;
	raw_spin_unlock_irqrestore(&worker->lock, flags);
	if (waiting)
		wait_for_completion(&flush.done);
}

bool kthread_cancel_work_sync(struct kthread_work *work)
{
	struct kthread_worker *worker = work->worker;
	unsigned long flags;
	bool pending = false;

	if (!worker)
		return false;
	raw_spin_lock_irqsave(&worker->lock, flags);
	if (!list_empty(&work->node)) {
		list_del_init(&work->node);
		pending = true;
	}
	bool running = worker->current_work == work;

	if (running)
		work->canceling++;
	raw_spin_unlock_irqrestore(&worker->lock, flags);
	if (running) {
		kthread_flush_work(work);
		raw_spin_lock_irqsave(&worker->lock, flags);
		work->canceling--;
		raw_spin_unlock_irqrestore(&worker->lock, flags);
	}
	return pending;
}

void kthread_destroy_worker(struct kthread_worker *worker)
{
	kthread_flush_worker(worker);
	WARN_ON(!list_empty(&worker->work_list));
	destroy_workqueue(stela_worker(worker)->queue);
	kfree(stela_worker(worker));
}

/* Stela's tasks have no priorities. */
void sched_set_fifo(struct task_struct *p)
{
	(void)p;
}
