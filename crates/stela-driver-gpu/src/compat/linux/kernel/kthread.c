// SPDX-License-Identifier: MIT
/* Linux's kthread workers, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/kthread.c. A worker's items
 * run in order on their own retained task, which the native owner starts.
 * The published task reference remains valid through stop and join. */
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/wait_bit.h>
#include <stela/workqueue.h>

struct stela_worker {
	struct kthread_worker worker;
	struct list_head node;
	char name[TASK_COMM_LEN];
	bool stopping, done;
};

static LIST_HEAD(kthreads);

static struct stela_worker *stela_worker(struct kthread_worker *worker)
{
	return container_of(worker, struct stela_worker, worker);
}

/* Items run with the lock released; each may queue more. */
static void run_items(void *context)
{
	struct stela_worker *thread = context;
	struct kthread_worker *worker = &thread->worker;
	unsigned long flags;
	strscpy(current->comm, thread->name, sizeof(current->comm));
	get_task_struct(current);
	WRITE_ONCE(worker->task, current);
	wake_up_var(&worker->task);

	raw_spin_lock_irqsave(&worker->lock, flags);
	for (;;) {
		if (list_empty(&worker->work_list)) {
			if (thread->stopping)
				break;
			set_current_state(TASK_INTERRUPTIBLE);
			raw_spin_unlock_irqrestore(&worker->lock, flags);
			schedule();
			raw_spin_lock_irqsave(&worker->lock, flags);
			continue;
		}
		__set_current_state(TASK_RUNNING);
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
	__set_current_state(TASK_RUNNING);
	list_del_init(&thread->node);
	/* No callback, yield or context access follows this acknowledgement.
	 * The native wrapper exits its owner using its own retained storage. */
	WRITE_ONCE(thread->done, true);
	wake_up_var(&thread->done);
}

struct kthread_worker *kthread_create_worker_on_node(unsigned int flags, int node,
						     const char namefmt[], ...)
{
	(void)node;
	if (flags & ~(unsigned int)KTW_FREEZABLE)
		return ERR_PTR(-EINVAL);
	struct stela_worker *worker = kzalloc_obj(*worker);
	va_list arguments;

	if (!worker)
		return ERR_PTR(-ENOMEM);
	va_start(arguments, namefmt);
	vsnprintf(worker->name, sizeof(worker->name), namefmt, arguments);
	va_end(arguments);
	__kthread_init_worker(&worker->worker, "stela", NULL);
	worker->worker.flags = flags;
	list_add_tail(&worker->node, &kthreads);
	int error = stela_linux_start_task(run_items, worker);
	if (error) {
		list_del(&worker->node);
		kfree(worker);
		return ERR_PTR(error);
	}
	wait_var_event(&worker->worker.task, READ_ONCE(worker->worker.task));
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
	wake_up_process(worker->task);
}

bool kthread_queue_work(struct kthread_worker *worker, struct kthread_work *work)
{
	unsigned long flags;
	bool queued = false;

	raw_spin_lock_irqsave(&worker->lock, flags);
	if (list_empty(&work->node) && !work->canceling && !stela_worker(worker)->stopping) {
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
	if (WARN_ON_ONCE(current == worker->task))
		return;
	kthread_flush_worker(worker);
	WARN_ON(!list_empty(&worker->work_list));
	struct stela_worker *thread = stela_worker(worker);
	unsigned long flags;
	raw_spin_lock_irqsave(&worker->lock, flags);
	thread->stopping = true;
	wake_up_process(worker->task);
	put_task_struct(worker->task);
	raw_spin_unlock_irqrestore(&worker->lock, flags);
	wait_var_event(&thread->done, READ_ONCE(thread->done));
	kfree(thread);
}

bool kthread_should_stop(void)
{
	struct stela_worker *thread;
	list_for_each_entry(thread, &kthreads, node)
		if (thread->worker.task == current)
			return thread->stopping;
	return false;
}

bool kthread_should_stop_or_park(void) { return kthread_should_stop(); }
