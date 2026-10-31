// SPDX-License-Identifier: MIT
/* Linux's workqueues, following Linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8
 * kernel/workqueue.c. Work runs on worker tasks the owner starts on request
 * (its start_worker service), each running stela_linux_workers_run until no
 * work it may take remains. As Linux's concurrency management does, workers
 * keep one of them runnable while work is pending: when the last runnable one
 * sleeps, another is requested, so a work item may wait for another. A
 * workqueue runs at most max_active of its items at once, an ordered one a
 * single item at a time in queueing order, and no work item runs on two
 * workers at once. Each queueing takes the next sequence number, kept in the
 * item's data above Linux's flag bits, so a flush waits only for what was
 * queued before it. Linux code runs in one context at a time, which
 * serializes everything here. BH workqueues, which run work in softirq
 * context, are not provided. */
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <stela/linux.h>
#include <stela/workqueue.h>

#define SEQ_SHIFT WORK_STRUCT_FLAG_BITS
/* As kernel/workqueue.c bounds a workqueue's name. */
#define WQ_NAME_LEN 32

struct workqueue_struct {
	/* In every_queue from allocation, or a system queue's first work, to
	 * destruction. */
	struct list_head node;
	struct list_head pending;
	unsigned int flags;
	int max_active;
	int active;
	char name[WQ_NAME_LEN];
};

struct worker {
	struct list_head node;
	struct task_struct *task;
	struct work_struct *work;
	struct workqueue_struct *wq;
	unsigned long seq;
	bool sleeping, highpri;
};

static LIST_HEAD(every_queue);
static LIST_HEAD(workers);
/* Workers requested but not yet running. */
static unsigned int starting;
/* The two NORMAL nice pools have independent runnable/start accounting. */
static unsigned int pool_starting[2];
struct task_request {
	struct list_head node;
	void (*run)(void *);
	void *context;
};
static LIST_HEAD(task_requests);
static unsigned int dedicated_starting;
static unsigned long last_seq;
/* Woken whenever a run ends or a pending item is cancelled. */
static DECLARE_WAIT_QUEUE_HEAD(work_done);

#define SYSTEM_WQ(object, wq_name, wq_flags)                                         \
	static struct workqueue_struct object##_struct = {                           \
		.node = LIST_HEAD_INIT(object##_struct.node),                        \
		.pending = LIST_HEAD_INIT(object##_struct.pending),                  \
		.flags = (wq_flags),                                                 \
		.max_active = WQ_DFL_ACTIVE,                                         \
		.name = wq_name,                                                     \
	};                                                                           \
	struct workqueue_struct *object = &object##_struct

SYSTEM_WQ(system_percpu_wq, "events", WQ_PERCPU);
SYSTEM_WQ(system_highpri_wq, "events_highpri", WQ_PERCPU | WQ_HIGHPRI);
SYSTEM_WQ(system_long_wq, "events_long", WQ_PERCPU);
SYSTEM_WQ(system_dfl_wq, "events_unbound", WQ_UNBOUND);
SYSTEM_WQ(system_freezable_wq, "events_freezable", WQ_PERCPU | WQ_FREEZABLE);
SYSTEM_WQ(system_power_efficient_wq, "events_power_efficient", WQ_PERCPU);
SYSTEM_WQ(system_freezable_power_efficient_wq, "events_freezable_pwr_efficient",
	  WQ_PERCPU | WQ_FREEZABLE);
SYSTEM_WQ(system_dfl_long_wq, "events_dfl_long", WQ_UNBOUND);
/* Linux's older names for two of them. */
struct workqueue_struct *system_wq = &system_percpu_wq_struct;
struct workqueue_struct *system_unbound_wq = &system_dfl_wq_struct;

static unsigned long seq_of(struct work_struct *work)
{
	return (unsigned long)atomic_long_read(&work->data) >> SEQ_SHIFT;
}

/* Pending on a workqueue, rather than on a delayed item's timer. */
static bool queued(struct work_struct *work)
{
	return work_pending(work) && !list_empty(&work->entry);
}

static struct worker *worker_of(struct task_struct *task)
{
	struct worker *worker;
	list_for_each_entry(worker, &workers, node)
		if (worker->task == task)
			return worker;
	return NULL;
}

/* The worker running the item, if one is. */
static struct worker *runner(struct work_struct *work)
{
	struct worker *worker;
	list_for_each_entry(worker, &workers, node)
		if (worker->work == work)
			return worker;
	return NULL;
}

static bool runnable_worker(bool highpri)
{
	struct worker *worker;
	list_for_each_entry(worker, &workers, node)
		if (!worker->sleeping && worker->highpri == highpri)
			return true;
	return pool_starting[highpri] != 0;
}

int stela_linux_start_task(void (*run)(void *), void *context)
{
	if (!run)
		return -EINVAL;
	const struct stela_linux_owner *owner = stela_linux_owner();
	if (!owner->services->start_worker)
		return -EOPNOTSUPP;
	struct task_request *request = kzalloc_obj(*request);
	if (!request)
		return -ENOMEM;
	request->run = run;
	request->context = context;
	list_add_tail(&request->node, &task_requests);
	starting++;
	dedicated_starting++;
	int error = owner->services->start_worker(owner->context, STELA_WORKER_DEDICATED);
	if (error) {
		/* The native producer promises no inline execution and no accepted
		 * job on refusal, so the request is still uniquely ours. */
		starting--;
		dedicated_starting--;
		list_del(&request->node);
		kfree(request);
	}
	return error;
}

/* The first pending item a worker may take: from a workqueue under its
 * concurrency limit, and not already running elsewhere. An ordered
 * workqueue's later items wait behind its first. */
static struct work_struct *next_work(struct workqueue_struct **wq_out, bool highpri)
{
	struct workqueue_struct *wq;
	list_for_each_entry(wq, &every_queue, node) {
		if (!!(wq->flags & WQ_HIGHPRI) != highpri)
			continue;
		if (wq->active >= wq->max_active)
			continue;
		struct work_struct *work;
		list_for_each_entry(work, &wq->pending, entry) {
			if (!runner(work)) {
				*wq_out = wq;
				return work;
			}
			if (wq->flags & __WQ_ORDERED)
				break;
		}
	}
	return NULL;
}

/* Keep a worker runnable while there is work it may take. */
static void kick(void)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	/* High-priority work gets its own nice -20 worker even when an ordinary
	 * worker is runnable or parked. Neither pool borrows the other's rank. */
	for (int pool = 1; pool >= 0; pool--) {
		bool highpri = pool != 0;
		struct workqueue_struct *wq;
		if (runnable_worker(highpri) || !next_work(&wq, highpri))
			continue;
		if (!owner->services->start_worker) {
			stela_linux_unsupported("workqueue workers");
			return;
		}
		/* A refusal leaves pending work explicit for a later worker. */
		if (!owner->services->start_worker(owner->context, highpri ? STELA_WORKER_HIGHPRI : STELA_WORKER_NORMAL)) {
			starting++;
			pool_starting[highpri]++;
		}
	}
}

static void enqueue(struct workqueue_struct *wq, struct work_struct *work)
{
	if (list_empty(&wq->node))
		list_add_tail(&wq->node, &every_queue);
	atomic_long_set(&work->data, (long)((unsigned long)WORK_STRUCT_PENDING | ++last_seq << SEQ_SHIFT));
	list_add_tail(&work->entry, &wq->pending);
	kick();
}

bool queue_work_on(int cpu, struct workqueue_struct *wq, struct work_struct *work)
{
	(void)cpu;
	if (test_and_set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work)))
		return false;
	enqueue(wq, work);
	return true;
}

bool queue_work_node(int node, struct workqueue_struct *wq, struct work_struct *work)
{
	(void)node;
	return queue_work_on(WORK_CPU_UNBOUND, wq, work);
}

void delayed_work_timer_fn(struct timer_list *timer)
{
	struct delayed_work *dwork = timer_container_of(dwork, timer, timer);
	enqueue(dwork->wq, &dwork->work);
}

static void queue_delayed(int cpu, struct workqueue_struct *wq, struct delayed_work *dwork,
			  unsigned long delay)
{
	dwork->wq = wq;
	dwork->cpu = cpu;
	if (!delay) {
		enqueue(wq, &dwork->work);
		return;
	}
	dwork->timer.expires = jiffies + delay;
	add_timer(&dwork->timer);
}

bool queue_delayed_work_on(int cpu, struct workqueue_struct *wq, struct delayed_work *dwork,
			   unsigned long delay)
{
	if (test_and_set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(&dwork->work)))
		return false;
	queue_delayed(cpu, wq, dwork, delay);
	return true;
}

/* Take a pending item back off its timer or workqueue; whether it was
 * pending. */
static bool grab_pending(struct work_struct *work, struct timer_list *timer)
{
	if (!work_pending(work))
		return false;
	if (!(timer && timer_delete(timer))) {
		list_del_init(&work->entry);
		wake_up_all(&work_done);
	}
	clear_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work));
	return true;
}

bool mod_delayed_work_on(int cpu, struct workqueue_struct *wq, struct delayed_work *dwork,
			 unsigned long delay)
{
	bool pending = grab_pending(&dwork->work, &dwork->timer);
	set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(&dwork->work));
	queue_delayed(cpu, wq, dwork, delay);
	return pending;
}

/* Whether the item has a queueing up to seq still to run. */
static bool unfinished(struct work_struct *work, unsigned long seq)
{
	struct worker *worker = runner(work);
	return (queued(work) && seq_of(work) <= seq) || (worker && worker->seq <= seq);
}

bool flush_work(struct work_struct *work)
{
	struct worker *worker = runner(work);
	if (!queued(work) && !worker)
		return false;
	unsigned long seq = queued(work) ? seq_of(work) : worker->seq;
	wait_event(work_done, !unfinished(work, seq));
	return true;
}

bool flush_delayed_work(struct delayed_work *dwork)
{
	if (timer_delete(&dwork->timer))
		enqueue(dwork->wq, &dwork->work);
	return flush_work(&dwork->work);
}

bool cancel_work(struct work_struct *work)
{
	return grab_pending(work, NULL);
}

bool cancel_work_sync(struct work_struct *work)
{
	bool pending = grab_pending(work, NULL);
	wait_event(work_done, !runner(work));
	return pending;
}

bool cancel_delayed_work(struct delayed_work *dwork)
{
	return grab_pending(&dwork->work, &dwork->timer);
}

bool cancel_delayed_work_sync(struct delayed_work *dwork)
{
	bool pending = grab_pending(&dwork->work, &dwork->timer);
	wait_event(work_done, !runner(&dwork->work));
	return pending;
}

/* Whether the workqueue has a queueing up to seq still to run. */
static bool queue_unfinished(struct workqueue_struct *wq, unsigned long seq)
{
	struct work_struct *work;
	struct worker *worker;
	list_for_each_entry(work, &wq->pending, entry)
		if (seq_of(work) <= seq)
			return true;
	list_for_each_entry(worker, &workers, node)
		if (worker->wq == wq && worker->seq <= seq)
			return true;
	return false;
}

void __flush_workqueue(struct workqueue_struct *wq)
{
	unsigned long seq = last_seq;
	wait_event(work_done, !queue_unfinished(wq, seq));
}

/* Linux's warning is the caller's compile-time one. */
void __warn_flushing_systemwide_wq(void)
{
}

/* Unlike a flush, also waits for work the drained work queues. */
void drain_workqueue(struct workqueue_struct *wq)
{
	wait_event(work_done, list_empty(&wq->pending) && !wq->active);
}

struct workqueue_struct *alloc_workqueue_noprof(const char *fmt, unsigned int flags,
						int max_active, ...)
{
	if (flags & WQ_BH) {
		stela_linux_unsupported("BH workqueues");
		return NULL;
	}
	if (max_active < 0 || max_active > WQ_MAX_ACTIVE)
		return NULL;
	struct workqueue_struct *wq = kzalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq)
		return NULL;
	va_list args;
	va_start(args, max_active);
	vsnprintf(wq->name, sizeof(wq->name), fmt, args);
	va_end(args);
	wq->flags = flags;
	wq->max_active = max_active ?: WQ_DFL_ACTIVE;
	INIT_LIST_HEAD(&wq->pending);
	list_add_tail(&wq->node, &every_queue);
	return wq;
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	drain_workqueue(wq);
	list_del(&wq->node);
	kfree(wq);
}

struct work_struct *current_work(void)
{
	struct worker *worker = worker_of(current);
	return worker ? worker->work : NULL;
}

void stela_linux_workers_run(unsigned int kind)
{
	struct worker self = {.task = current};
	if (WARN_ON_ONCE(worker_of(current)))
		return;
	if (starting)
		starting--;
	if (kind == STELA_WORKER_DEDICATED) {
		if (WARN_ON_ONCE(list_empty(&task_requests)))
			return;
		struct task_request *request = list_first_entry(&task_requests, struct task_request, node);
		void (*run)(void *) = request->run;
		void *context = request->context;
		list_del(&request->node);
		dedicated_starting--;
		kfree(request);
		run(context);
		kick();
		return;
	}
	if (WARN_ON_ONCE(kind != STELA_WORKER_NORMAL && kind != STELA_WORKER_HIGHPRI))
		return;
	self.highpri = kind == STELA_WORKER_HIGHPRI;
	if (pool_starting[self.highpri])
		pool_starting[self.highpri]--;
	set_user_nice(current, self.highpri ? MIN_NICE : 0);
	list_add_tail(&self.node, &workers);
	struct workqueue_struct *wq;
	struct work_struct *work;
	while ((work = next_work(&wq, self.highpri))) {
		list_del_init(&work->entry);
		clear_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work));
		self.work = work;
		self.wq = wq;
		self.seq = seq_of(work);
		wq->active++;
		work->func(work);
		wq->active--;
		self.work = NULL;
		self.wq = NULL;
		wake_up_all(&work_done);
	}
	list_del(&self.node);
	set_user_nice(current, 0);
	kick();
}

void stela_linux_worker_sleeping(bool sleeping)
{
	struct worker *worker = worker_of(current);
	if (!worker)
		return;
	worker->sleeping = sleeping;
	if (sleeping)
		kick();
}
