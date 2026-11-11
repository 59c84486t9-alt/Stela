// SPDX-License-Identifier: GPL-2.0-or-later
/* Original Tiny SRCU on real retained Runtime/service/workqueue tasks. */
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/irq_work.h>
#include <linux/kthread.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/workqueue.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/srcu.h>
#include <stela/test.h>

void stela_linux_srcu_queue_before_threads(void);
void stela_linux_srcu_source_cases(void);
void stela_linux_srcu_negative_case(unsigned int which, void (*witness)(void));
void stela_linux_srcu_worker_pressure_test(void);
void stela_linux_srcu_bootstrap_pressure_test(void);
int stela_linux_srcu_bootstrap_joined(const struct stela_linux_owner *owner);
DEFINE_STATIC_SRCU(readers);
static struct work_struct grace_work;
static DECLARE_COMPLETION(grace_started);
static bool reader_left;

static void grace_period(struct work_struct *work)
{
	(void)work;
	complete(&grace_started);
	synchronize_srcu(&readers);
	assert(reader_left);
}

static void srcu(void)
{
	synchronize_srcu(&readers);
	int index = srcu_read_lock(&readers);

	INIT_WORK(&grace_work, grace_period);
	assert(schedule_work(&grace_work));
	wait_for_completion(&grace_started);
	reader_left = true;
	srcu_read_unlock(&readers, index);
	assert(flush_work(&grace_work));
}

struct sync_waiter {
	struct work_struct work;
	struct srcu_struct *domain;
	struct completion started;
	bool finished;
};
static void synchronize_worker(struct work_struct *work)
{
	struct sync_waiter *waiter = container_of(work, struct sync_waiter, work);
	complete(&waiter->started);
	synchronize_srcu(waiter->domain);
	waiter->finished = true;
}
static void wait_for_gp(struct srcu_struct *domain)
{
	for (unsigned int step = 0; step != 100 && !READ_ONCE(domain->srcu_gp_waiting); step++)
		schedule_timeout_uninterruptible(1);
	assert(READ_ONCE(domain->srcu_gp_waiting));
}
static void sleeping_and_independent_domains(void)
{
	struct srcu_struct a, b;
	assert(!init_srcu_struct(&a) && !init_srcu_struct(&b));
	int old = srcu_read_lock(&a);
	int nested = srcu_read_lock(&a);
	assert(nested == old && a.srcu_lock_nesting[old] == 2);
	struct sync_waiter waiter = {.domain = &a};
	init_completion(&waiter.started);
	INIT_WORK(&waiter.work, synchronize_worker);
	assert(schedule_work(&waiter.work));
	wait_for_completion(&waiter.started);
	wait_for_gp(&a);
	msleep(250);
	assert(!waiter.finished && a.srcu_lock_nesting[old] == 2);
	srcu_read_unlock(&a, nested);
	assert(!waiter.finished && a.srcu_lock_nesting[old] == 1);
	/* A held reader/domain cannot serialize an independent B grace period. */
	synchronize_srcu(&b);
	assert(!waiter.finished && a.srcu_lock_nesting[old] == 1);
	srcu_read_unlock(&a, old);
	assert(flush_work(&waiter.work));
	assert(waiter.finished);
	cleanup_srcu_struct(&a);
	cleanup_srcu_struct(&b);
}
struct observed {
	struct rcu_head head;
	struct completion done;
	unsigned int calls;
};
static void observed_callback(struct rcu_head *head)
{
	struct observed *item = container_of(head, struct observed, head);
	assert(in_task() && !in_hardirq() && !in_serving_softirq() && !irqs_disabled());
	assert(preempt_count() == SOFTIRQ_DISABLE_OFFSET);
	assert(stela_linux_atomic_callback_active() && !stela_linux_quiescent());
	item->calls++;
	complete(&item->done);
}
static void disabled_unlock_requires_counter_recheck(void)
{
	struct srcu_struct domain;
	assert(!init_srcu_struct(&domain));
	struct observed item = {};
	init_completion(&item.done);
	int old = srcu_read_lock(&domain);
	call_srcu(&domain, &item.head, observed_callback);
	assert(!item.calls);
	wait_for_gp(&domain);
	msleep(250);
	assert(!item.calls && domain.srcu_lock_nesting[old] == 1);
	local_irq_disable();
	srcu_read_unlock(&domain, old);
	local_irq_enable();
	/* Original unlock cannot directly wake with IRQs disabled. Its original
	 * HZ/10 fallback must recheck zero before callback delivery. */
	assert(!item.calls);
	wait_for_completion(&item.done);
	srcu_barrier(&domain);
	assert(item.calls == 1);
	cleanup_srcu_struct(&domain);
}
struct ordered_state;
struct ordered_item {
	struct rcu_head head;
	struct ordered_state *state;
	char mark;
	bool free_self;
};
struct ordered_state {
	struct srcu_struct domain;
	struct ordered_item b, c;
	struct completion first_batch;
	char order[3];
	unsigned int count;
	bool freed_a;
};
static void ordered_callback(struct rcu_head *head)
{
	struct ordered_item *item = container_of(head, struct ordered_item, head);
	struct ordered_state *state = item->state;
	assert(state->count < 3);
	state->order[state->count++] = item->mark;
	assert(preempt_count() == SOFTIRQ_DISABLE_OFFSET && stela_linux_atomic_callback_active());
	if (item->mark == 'a')
		call_srcu(&state->domain, &state->c.head, ordered_callback);
	if (item->mark == 'b')
		complete(&state->first_batch);
	if (item->free_self) {
		state->freed_a = true;
		kfree(item);
	}
}
static void fifo_and_requeue_need_distinct_generations(void)
{
	struct ordered_state state = {};
	assert(!init_srcu_struct(&state.domain));
	init_completion(&state.first_batch);
	state.b = (struct ordered_item){.state = &state, .mark = 'b'};
	state.c = (struct ordered_item){.state = &state, .mark = 'c'};
	struct ordered_item *a = kzalloc(sizeof(*a), GFP_KERNEL);
	assert(a);
	*a = (struct ordered_item){.state = &state, .mark = 'a', .free_self = true};
	int old = srcu_read_lock(&state.domain);
	call_srcu(&state.domain, &a->head, ordered_callback);
	call_srcu(&state.domain, &state.b.head, ordered_callback);
	wait_for_gp(&state.domain);
	int next = srcu_read_lock(&state.domain);
	assert(next != old);
	srcu_read_unlock(&state.domain, old);
	wait_for_completion(&state.first_batch);
	assert(state.freed_a && state.count == 2 && state.order[0] == 'a' && state.order[1] == 'b');
	wait_for_gp(&state.domain);
	msleep(150);
	assert(state.count == 2);
	srcu_read_unlock(&state.domain, next);
	srcu_barrier(&state.domain);
	assert(state.count == 3 && state.order[2] == 'c');
	cleanup_srcu_struct(&state.domain);
}
static void polling_wrap_and_dynamic_cleanup(void)
{
	struct srcu_struct *domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	assert(domain && !init_srcu_struct(domain));
	unsigned long cookie = get_state_synchronize_srcu(domain);
	assert(!poll_state_synchronize_srcu(domain, cookie));
	assert(poll_state_synchronize_srcu(domain, get_completed_synchronize_srcu()));
	/* An isolated initialized empty domain near the modular boundary. */
	domain->srcu_idx = ULONG_MAX - 3;
	domain->srcu_idx_max = domain->srcu_idx;
	for (unsigned int wrap = 0; wrap != 2; wrap++) {
		int reader = srcu_read_lock(domain);
		cookie = start_poll_synchronize_srcu(domain);
		wait_for_gp(domain);
		assert(!poll_state_synchronize_srcu(domain, cookie));
		srcu_read_unlock(domain, reader);
		srcu_barrier(domain);
		assert(poll_state_synchronize_srcu(domain, cookie));
	}
	/* Producers/readers are stopped. Original cleanup joins final irqwait RCU
	 * access and GP work before this containing allocation is released. */
	cleanup_srcu_struct(domain);
	kfree(domain);
}
static void pending_kick_cleanup_joins_before_free(void)
{
	struct srcu_struct *domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	struct observed item = {};
	assert(domain && !init_srcu_struct(domain));
	init_completion(&item.done);
	call_srcu(domain, &item.head, observed_callback);
	assert(!item.calls && irq_work_is_pending(&domain->srcu_irq_work));
	/* No more producer or reader exists. Even an unstarted kickoff must join
	 * its final IRQ-work access and all original GP work before this free. */
	cleanup_srcu_struct(domain);
	assert(item.calls == 1);
	kfree(domain);
}
struct cleanup_race {
	struct srcu_struct domain;
	struct work_struct cleanup, reader;
	struct completion cleanup_ready, reader_ready, cleanup_go, reader_go;
	struct completion acquired, release;
	struct observed callback;
	int old_index;
};
static void cleanup_race_worker(struct work_struct *work)
{
	struct cleanup_race *state = container_of(work, struct cleanup_race, cleanup);
	complete(&state->cleanup_ready);
	wait_for_completion(&state->cleanup_go);
	/* Both high-priority tasks already ran and parked. Waking the reader does
	 * not switch this nonpreemptible callback before cleanup's entry check. */
	complete(&state->reader_go);
	cleanup_srcu_struct(&state->domain);
}
static void cleanup_race_reader(struct work_struct *work)
{
	struct cleanup_race *state = container_of(work, struct cleanup_race, reader);
	complete(&state->reader_ready);
	wait_for_completion(&state->reader_go);
	state->old_index = srcu_read_lock(&state->domain);
	complete(&state->acquired);
	wait_for_completion(&state->release);
	srcu_read_unlock(&state->domain, state->old_index);
}
static void cleanup_with_reader_arriving_during_join(void (*witness)(void))
{
	struct cleanup_race state = {};
	assert(!init_srcu_struct(&state.domain));
	init_completion(&state.cleanup_ready);
	init_completion(&state.reader_ready);
	init_completion(&state.cleanup_go);
	init_completion(&state.reader_go);
	init_completion(&state.acquired);
	init_completion(&state.release);
	init_completion(&state.callback.done);
	INIT_WORK(&state.cleanup, cleanup_race_worker);
	INIT_WORK(&state.reader, cleanup_race_reader);
	assert(queue_work(system_highpri_wq, &state.cleanup));
	assert(queue_work(system_highpri_wq, &state.reader));
	wait_for_completion(&state.cleanup_ready);
	wait_for_completion(&state.reader_ready);
	call_srcu(&state.domain, &state.callback.head, observed_callback);
	assert(irq_work_is_pending(&state.domain.srcu_irq_work));
	complete(&state.cleanup_go);
	wait_for_completion(&state.acquired);
	wait_for_gp(&state.domain);
	/* Cleanup entered with zero readers, then actually joined a pending
	 * kickoff/GP. This new-generation reader cannot block that prior GP. */
	int next = srcu_read_lock(&state.domain);
	assert(next != state.old_index);
	complete(&state.release);
	if (witness)
		witness();
	flush_work(&state.cleanup);
	/* Returning here would falsely permit storage release with a live reader.
	 * Only the final counter check traps; entry-only validation is insufficient. */
	srcu_read_unlock(&state.domain, next);
	flush_work(&state.reader);
}

static void callback_sleep(struct rcu_head *head)
{
	(void)head;
	schedule();
}
static void callback_exit(struct rcu_head *head)
{
	(void)head;
	stela_linux_exit();
}
static void callback_rebalanced_sleep(struct rcu_head *head)
{
	(void)head;
	preempt_count_set(0);
	schedule();
}
static void callback_unbalanced_return(struct rcu_head *head)
{
	(void)head;
	local_irq_disable();
}
static rcu_callback_t invalid_callback;
static void queue_invalid_callback(rcu_callback_t callback)
{
	struct srcu_struct domain;
	struct rcu_head head;
	assert(!init_srcu_struct(&domain));
	call_srcu(&domain, &head, callback);
	srcu_barrier(&domain);
}
static rcu_callback_t const invalid_callbacks[] = {callback_sleep, callback_exit,
	callback_rebalanced_sleep, callback_unbalanced_return};
DEFINE_STATIC_SRCU(early_domain);
static struct observed early;

void stela_linux_srcu_queue_before_threads(void)
{
	assert(!READ_ONCE(bdi_wq));
	/* The inactive scheduler allows the original synchronous fastpath.
	 * The queued callback still requires actual worker startup. */
	synchronize_srcu(&early_domain);
	init_completion(&early.done);
	call_srcu(&early_domain, &early.head, observed_callback);
	assert(!early.calls && irq_work_is_pending(&early_domain.srcu_irq_work));
}
static void source_cases(void)
{
	srcu();
	sleeping_and_independent_domains();
	disabled_unlock_requires_counter_recheck();
	fifo_and_requeue_need_distinct_generations();
	polling_wrap_and_dynamic_cleanup();
	pending_kick_cleanup_joins_before_free();
}

static void wait_for_workqueues(void)
{
	/* PID1 publishes this after original workqueue startup and topology. */
	for (unsigned int tick = 0; tick < HZ && !READ_ONCE(bdi_wq); tick++)
		schedule_timeout_uninterruptible(1);
	assert(READ_ONCE(bdi_wq));
}

struct worker_pressure {
	struct kthread_worker *held[16];
	unsigned int count;
};

static void fill_worker_stacks(struct worker_pressure *pressure)
{
	for (;;) {
		struct kthread_worker *worker = kthread_create_worker(0, "srcu-pressure");
		if (IS_ERR(worker)) {
			assert(PTR_ERR(worker) == -ENOMEM || PTR_ERR(worker) == -ENOSPC);
			break;
		}
		assert(pressure->count < ARRAY_SIZE(pressure->held));
		pressure->held[pressure->count++] = worker;
	}
	assert(pressure->count >= 2);
}

static void release_worker_stacks(struct worker_pressure *pressure)
{
	while (pressure->count)
		kthread_destroy_worker(pressure->held[--pressure->count]);
	rcu_barrier();
}

static DECLARE_COMPLETION(normal_running);
static DECLARE_COMPLETION(release_normal);

static void occupy_normal_worker(struct work_struct *work)
{
	assert(current_work() == work);
	complete(&normal_running);
	wait_for_completion(&release_normal);
}

static void callback_waits_for_worker_capacity(struct worker_pressure *pressure)
{
	struct srcu_struct domain;
	struct observed item = {};
	struct work_struct occupied;
	assert(!init_srcu_struct(&domain));
	init_completion(&item.done);
	INIT_WORK(&occupied, occupy_normal_worker);
	assert(schedule_work(&occupied));
	assert(wait_for_completion_timeout(&normal_running, HZ));
	/* Let the original pool establish its spare before exhausting stacks. */
	fill_worker_stacks(pressure);
	call_srcu(&domain, &item.head, observed_callback);
	assert(irq_work_is_pending(&domain.srcu_irq_work) && !item.calls);
	msleep(30);
	assert(!item.calls && !READ_ONCE(domain.srcu_gp_running));
	/* Recover through the original worker manager's retry, with the first
	 * worker still occupied. The queued SRCU request must survive that wait. */
	release_worker_stacks(pressure);
	assert(wait_for_completion_timeout(&item.done, 3 * HZ));
	complete(&release_normal);
	flush_work(&occupied);
	srcu_barrier(&domain);
	assert(item.calls == 1);
	cleanup_srcu_struct(&domain);
}

void stela_linux_srcu_worker_pressure_test(void)
{
	wait_for_workqueues();
	struct worker_pressure pressure = {};
	callback_waits_for_worker_capacity(&pressure);
}

static DECLARE_COMPLETION(pool_warmed);

static void warm_pool_worker(struct work_struct *work)
{
	assert(current_work() == work);
	complete(&pool_warmed);
}

static void warm_pool(struct workqueue_struct *queue)
{
	struct work_struct work;
	INIT_WORK(&work, warm_pool_worker);
	reinit_completion(&pool_warmed);
	assert(queue_work(queue, &work));
	assert(wait_for_completion_timeout(&pool_warmed, 3 * HZ));
	flush_work(&work);
}

void stela_linux_srcu_bootstrap_pressure_test(void)
{
	wait_for_workqueues();
	const struct stela_linux_owner *owner = stela_linux_owner();
	struct worker_pressure pressure = {};
	warm_pool(system_percpu_wq);
	warm_pool(system_highpri_wq);
	fill_worker_stacks(&pressure);
	/* Original probes need a second worker while each first worker waits.
	 * Under exhaustion that dependency times out or is eventually handled
	 * by the same worker, neither of which is a successful replacement. */
	int status = stela_linux_srcu_bootstrap(owner);
	assert(status == -EAGAIN || status == -ETIMEDOUT);
	assert(!stela_linux_srcu_bootstrapping(owner));
	release_worker_stacks(&pressure);
	warm_pool(system_percpu_wq);
	warm_pool(system_highpri_wq);
	assert(!stela_linux_srcu_bootstrap(owner));
	assert(stela_linux_srcu_bootstrap(owner) == -EALREADY);
	assert(stela_linux_srcu_bootstrap_joined(owner) == -EPERM);
}

void stela_linux_srcu_source_cases(void)
{
	wait_for_workqueues();
	const struct stela_linux_owner *owner = stela_linux_owner();
	assert(wait_for_completion_timeout(&early.done, HZ));
	srcu_barrier(&early_domain);
	assert(early.calls == 1);
	assert(!stela_linux_srcu_bootstrap(owner));
	assert(stela_linux_srcu_bootstrap(owner) == -EALREADY);
	assert(stela_linux_srcu_bootstrap_joined(owner) == -EPERM);
	assert(stela_linux_srcu_current_active(NULL) == -EINVAL);
	assert(stela_linux_srcu_current_active(owner) == -EPERM);
	source_cases();
}

static void (*negative_witness)(void);

static void witnessed_invalid_callback(struct rcu_head *head)
{
	assert(stela_linux_atomic_callback_active() && in_task() &&
	       preempt_count() == SOFTIRQ_DISABLE_OFFSET && !irqs_disabled());
	negative_witness();
	invalid_callback(head);
}

void stela_linux_srcu_negative_case(unsigned int which, void (*witness)(void))
{
	wait_for_workqueues();
	if (which < ARRAY_SIZE(invalid_callbacks)) {
		negative_witness = witness;
		invalid_callback = invalid_callbacks[which];
		queue_invalid_callback(witnessed_invalid_callback);
	} else if (which == ARRAY_SIZE(invalid_callbacks)) {
		struct srcu_struct domain;
		assert(!init_srcu_struct(&domain));
		int reader = srcu_read_lock(&domain);
		assert(domain.srcu_lock_nesting[reader] == 1 && stela_linux_quiescent());
		witness();
		cleanup_srcu_struct(&domain);
	} else {
		assert(which == ARRAY_SIZE(invalid_callbacks) + 1);
		cleanup_with_reader_arriving_during_join(witness);
	}
}
