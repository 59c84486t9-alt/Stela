// SPDX-License-Identifier: MIT
/* Callable whole-original-mutex fixtures. Each role runs on a distinct actual
 * Runtime stack with original task metadata and an entered owner. Checkpoints
 * enqueue real continuations or post a retained expected-job cancellation;
 * no fixture writes lock internals or grants ownership to a sleeper. */
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/wake_q.h>
#include <linux/string.h>
#include <linux/ww_mutex.h>
#include <stela/linux.h>
#include <stela/task.h>
#include <stela/test.h>

struct stela_mutex_test_call {
	u32 scenario, role;
	void *context;
	void (*checkpoint)(void *context, u32 event);
};
void stela_linux_mutex_test_run(void *opaque);

static struct mutex lock, auxiliary;
static struct ww_mutex first, second, extra;
static DEFINE_WD_CLASS(die_class);
static DEFINE_WW_CLASS(wound_class);
static struct task_struct *tasks[4];
static unsigned int attempted, finished, acquired, arrivals[3], winners[3];
static unsigned int payload, deadlocks, reused, reuse_finished;
static struct rcu_head signal_retirement;
static const struct stela_mutex_test_call *retirement_call;

static void checkpoint(const struct stela_mutex_test_call *call, u32 event)
{
	call->checkpoint(call->context, event);
}

static void until(const unsigned int *value, unsigned int expected)
{
	unsigned int yields = 0;
	while (READ_ONCE(*value) != expected) {
		/* A bounded number of genuine coroutine switches, not CPU polling. */
		assert(yields++ < 64);
		assert(!stela_linux_task_yield());
	}
}

static void current_valid(void)
{
	unsigned long pointer;
	asm volatile("mov %%rsp, %0" : "=r"(pointer));
	assert(current->flags == PF_KTHREAD);
	assert(current->policy == SCHED_NORMAL);
	assert(current->prio == DEFAULT_PRIO && current->normal_prio == DEFAULT_PRIO);
	assert(current->static_prio == DEFAULT_PRIO);
	assert(pointer >= (unsigned long)current->stack);
	assert(pointer - (unsigned long)current->stack < THREAD_SIZE);
	assert(!preempt_count() && !irqs_disabled());
	assert(current->on_cpu == 1 && current->on_rq == 1 && !current->is_blocked);
	assert(!stela_linux_task_pending_signals());
}

static void wrong_baseline_put(void)
{
	/* The borrowed baseline is not a caller-owned get_task_struct reference. */
	put_task_struct(current);
	rcu_barrier();
}

static void wake_queue_and_refs(void)
{
	DEFINE_WAKE_Q(queue);
	struct task_struct *self = current;
	assert(refcount_read(&self->usage) == 1);
	wake_q_add(&queue, self);
	assert(refcount_read(&self->usage) == 2);
	wake_q_add(&queue, self);
	assert(refcount_read(&self->usage) == 2);
	get_task_struct(self);
	wake_q_add_safe(&queue, self); /* duplicate consumes this real extra ref */
	assert(refcount_read(&self->usage) == 2);
	wake_up_q(&queue);
	assert(refcount_read(&self->usage) == 1 && !self->wake_q.next);
	wake_q_init(&queue); /* original wake_up_q does not reinitialize the head */
	get_task_struct(self);
	wake_q_add_safe(&queue, self); /* newly queued transfers the owned ref */
	assert(refcount_read(&self->usage) == 2);
	wake_up_q(&queue);
	assert(refcount_read(&self->usage) == 1 && !self->wake_q.next);
	assert(!wake_up_state(self, TASK_NORMAL));
	assert(stela_test_traps(wrong_baseline_put));
	assert(refcount_read(&self->usage) == 1);
}

static void uncontended(const struct stela_mutex_test_call *call)
{
	atomic_t users = ATOMIC_INIT(2);
	assert(!mutex_is_locked(&lock));
	assert(!mutex_get_owner(&lock));
	assert(mutex_trylock(&lock));
	assert(mutex_get_owner(&lock) == (unsigned long)current);
	assert(!mutex_trylock(&lock));
	mutex_unlock(&lock);
	assert(!atomic_dec_and_mutex_lock(&users, &lock));
	assert(atomic_read(&users) == 1 && !mutex_is_locked(&lock));
	assert(atomic_dec_and_mutex_lock(&users, &lock));
	assert(!atomic_read(&users) && mutex_is_locked(&lock));
	mutex_unlock(&lock);
	ww_mutex_init(&extra, &wound_class);
	assert(ww_mutex_trylock(&extra, NULL));
	assert(!ww_mutex_trylock(&extra, NULL));
	ww_mutex_unlock(&extra);
	assert(!ww_mutex_lock(&extra, NULL));
	ww_mutex_unlock(&extra);
	assert(!ww_mutex_lock_interruptible(&extra, NULL));
	ww_mutex_unlock(&extra);
	ww_mutex_destroy(&extra);
	/* Available IO locks restore the exact nested token without ever being
	 * accounted as blocked. This checks behavior absent a scheduler switch. */
	mutex_lock_io(&lock);
	assert(!current->in_iowait);
	mutex_unlock(&lock);
	int token = io_schedule_prepare();
	assert(!token && current->in_iowait);
	mutex_lock_io(&lock);
	assert(current->in_iowait);
	mutex_unlock(&lock);
	io_schedule_finish(token);
	assert(!current->in_iowait);
	assert(!stela_linux_task_waiting_io() && !stela_linux_task_waiting_load());
	/* Pending signals cannot defeat an available fastpath acquisition.
	 * Both bits are delivered by retained TargetTask, never fixture writes. */
	checkpoint(call, 7);
	assert(stela_linux_task_pending_signals() == 1);
	assert(!mutex_lock_interruptible(&lock));
	mutex_unlock(&lock);
	assert(!mutex_lock_killable(&lock));
	mutex_unlock(&lock);
	checkpoint(call, 8);
	assert(stela_linux_task_pending_signals() == 3);
	assert(!mutex_lock_interruptible(&lock));
	mutex_unlock(&lock);
	assert(!mutex_lock_killable(&lock));
	mutex_unlock(&lock);
	assert(!stela_linux_task_ack_signal(1));
	assert(!stela_linux_task_ack_signal(2));
	assert(!stela_linux_task_pending_signals());
	wake_queue_and_refs();
}

static void post_during_prepare(struct rcu_head *head)
{
	assert(head == &signal_retirement && retirement_call);
	assert(current == tasks[1]);
	/* Original process retirement has real softirq/preempt accounting. The
	 * Rust checkpoint only tries its uncontended metadata lock and uses
	 * bounded atomic/refcount operations; it never allocates or parks. */
	assert(preempt_count() == (int)SOFTIRQ_OFFSET && !irqs_disabled());
	checkpoint(retirement_call, 4);
}

static void reset(unsigned int scenario)
{
	assert(!attempted || finished == attempted);
	memset(tasks, 0, sizeof(tasks));
	memset(arrivals, 0, sizeof(arrivals));
	memset(winners, 0, sizeof(winners));
	attempted = finished = acquired = payload = deadlocks = reused = reuse_finished = 0;
	retirement_call = NULL;
	mutex_init(&lock);
	mutex_init(&auxiliary);
	struct ww_class *class = scenario == 7 ? &die_class : &wound_class;
	ww_mutex_init(&first, class);
	ww_mutex_init(&second, class);
}

static void acknowledge_all(void)
{
	unsigned int pending = stela_linux_task_pending_signals();
	if (pending & 1)
		assert(!stela_linux_task_ack_signal(1));
	if (pending & 2)
		assert(!stela_linux_task_ack_signal(2));
	assert(!stela_linux_task_pending_signals());
}

static void ordinary_worker(const struct stela_mutex_test_call *call)
{
	unsigned int role = call->role, scenario = call->scenario;
	assert(role >= 1 && role <= 3 && current != tasks[0]);
	for (unsigned int i = 0; i < 4; i++)
		assert(!tasks[i] || tasks[i] != current);
	tasks[role] = current;
	assert(!mutex_trylock(&lock));
	arrivals[attempted++] = role;
	int result = 0;
	if (scenario == 5) {
		retirement_call = call;
		call_rcu(&signal_retirement, post_during_prepare);
	}
	switch (scenario) {
	case 1:
	case 5:
	case 6:
		result = mutex_lock_interruptible(&lock);
		break;
	case 2:
		result = mutex_lock_killable(&lock);
		break;
	case 4:
	case 10: {
		int outer = io_schedule_prepare();
		int inner = io_schedule_prepare();
		assert(!outer && inner == 1 && current->in_iowait);
		io_schedule_finish(inner);
		assert(current->in_iowait);
		io_schedule_finish(outer);
		assert(!current->in_iowait);
		mutex_lock_io(&lock);
		assert(!current->in_iowait);
		break;
	}
	default:
		mutex_lock(&lock);
		break;
	}
	if (scenario == 1 || scenario == 2 || scenario == 5) {
		assert(result == -EINTR && !current->blocked_on);
		assert(mutex_get_owner(&lock) == (unsigned long)tasks[0]);
		assert(stela_linux_task_pending_signals() == (scenario == 2 ? 3U : 1U));
	} else {
		assert(!result && mutex_get_owner(&lock) == (unsigned long)current);
		assert(payload == 42);
		winners[acquired++] = role;
		mutex_unlock(&lock);
	}
	acknowledge_all();
	assert(!preempt_count() && !current->blocked_on);
	assert(!current->in_iowait && current->__state == TASK_RUNNING);
	finished++;
}

static void ordinary_owner(const struct stela_mutex_test_call *call)
{
	unsigned int scenario = call->scenario, workers = scenario ? 1 : 3;
	uncontended(call);
	mutex_lock(&lock);
	tasks[0] = current;
	checkpoint(call, 1);
	until(&attempted, workers);
	assert(!acquired && mutex_get_owner(&lock) == (unsigned long)current);
	if (scenario == 1 || scenario == 2 || scenario == 3 || scenario == 4 || scenario == 6 || scenario == 10) {
		assert(stela_linux_task_waiting_load() == (scenario == 1 || scenario == 6 ? 0U : 1U));
		assert(stela_linux_task_waiting_io() == (scenario == 4 || scenario == 10 ? 1U : 0U));
	}
	if (scenario == 1 || scenario == 2 || scenario == 3 || scenario == 4)
		checkpoint(call, 2);
	if (scenario == 2 || scenario == 3 || scenario == 4) {
		/* Nonfatal cancellation does not wake killable/uninterruptible IO. */
		assert(!stela_linux_task_yield());
		assert(!finished && stela_linux_task_waiting_load() == 1);
		if (scenario == 2) {
			checkpoint(call, 3);
		} else {
			/* Lock-scoped borrowed waiter is valid at baseline usage one. */
			assert(refcount_read(&tasks[1]->usage) == 1);
			assert(wake_up_process(tasks[1]) == 1);
			assert(!tasks[1]->blocked_on && !tasks[1]->is_blocked);
			assert(tasks[1]->on_rq == 1 && !tasks[1]->on_cpu);
			assert(!stela_linux_task_waiting_load());
			assert(!stela_linux_task_yield());
			assert(!finished && stela_linux_task_waiting_load() == 1);
			assert(stela_linux_task_waiting_io() == (scenario == 4 || scenario == 10 ? 1U : 0U));
		}
	}
	if (scenario == 10) {
		/* Only a generation-gated generic IRQ wake view is invoked. It does
		 * not touch C state/accounting. Arrival must resolve them once on
		 * the real resumed stack before the original waiter rechecks. */
		assert(tasks[1]->blocked_on == &lock && tasks[1]->is_blocked);
		checkpoint(call, 10);
		assert(tasks[1]->blocked_on == &lock && tasks[1]->is_blocked);
		assert(stela_linux_task_waiting_io() == 1);
		assert(!stela_linux_task_yield());
		assert(!finished && stela_linux_task_waiting_io() == 1);
		assert(stela_linux_task_waiting_load() == 1);
	}
	if (scenario == 6) {
		/* A genuine spurious resume requests original HANDOFF; cancellation
		 * then loses to original unlock/PICKUP before the waiter runs. */
		assert(wake_up_process(tasks[1]) == 1);
		assert(!stela_linux_task_yield());
		assert(atomic_long_read(&lock.owner) & 2UL);
		checkpoint(call, 2);
	}
	if (scenario == 1 || scenario == 2 || scenario == 5) {
		until(&finished, 1);
		assert(!acquired && !lock.first_waiter);
	}
	payload = 42;
	mutex_unlock(&lock);
	if (scenario == 6)
		assert(atomic_long_read(&lock.owner) & 4UL);
	until(&finished, workers);
	assert(!stela_linux_task_waiting_io() && !stela_linux_task_waiting_load());
	if (!scenario) {
		assert(acquired == 3);
		for (unsigned int i = 0; i < 3; i++)
			assert(winners[i] == arrivals[i]);
		checkpoint(call, 5); /* old target after actual completion */
		checkpoint(call, 6); /* same Notify continuation, new real job */
		until(&reused, 1);
		checkpoint(call, 5); /* old target while the future job is live */
		until(&reuse_finished, 1);
	}
	assert(!mutex_is_locked(&lock) && !lock.first_waiter);
}

static void ww_worker(const struct stela_mutex_test_call *call)
{
	struct ww_acquire_ctx context;
	unsigned int scenario = call->scenario;
	struct ww_class *class = scenario == 7 ? &die_class : &wound_class;
	tasks[1] = current;
	ww_acquire_init(&context, class);
	assert(context.task == current && !context.acquired);
	if (scenario != 9) {
		assert(!ww_mutex_lock(&second, &context));
		assert(context.acquired == 1);
	}
	attempted++;
	int error = ww_mutex_lock_interruptible(&first, &context);
	if (scenario == 9) {
		assert(error == -EINTR && !context.acquired);
		assert(stela_linux_task_pending_signals() == 1);
		acknowledge_all();
	} else {
		assert(error == -EDEADLK && context.acquired == 1);
		if (scenario == 8)
			assert(context.wounded);
		deadlocks++;
		ww_mutex_unlock(&second);
		assert(!context.acquired);
		ww_mutex_lock_slow(&first, &context);
		assert(context.acquired == 1 && !context.wounded);
		assert(ww_mutex_trylock(&second, &context));
		assert(context.acquired == 2);
		ww_acquire_done(&context);
		ww_mutex_unlock(&second);
		ww_mutex_unlock(&first);
	}
	assert(!context.acquired && !current->blocked_on);
	ww_acquire_fini(&context);
	finished++;
}

static void ww_owner(const struct stela_mutex_test_call *call)
{
	struct ww_acquire_ctx context;
	struct ww_class *class = call->scenario == 7 ? &die_class : &wound_class;
	ww_acquire_init(&context, class); /* older than worker's actual context */
	assert(!ww_mutex_lock(&first, &context));
	assert(ww_mutex_lock(&first, &context) == -EALREADY);
	tasks[0] = current;
	checkpoint(call, 1);
	until(&attempted, 1);
	if (call->scenario == 9) {
		checkpoint(call, 2);
		until(&finished, 1);
		assert(!deadlocks && context.acquired == 1);
	} else {
		if (call->scenario == 7)
			until(&deadlocks, 1);
		else
			assert(!deadlocks && !finished);
		/* Wound/wait: this older task blocks on second, original wake_q
		 * wounds the younger owner sleeping on first, and genuine wake/
		 * backoff releases second so this original lock call can resume. */
		assert(!ww_mutex_lock(&second, &context));
		assert(deadlocks == 1 && context.acquired == 2);
		ww_mutex_unlock(&second);
	}
	ww_acquire_done(&context);
	ww_mutex_unlock(&first);
	assert(!context.acquired);
	ww_acquire_fini(&context);
	until(&finished, 1);
	assert(!mutex_is_locked(&first.base) && !mutex_is_locked(&second.base));
}

void stela_linux_mutex_test_run(void *opaque)
{
	const struct stela_mutex_test_call *call = opaque;
	const struct stela_linux_services services = {};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	current_valid();
	assert(call && call->scenario <= 10 && call->role <= 4);
	if (!call->role) {
		reset(call->scenario);
		if (call->scenario < 7 || call->scenario == 10)
			ordinary_owner(call);
		else
			ww_owner(call);
	} else if (call->role == 4) {
		assert(!call->scenario && current == tasks[1]);
		mutex_lock(&auxiliary);
		reused++;
		assert(!stela_linux_task_yield());
		assert(!stela_linux_task_pending_signals());
		mutex_unlock(&auxiliary);
		reuse_finished++;
	} else if (call->scenario < 7 || call->scenario == 10) {
		ordinary_worker(call);
	} else {
		assert(call->role == 1);
		ww_worker(call);
	}
	assert(!current->blocked_on && !preempt_count());
	assert(!stela_linux_task_pending_signals());
	assert(stela_linux_quiescent());
	/* A real extra original C ref refuses scope completion, then releases.
	 * The enclosing Rust wrapper subsequently performs the actual scope end. */
	struct task_struct *self = current;
	get_task_struct(self);
	stela_linux_exit();
	assert(stela_linux_task_scope_end((struct stela_linux_task *)self) == -EBUSY);
	put_task_struct(self);
}
