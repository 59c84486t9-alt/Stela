// SPDX-License-Identifier: MIT
/* Original Linux task metadata bound to actual retained Runtime continuations.
 * This implements identity/lease transitions, not a substitute Linux scheduler. */
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/limits.h>
#include <linux/preempt.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/task.h>

static_assert(CONFIG_THREAD_INFO_IN_TASK == 1);
static_assert(!IS_ENABLED(CONFIG_SMP));
static_assert(!IS_ENABLED(CONFIG_PREEMPT_RT));
static_assert(!IS_ENABLED(CONFIG_MUTEX_SPIN_ON_OWNER));
static_assert(!IS_ENABLED(CONFIG_SCHED_PROXY_EXEC));
static_assert(!IS_ENABLED(CONFIG_DEBUG_LOCK_ALLOC));
static_assert(!IS_ENABLED(CONFIG_DEBUG_MUTEXES));
static_assert(!IS_ENABLED(CONFIG_DEBUG_WW_MUTEX_SLOWPATH));
static_assert(!IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY_BUILD));
static_assert(!IS_ENABLED(CONFIG_PREEMPT_DYNAMIC));
/* I2C's required RT/PI extension is separate; no partial RT field enablement. */
static_assert(!IS_ENABLED(CONFIG_RT_MUTEXES));
static_assert(!IS_ENABLED(CONFIG_BLOCK));
static_assert(!IS_ENABLED(CONFIG_TASK_DELAY_ACCT));
static_assert(!IS_ENABLED(CONFIG_PSI));
static_assert(!IS_ENABLED(CONFIG_SCHEDSTATS));
static_assert(sizeof(struct stela_linux_task_context) == 64);
static_assert(offsetof(struct stela_linux_task_context, sequence) == 16);
static_assert(offsetof(struct stela_linux_task_context, stack_pointer) == 56);
static_assert(offsetof(struct task_struct, thread_info) == 0);
static_assert(__alignof__(struct task_struct) >= 64);

struct stela_linux_task {
	struct task_struct linux_task;
	struct stela_linux_task_context context;
	const struct stela_linux_task_ops *ops;
	void *binding;
	const struct stela_linux_task_scope_ops *scope_ops;
	void *scope;
	struct stela_linux_lease lease;
	int prepared_count;
	bool attached, active, suspended, prepared;
	bool io_blocked, load_blocked, finalizing;
	bool scope_boundary;
};

/* The real same-CPU Runtime owns publication. This does not authorize C entry
 * from another CPU, an ISR, or an unretained stack. The current callback checks
 * actual CPU/IRQ/RSP before any admitted task service uses mutable metadata. */
static struct stela_linux_task *active;

/* Actual attached stack leases only. Registration/retirement are bounded IF0
 * hooks on the single qualified CPU; no native ISR can read this catalog.
 * Rust's retained binding owns each metadata pointer through actual detach.
 * A closed job remains registered until detach but never owns live storage. */
#define STACK_TASKS 32U
static struct stela_linux_task *stack_tasks[STACK_TASKS];

unsigned int stela_linux_task_catalog_capacity(void)
{
	/* Ceiling only. stack_admit still requires actual attached stack leases. */
	return STACK_TASKS;
}

size_t stela_linux_task_stack_bytes(void) { return THREAD_SIZE; }
size_t stela_linux_task_stack_alignment(void) { return THREAD_ALIGN; }
size_t stela_linux_task_stack_guard(void) { return PAGE_SIZE; }

static unsigned int stack_slot(const struct stela_linux_task *task)
{
	for (unsigned int slot = 0; slot < STACK_TASKS; slot++)
		if (stack_tasks[slot] == task)
			return slot;
	return STACK_TASKS;
}

static int stack_admit(const struct stela_linux_task_context *view)
{
	int free_slot = -ENOSPC;
	for (unsigned int slot = 0; slot < STACK_TASKS; slot++) {
		const struct stela_linux_task *task = stack_tasks[slot];
		if (!task) {
			if (free_slot < 0)
				free_slot = (int)slot;
			continue;
		}
		/* Both guard and usable mapping remain exclusively retained even
		 * between jobs. Never admit a second owner of overlapping ranges. */
		if ((view->guard_start < task->context.stack_end &&
		     task->context.guard_start < view->stack_end) ||
		    (view->queue_id == task->context.queue_id &&
		     view->context_id == task->context.context_id))
			return -EINVAL;
	}
	return free_slot;
}

static bool view_valid(const struct stela_linux_task_context *view, bool live)
{
	return view && view->queue_id && view->context_id &&
	       (live ? view->sequence != 0 : view->sequence == 0) &&
	       !(view->stack_start & (PAGE_SIZE - 1UL)) &&
	       view->stack_end > view->stack_start &&
	       view->stack_end - view->stack_start == THREAD_SIZE &&
	       !(view->guard_start & (PAGE_SIZE - 1UL)) &&
	       view->guard_end == view->stack_start &&
	       view->guard_end > view->guard_start &&
	       view->guard_end - view->guard_start >= PAGE_SIZE &&
	       view->stack_pointer >= view->stack_start &&
	       view->stack_pointer < view->stack_end;
}

static bool same_stack(const struct stela_linux_task *task,
		       const struct stela_linux_task_context *view)
{
	return task->context.queue_id == view->queue_id &&
	       task->context.context_id == view->context_id &&
	       task->context.stack_start == view->stack_start &&
	       task->context.stack_end == view->stack_end &&
	       task->context.guard_start == view->guard_start &&
	       task->context.guard_end == view->guard_end;
}

static bool actual_stack(const struct stela_linux_task_context *view)
{
	unsigned long stack_pointer;
	asm volatile("mov %%rsp, %0" : "=r"(stack_pointer));
	return stack_pointer >= view->stack_start && stack_pointer < view->stack_end;
}

static bool live_here(struct stela_linux_task *task,
		      const struct stela_linux_task_context *view)
{
	if (!task)
		return false;
	/* ops/binding are immutable throughout attached lifetime and retained
	 * until real producer quiescence. Validate the actual root CPU/IRQ/RSP
	 * BEFORE reading mutable C task/context metadata. Rust's callback also
	 * defers dereferencing view until that independent validation succeeds. */
	if (!task->ops || !task->ops->is_current(task->binding, view))
		return false;
	return task->attached && task->active && view_valid(view, true) &&
	       __atomic_load_n(&active, __ATOMIC_ACQUIRE) == task &&
	       same_stack(task, view) && task->context.sequence == view->sequence &&
	       actual_stack(view);
}

static struct stela_linux_task *current_record(void)
{
	struct stela_linux_task *task = __atomic_load_n(&active, __ATOMIC_ACQUIRE);
	if (!task || !live_here(task, &task->context))
		__builtin_trap();
	return task;
}

struct thread_info *stela_linux_thread_info(void)
{
	if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
		return &stela_thread_info;
	return &current_record()->linux_task.thread_info;
}

struct task_struct *stela_linux_current(void)
{
	struct stela_linux_task *task = current_record();
	/* Even a real continuation outside its entered Linux owner is not an
	 * admitted current for original Linux services. */
	(void)stela_linux_owner();
	return &task->linux_task;
}

struct task_struct *stela_linux_task_stack_owner(const void *storage, size_t bytes)
{
	/* Establish real CPU/current/RSP/owner BEFORE any mutable catalog read.
	 * Merely supplying a pointer or being inside a mapped stack is no grant. */
	struct stela_linux_task *caller = current_record();
	(void)stela_linux_owner();
	unsigned long begin = (unsigned long)storage;
	if (!bytes || bytes > ULONG_MAX - begin)
		return NULL;
	unsigned long end = begin + bytes;
	for (unsigned int slot = 0; slot < STACK_TASKS; slot++) {
		struct stela_linux_task *task = stack_tasks[slot];
		if (!task || !task->attached || !task->context.sequence ||
		    task->context.queue_id != caller->context.queue_id)
			continue;
		if (begin >= task->context.stack_start && end <= task->context.stack_end)
			return &task->linux_task;
	}
	return NULL;
}

/* Only admitted same-CPU C code and IF=0 switch hooks access these counters.
 * They describe actual committed sleepers, not token nesting or all Linux rq
 * statistics. A native CPU-idle/accounting consumer remains unbound. */
static unsigned int waiting_io, waiting_load;

static void block_account(struct stela_linux_task *task, unsigned int state)
{
	if (task->io_blocked || task->load_blocked || task->linux_task.is_blocked)
		__builtin_trap();
	bool io = task->linux_task.in_iowait;
	/* Pinned sched/core.c block_task: idle/frozen sleepers do not add load. */
	bool load = (state & TASK_UNINTERRUPTIBLE) &&
		!(state & TASK_NOLOAD) && !(state & TASK_FROZEN);
	if ((io && waiting_io == UINT_MAX) || (load && waiting_load == UINT_MAX))
		__builtin_trap();
	task->io_blocked = io;
	task->load_blocked = load;
	task->linux_task.sched_contributes_to_load = load;
	waiting_io += io;
	waiting_load += load;
	task->linux_task.is_blocked = 1;
	task->linux_task.on_rq = 0;
}

static void wake_account(struct stela_linux_task *task)
{
	if ((task->io_blocked && !waiting_io) || (task->load_blocked && !waiting_load))
		__builtin_trap();
	waiting_io -= task->io_blocked;
	waiting_load -= task->load_blocked;
	task->io_blocked = false;
	task->load_blocked = false;
	task->linux_task.is_blocked = 0;
}

static bool quiet_except_usage_flags(const struct stela_linux_task *task, unsigned long allowed)
{
	/* Linux's sigisemptyset() takes a mutable set: test a copy. */
	sigset_t pending = task->linux_task.pending.signal;

	return !task->linux_task.thread_info.preempt_count &&
	       !(task->linux_task.thread_info.flags & ~allowed) &&
	       READ_ONCE(task->linux_task.__state) == TASK_RUNNING &&
	       task->linux_task.flags == PF_KTHREAD && !task->linux_task.blocked_on &&
	       !task->linux_task.blocked_donor && !task->linux_task.wake_q.next &&
	       !task->linux_task.in_iowait && !task->linux_task.is_blocked &&
	       !task->io_blocked && !task->load_blocked &&
	       sigisemptyset(&pending) &&
	       list_empty(&task->linux_task.pending.list) &&
	       refcount_read(&task->linux_task.stack_refcount) == 1;
}

static bool quiet_except_usage(const struct stela_linux_task *task)
{
	return quiet_except_usage_flags(task, 0);
}

static bool quiet(const struct stela_linux_task *task)
{
	return quiet_except_usage(task) && refcount_read(&task->linux_task.usage) == 1;
}

struct stela_linux_task *stela_linux_task_allocate(void)
{
	struct stela_linux_task *task = stela_linux_heap_alloc(sizeof(*task), __alignof__(*task));
	if (!task)
		return NULL;
	task->linux_task.thread_info.task = &task->linux_task;
	task->linux_task.flags = PF_KTHREAD;
	/* Equal-priority normal kernel continuations; zero prio would falsely
	 * describe an RT task when a later separately admitted profile reads it. */
	task->linux_task.policy = SCHED_NORMAL;
	task->linux_task.prio = DEFAULT_PRIO;
	task->linux_task.static_prio = DEFAULT_PRIO;
	task->linux_task.normal_prio = DEFAULT_PRIO;
	INIT_LIST_HEAD(&task->linux_task.pending.list);
	sigemptyset(&task->linux_task.pending.signal);
	refcount_set(&task->linux_task.usage, 1);
	refcount_set(&task->linux_task.stack_refcount, 1);
	raw_spin_lock_init(&task->linux_task.pi_lock);
	raw_spin_lock_init(&task->linux_task.blocked_lock);
	task->lease.irq_flags = ARCH_IRQ_ENABLED;
	return task;
}

int stela_linux_task_attach(struct stela_linux_task *task,
	const struct stela_linux_task_context *view,
	const struct stela_linux_task_ops *ops, void *binding)
{
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (!task || task->attached || !quiet(task) || !view_valid(view, true) ||
	    !actual_stack(view) || !ops || !ops->is_current || !ops->wake_target ||
	    !ops->service_reserved || !binding ||
	    __atomic_load_n(&active, __ATOMIC_ACQUIRE) || lease.owner ||
	    lease.irq_flags != ARCH_IRQ_ENABLED || stela_thread_info.preempt_count ||
	    stela_thread_info.flags)
		return -EINVAL;
	int slot = stack_admit(view);
	if (slot < 0)
		return slot;
	/* Initial attach precedes publication of the first real WakeHandle. The
	 * Runtime caller already validated CPU/IRQ/current/stack and retains us. */
	task->context = *view;
	task->linux_task.stack = (void *)view->stack_start;
	*(unsigned long *)task->linux_task.stack = STACK_END_MAGIC;
	task->ops = ops;
	task->binding = binding;
	task->attached = true;
	task->active = true;
	task->linux_task.on_cpu = 1;
	task->linux_task.on_rq = 1;
	stack_tasks[(unsigned int)slot] = task;
	__atomic_store_n(&active, task, __ATOMIC_RELEASE);
	return 0;
}

int stela_linux_task_scope_begin(struct stela_linux_task *task,
	const struct stela_linux_task_scope_ops *ops, void *scope)
{
	if (!task || !live_here(task, &task->context) || task->scope ||
	    task->prepared || task->suspended || !quiet(task) ||
	    !ops || !ops->park || !ops->yield || !ops->reschedule ||
	    !ops->reschedule_requested || !scope)
		return -EINVAL;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (lease.owner || lease.irq_flags != ARCH_IRQ_ENABLED)
		return -EBUSY;
	task->scope_ops = ops;
	task->scope = scope;
	return 0;
}

int stela_linux_task_scope_end(struct stela_linux_task *task)
{
	if (stela_linux_atomic_callback_active() || !task ||
	    !live_here(task, &task->context) || !task->scope || task->scope_boundary ||
	    task->prepared || task->suspended ||
	    !quiet_except_usage_flags(task, _TIF_NEED_RESCHED) ||
	    refcount_read(&task->linux_task.usage) != 1)
		return -EBUSY;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (lease.owner || lease.irq_flags != ARCH_IRQ_ENABLED)
		return -EBUSY;
	for (;;) {
		bool forced = test_tsk_thread_flag(&task->linux_task, TIF_NEED_RESCHED);
		clear_tsk_thread_flag(&task->linux_task, TIF_NEED_RESCHED);
		bool requested = task->scope_ops->reschedule_requested(task->scope);
		if (!forced && !requested)
			break;
		{
			/* The body exited its owner and drained RCU/pages already. Its local
			 * owner no longer exists: retain only this actual pinned Runtime scope
			 * and a private outside-owner preparation marker through the switch. */
			task->scope_boundary = true;
			int result = task->scope_ops->reschedule(task->scope);
			if (result || !live_here(task, &task->context) ||
			    !task->scope_boundary || task->prepared || task->suspended ||
			    !quiet_except_usage_flags(task, _TIF_NEED_RESCHED) ||
			    refcount_read(&task->linux_task.usage) != 1 || !stela_linux_lease_matches(&lease))
				__builtin_trap();
			task->scope_boundary = false;
		}
		/* A peer can post a new scheduler request during the ownerless switch.
		 * Consume it only through another real boundary, never a silent clear. */
		if (!test_tsk_thread_flag(&task->linux_task, TIF_NEED_RESCHED))
			break;
	}
	task->scope = NULL;
	task->scope_ops = NULL;
	return 0;
}

/* Process-context PREPARE. The caller proves why count==1 belongs exclusively
 * to a known scheduler level; this internal function does not infer an RCU
 * reader's legality from the numeric count. RCU/BH/IRQ suspension is forbidden. */
static int prepare(struct stela_linux_task *task, int count)
{
	if (stela_linux_atomic_callback_active() || task->scope_boundary ||
	    !live_here(task, &task->context) || !task->scope || task->prepared ||
	    task->suspended || preempt_count() != count || irqs_disabled())
		return -EBUSY;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (!lease.owner || lease.irq_flags != ARCH_IRQ_ENABLED)
		return -EBUSY;
	if (count)
		preempt_count_sub(count);
	stela_linux_rcu_finish();
	stela_linux_pages_finish();
	if (!stela_linux_quiescent() || !stela_linux_lease_matches(&lease))
		__builtin_trap();
	if (count)
		preempt_count_add(count);
	task->lease = lease;
	task->prepared_count = count;
	task->prepared = true;
	return 0;
}

static bool prepared_here(struct stela_linux_task *task)
{
	return !stela_linux_atomic_callback_active() &&
	       task->prepared && task->scope && !task->suspended &&
	       task->linux_task.thread_info.preempt_count == task->prepared_count &&
	       !(task->linux_task.thread_info.flags & ~(_TIF_SIGPENDING | _TIF_NEED_RESCHED)) &&
	       task->lease.owner && task->lease.irq_flags == ARCH_IRQ_ENABLED &&
	       stela_linux_lease_matches(&task->lease);
}

static bool supported_block_state(unsigned int state)
{
	/* Preserve the existing ordinary wait masks, plus the exact idle state.
	 * TASK_NOLOAD alone is not an admitted sleeping state. */
	return state == TASK_IDLE ||
	       !(state & ~(unsigned int)(TASK_NORMAL | TASK_WAKEKILL));
}

int stela_linux_task_still_blocked(struct stela_linux_task *task,
	const struct stela_linux_task_context *view)
{
	if (!live_here(task, view) || !prepared_here(task))
		return -EBUSY;
	unsigned int state = READ_ONCE(task->linux_task.__state);
	if (!supported_block_state(state))
		return -EOPNOTSUPP;
	return state != TASK_RUNNING;
}

int stela_linux_task_leave(struct stela_linux_task *task,
	const struct stela_linux_task_context *view, unsigned int reason)
{
	/* The private delivery scope cannot be defeated by rebalancing public
	 * preempt/IRQ state. Refuse before task accounting or lease mutation. */
	if (stela_linux_atomic_callback_active())
		return -EBUSY;
	if (!live_here(task, view) || reason > 2)
		return -EINVAL;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (lease.owner) {
		if (!prepared_here(task) ||
		    (reason != 1 && (task->prepared_count || READ_ONCE(task->linux_task.__state))) ||
		    (reason == 1 && !supported_block_state(READ_ONCE(task->linux_task.__state))))
			return -EBUSY;
	} else if (task->scope_boundary) {
		if (reason != 2 || !task->scope || task->prepared || task->suspended ||
		    !quiet(task) || lease.irq_flags != ARCH_IRQ_ENABLED)
			return -EBUSY;
	} else if (reason || task->scope || task->prepared || !quiet(task) ||
		   lease.irq_flags != ARCH_IRQ_ENABLED) {
		return -EBUSY;
	}
	/* Every refusal above is mutation-free. No callbacks, allocator, final
	 * release or Rust owner borrow crosses this committed IF=0 transition. */
	task->lease = lease;
	if (reason == 1)
		block_account(task, READ_ONCE(task->linux_task.__state));
	task->linux_task.on_cpu = 0;
	stela_linux_lease_suspend(&lease);
	task->active = false;
	task->suspended = true;
	__atomic_store_n(&active, NULL, __ATOMIC_RELEASE);
	return 0;
}

int stela_linux_task_arrive(struct stela_linux_task *task,
	const struct stela_linux_task_context *view, bool new_job)
{
	if (!task || !task->attached || task->active || !view_valid(view, true) ||
	    !same_stack(task, view) || !actual_stack(view) ||
	    __atomic_load_n(&active, __ATOMIC_ACQUIRE) ||
	    stela_thread_info.preempt_count || stela_thread_info.flags ||
	    !task->ops->is_current(task->binding, view))
		return -EINVAL;
	if (new_job) {
		if (task->context.sequence || task->suspended || task->scope ||
		    task->prepared || !quiet(task) || task->lease.owner)
			return -EBUSY;
	} else if (!task->suspended || task->context.sequence != view->sequence) {
		return -EINVAL;
	}
	if (!stela_linux_lease_resume(&task->lease))
		return -EBUSY;
	/* Also resolves a real Runtime spurious/IRQ pending wake which never
	 * entered C wake_up_process. Actual !SMP/!PROXY switch exclusion owns
	 * this target before current publication; no Linux ISR/task can race. */
	WRITE_ONCE(task->linux_task.blocked_on, NULL);
	wake_account(task);
	task->context = *view;
	task->linux_task.on_cpu = 1;
	task->linux_task.on_rq = 1;
	task->suspended = false;
	task->active = true;
	/* A genuine resume makes this sleeper runnable. Original lock/wait code
	 * must still recheck its own condition; this never grants lock ownership. */
	WRITE_ONCE(task->linux_task.__state, TASK_RUNNING);
	__atomic_store_n(&active, task, __ATOMIC_RELEASE);
	return 0;
}

int stela_linux_task_complete(struct stela_linux_task *task,
	const struct stela_linux_task_context *view)
{
	if (!live_here(task, view) || task->scope || task->prepared || task->suspended ||
	    !quiet(task))
		return -EBUSY;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (lease.owner || lease.irq_flags != ARCH_IRQ_ENABLED)
		return -EBUSY;
	task->lease = lease;
	task->context.sequence = 0;
	task->linux_task.on_cpu = 0;
	task->linux_task.on_rq = 0;
	task->active = false;
	__atomic_store_n(&active, NULL, __ATOMIC_RELEASE);
	return 0;
}

int stela_linux_task_detach(struct stela_linux_task *task,
	const struct stela_linux_task_context *view)
{
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (!task || !task->attached || task->active || task->suspended || task->scope ||
	    task->prepared || task->context.sequence || !quiet(task) ||
	    !view_valid(view, false) || !same_stack(task, view) ||
	    __atomic_load_n(&active, __ATOMIC_ACQUIRE) || lease.owner ||
	    lease.irq_flags != ARCH_IRQ_ENABLED || stela_thread_info.preempt_count ||
	    stela_thread_info.flags)
		return -EBUSY;
	unsigned int slot = stack_slot(task);
	if (slot == STACK_TASKS)
		__builtin_trap();
	/* The unsafe Runtime caller established real producer/waiter quiescence.
	 * Reference counts cannot prove arbitrary held-mutex or foreign lifetimes. */
	stack_tasks[slot] = NULL;
	task->attached = false;
	task->binding = NULL;
	task->ops = NULL;
	return 0;
}

void stela_linux_task_release(struct stela_linux_task *task)
{
	if (!task || task->attached || task->active || task->suspended || task->scope ||
	    task->prepared || !quiet(task))
		__builtin_trap();
	if (stack_slot(task) != STACK_TASKS)
		__builtin_trap();
	/* Consume the actual retained baseline only after independent detach and
	 * unique Rust metadata ownership; extra public C refs must already end. */
	task->finalizing = true;
	if (!refcount_dec_and_test(&task->linux_task.usage))
		__builtin_trap();
	__put_task_struct(&task->linux_task);
}

void __put_task_struct(struct task_struct *linux_task)
{
	struct stela_linux_task *task = container_of(linux_task, struct stela_linux_task, linux_task);
	if (!task->finalizing || task->attached || task->active || task->suspended || task->scope ||
	    task->prepared || task->context.sequence || !quiet_except_usage(task) ||
	    refcount_read(&linux_task->usage))
		__builtin_trap();
	stela_linux_heap_free(task, sizeof(*task), __alignof__(*task));
}

void __put_task_struct_rcu_cb(struct rcu_head *head)
{
	/* Original put_task_struct reaches this only at final refcount zero.
	 * An active task's baseline is borrowed and cannot legally be put by a
	 * caller that did not own it. The real finalizer validates that lifetime. */
	__put_task_struct(container_of(head, struct task_struct, rcu));
}

static int finish_prepared(struct stela_linux_task *task, int result)
{
	if (!live_here(task, &task->context) || !prepared_here(task))
		__builtin_trap();
	task->prepared = false;
	task->prepared_count = 0;
	return result;
}

int stela_linux_task_park(bool scheduler_preempt_disabled)
{
	struct stela_linux_task *task = current_record();
	int error = prepare(task, scheduler_preempt_disabled ? 1 : 0);
	if (error)
		return error;
	/* Same selected scheduler effect as try_to_block_task: a signal posted
	 * by a process PREPARE retirement callback must not be lost. Native IRQ
	 * views only publish generic pending wake, never mutate Linux sigsets. */
	smp_mb();
	if (signal_pending_state(READ_ONCE(task->linux_task.__state), &task->linux_task)) {
		clear_task_blocked_on(&task->linux_task, NULL);
		WRITE_ONCE(task->linux_task.__state, TASK_RUNNING);
	}
	int result = task->scope_ops->park(task->scope);
	if (result > 1)
		__builtin_trap();
	return finish_prepared(task, result);
}

int stela_linux_task_yield(void)
{
	struct stela_linux_task *task = current_record();
	int error = prepare(task, 0);
	if (error)
		return error;
	int result = task->scope_ops->yield(task->scope);
	if (result > 0)
		__builtin_trap();
	return finish_prepared(task, result);
}

int __cond_resched(void)
{
	struct stela_linux_task *task = current_record();
	(void)stela_linux_owner();
	/* Legal nonblocking no-op in critical context, before provider/drain or
	 * flag effects. The private guard survives public counter rebalance. */
	if (stela_linux_atomic_callback_active() || preempt_count() || irqs_disabled())
		return 0;
	if (!task->scope || task->scope_boundary || task->prepared || task->suspended ||
	    READ_ONCE(task->linux_task.__state) != TASK_RUNNING)
		__builtin_trap();
	bool forced = test_tsk_thread_flag(&task->linux_task, TIF_NEED_RESCHED);
	clear_tsk_thread_flag(&task->linux_task, TIF_NEED_RESCHED);
	bool requested = task->scope_ops->reschedule_requested(task->scope);
	if (!forced && !requested)
		return 0;
	if (prepare(task, 0))
		__builtin_trap();
	int result = task->scope_ops->reschedule(task->scope);
	if (result || finish_prepared(task, result))
		__builtin_trap();
	return 1;
}

/* The whole original mutex uses precisely this scheduler boundary. Invalid
 * outer atomic/read-side nesting is a contract violation, not busy polling. */
void schedule_preempt_disabled(void)
{
	if (preempt_count() != 1 || stela_linux_task_park(true) < 0)
		__builtin_trap();
	__set_current_state(TASK_RUNNING);
}

/* Generic process waits (including original rcuwait) enter at preempt0.
 * They never borrow the normal-mutex scheduler level or infer an RT wait.
 * A running caller yields fairly; a sleeping caller uses the same real
 * PREPARE/drain, signal recheck and atomic predicate/park transition. */
void schedule(void)
{
	struct task_struct *task = stela_linux_current();
	unsigned int state = READ_ONCE(task->__state);
	bool admitted_state = state == TASK_RUNNING || state == TASK_INTERRUPTIBLE ||
		state == TASK_UNINTERRUPTIBLE || state == TASK_KILLABLE || state == TASK_IDLE;
	if (stela_linux_atomic_callback_active() || preempt_count() || irqs_disabled() ||
	    !admitted_state ||
	    (task->flags & (PF_KTHREAD | PF_WQ_WORKER | PF_IO_WORKER)) != PF_KTHREAD || task->plug)
		__builtin_trap();
	int result = state == TASK_RUNNING ? stela_linux_task_yield() : stela_linux_task_park(false);
	if (result < 0)
		__builtin_trap();
	/* A pending immutable Runtime wake can skip the actual switch without
	 * a C wake_up_process/arrive hook. Scheduler return is still runnable. */
	__set_current_state(TASK_RUNNING);
}

static int wake_state(struct task_struct *linux_task, unsigned int state)
{
	(void)current_record();
	(void)stela_linux_owner();
	/* Original API borrowed lifetime: a task ref, live waiter/lock scope or
	 * other real producer lease retains this actual job. A numeric extra
	 * reference is not universal ownership proof. The caller supplies that
	 * lifetime; positive usage only rejects an already-dead object. */
	if (!refcount_read(&linux_task->usage))
		__builtin_trap();
	struct stela_linux_task *task = container_of(linux_task, struct stela_linux_task, linux_task);
	if (!task->attached || !task->context.sequence || !task->ops)
		__builtin_trap();
	guard(raw_spinlock_irqsave)(&linux_task->pi_lock);
	/* Full wake barrier pairs with original set_current_state before the
	 * genuine predicate/park. No preemptive Linux ISR can enter this port. */
	smp_mb();
	if (!(READ_ONCE(linux_task->__state) & state))
		return 0;
	/* Publish the generation-safe signal before changing C state. Failure
	 * under a held live ref is corruption and must not lose a wake. */
	if (task->ops->wake_target(task->binding, task->context.sequence))
		__builtin_trap();
	clear_task_blocked_on(linux_task, NULL);
	wake_account(task);
	linux_task->on_rq = 1;
	WRITE_ONCE(linux_task->__state, TASK_RUNNING);
	return 1;
}

int wake_up_process(struct task_struct *task)
{
	return wake_state(task, TASK_NORMAL);
}

int wake_up_state(struct task_struct *task, unsigned int state)
{
	return wake_state(task, state);
}

static int wait_signal(unsigned int kind)
{
	switch (kind) {
	case 1: return SIGUSR1;
	case 2: return SIGKILL;
	default: return 0;
	}
}

int stela_linux_task_signal(struct stela_linux_task *task, u64 expected_sequence,
	unsigned int kind)
{
	(void)stela_linux_current();
	/* Metadata is separately retained by TargetTask. Inspect only generation
	 * until it matches; stale handles cannot inspect a future job's state. */
	if (!expected_sequence || task->context.sequence != expected_sequence)
		return -ESTALE;
	int signal_number = wait_signal(kind);
	if (!signal_number)
		return -EINVAL;
	if (!task->attached)
		return -ESTALE;
	/* Wait cancellation requires a live body, never its returned owner. */
	if (!task->scope || task->scope_boundary)
		return -EBUSY;
	/* Reserved Timer/IRQ service shutdown is explicit stop/drain/join, not
	 * ordinary wait cancellation. Refuse before refs, signal bits or wakes. */
	if (task->ops->service_reserved(task->binding))
		return -EOPNOTSUPP;
	get_task_struct(&task->linux_task);
	sigaddset(&task->linux_task.pending.signal, signal_number);
	set_tsk_thread_flag(&task->linux_task, TIF_SIGPENDING);
	unsigned int state = TASK_INTERRUPTIBLE | (kind == 2 ? TASK_WAKEKILL : 0U);
	(void)wake_up_state(&task->linux_task, state);
	put_task_struct(&task->linux_task);
	return 0;
}

int stela_linux_task_ack_signal(unsigned int kind)
{
	struct task_struct *task = stela_linux_current();
	int signal_number = wait_signal(kind);
	if (!signal_number)
		return -EINVAL;
	sigdelset(&task->pending.signal, signal_number);
	if (sigisemptyset(&task->pending.signal))
		clear_tsk_thread_flag(task, TIF_SIGPENDING);
	return 0;
}

unsigned int stela_linux_task_pending_signals(void)
{
	struct task_struct *task = stela_linux_current();
	return (sigismember(&task->pending.signal, SIGUSR1) ? 1U : 0U) |
	       (sigismember(&task->pending.signal, SIGKILL) ? 2U : 0U);
}

unsigned int stela_linux_task_waiting_io(void)
{
	(void)stela_linux_current();
	return waiting_io;
}

unsigned int stela_linux_task_waiting_load(void)
{
	(void)stela_linux_current();
	return waiting_load;
}
