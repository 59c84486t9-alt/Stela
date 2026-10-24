// SPDX-License-Identifier: MIT
/* Original Linux task metadata bound to actual retained Runtime continuations.
 * This implements identity/lease transitions, not a substitute Linux scheduler. */
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/task.h>

static_assert(CONFIG_THREAD_INFO_IN_TASK == 1);
static_assert(!IS_ENABLED(CONFIG_SMP));
static_assert(!IS_ENABLED(CONFIG_PREEMPT_RT));
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
};

/* The real same-CPU Runtime owns publication. This does not authorize C entry
 * from another CPU, an ISR, or an unretained stack. The current callback checks
 * actual CPU/IRQ/RSP before any admitted task service uses mutable metadata. */
static struct stela_linux_task *active;

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

static bool quiet(const struct stela_linux_task *task)
{
	return !task->linux_task.thread_info.preempt_count && !task->linux_task.thread_info.flags &&
	       READ_ONCE(task->linux_task.__state) == TASK_RUNNING &&
	       task->linux_task.flags == PF_KTHREAD && !task->linux_task.blocked_on &&
	       !task->linux_task.blocked_donor && !task->linux_task.wake_q.next &&
	       refcount_read(&task->linux_task.usage) == 1 &&
	       refcount_read(&task->linux_task.stack_refcount) == 1;
}

struct stela_linux_task *stela_linux_task_allocate(void)
{
	struct stela_linux_task *task = stela_linux_heap_alloc(sizeof(*task), __alignof__(*task));
	if (!task)
		return NULL;
	task->linux_task.thread_info.task = &task->linux_task;
	task->linux_task.flags = PF_KTHREAD;
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
	    !actual_stack(view) || !ops || !ops->is_current || !binding ||
	    __atomic_load_n(&active, __ATOMIC_ACQUIRE) || lease.owner ||
	    lease.irq_flags != ARCH_IRQ_ENABLED || stela_thread_info.preempt_count ||
	    stela_thread_info.flags)
		return -EINVAL;
	/* Initial attach precedes publication of the first real WakeHandle. The
	 * Runtime caller already validated CPU/IRQ/current/stack and retains us. */
	task->context = *view;
	task->linux_task.stack = (void *)view->stack_start;
	*(unsigned long *)task->linux_task.stack = STACK_END_MAGIC;
	task->ops = ops;
	task->binding = binding;
	task->attached = true;
	task->active = true;
	__atomic_store_n(&active, task, __ATOMIC_RELEASE);
	return 0;
}

int stela_linux_task_scope_begin(struct stela_linux_task *task,
	const struct stela_linux_task_scope_ops *ops, void *scope)
{
	if (!task || !live_here(task, &task->context) || task->scope ||
	    task->prepared || task->suspended || !quiet(task) ||
	    !ops || !ops->park || !ops->yield || !scope)
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
	if (!task || !live_here(task, &task->context) || !task->scope ||
	    task->prepared || task->suspended || !quiet(task))
		return -EBUSY;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (lease.owner || lease.irq_flags != ARCH_IRQ_ENABLED)
		return -EBUSY;
	task->scope = NULL;
	task->scope_ops = NULL;
	return 0;
}

/* Process-context PREPARE. The caller proves why count==1 belongs exclusively
 * to a known scheduler level; this internal function does not infer an RCU
 * reader's legality from the numeric count. RCU/BH/IRQ suspension is forbidden. */
static int prepare(struct stela_linux_task *task, int count)
{
	if (!live_here(task, &task->context) || !task->scope || task->prepared ||
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
	return task->prepared && task->scope && !task->suspended &&
	       task->linux_task.thread_info.preempt_count == task->prepared_count &&
	       !task->linux_task.thread_info.flags &&
	       task->lease.owner && task->lease.irq_flags == ARCH_IRQ_ENABLED &&
	       stela_linux_lease_matches(&task->lease);
}

int stela_linux_task_still_blocked(struct stela_linux_task *task,
	const struct stela_linux_task_context *view)
{
	if (!live_here(task, view) || !prepared_here(task))
		return -EBUSY;
	unsigned int state = READ_ONCE(task->linux_task.__state);
	if (state & ~(unsigned int)(TASK_NORMAL | TASK_WAKEKILL))
		return -EOPNOTSUPP;
	return state != TASK_RUNNING;
}

int stela_linux_task_leave(struct stela_linux_task *task,
	const struct stela_linux_task_context *view, unsigned int reason)
{
	if (!live_here(task, view) || reason > 1)
		return -EINVAL;
	struct stela_linux_lease lease;
	stela_linux_lease_snapshot(&lease);
	if (lease.owner) {
		if (!prepared_here(task) ||
		    (reason == 0 && (task->prepared_count || READ_ONCE(task->linux_task.__state))) ||
		    (reason == 1 && (READ_ONCE(task->linux_task.__state) & ~(unsigned int)(TASK_NORMAL | TASK_WAKEKILL))))
			return -EBUSY;
	} else if (reason || task->scope || task->prepared || !quiet(task) ||
		   lease.irq_flags != ARCH_IRQ_ENABLED) {
		return -EBUSY;
	}
	/* Every refusal above is mutation-free. No callbacks, allocator, final
	 * release or Rust owner borrow crosses this committed IF=0 transition. */
	task->lease = lease;
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
	task->context = *view;
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
	/* The unsafe Runtime caller established real producer/waiter quiescence.
	 * Reference counts cannot prove arbitrary held-mutex or foreign lifetimes. */
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
	stela_linux_heap_free(task, sizeof(*task), __alignof__(*task));
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
