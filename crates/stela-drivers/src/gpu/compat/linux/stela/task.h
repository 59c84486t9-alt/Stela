/* SPDX-License-Identifier: MIT */
#ifndef STELA_TASK_H
#define STELA_TASK_H
#include <linux/types.h>

struct task_struct;
struct thread_info;
struct stela_linux_owner;
struct stela_linux_task;

/* Exact repr(C) platform::work::TaskContext. The callback view is borrowed;
 * primitive fields may be copied, never the view pointer. Bounds describe the
 * separately retained real Runtime stack/guard, not a new mapping authority. */
struct stela_linux_task_context {
	u64 queue_id, context_id, sequence;
	size_t stack_start, stack_end, guard_start, guard_end, stack_pointer;
};

struct stela_linux_task_ops {
	/* Actual CPU/IRQ/RSP/current ticket validation, bounded and allocation-
	 * free. The retained binding/code outlive this attached task. */
	bool (*is_current)(void *binding, const struct stela_linux_task_context *context);
};

struct stela_linux_task_scope_ops {
	/* Retained shared Runtime borrow on this actual stack. No unwind or
	 * escape. park: 0 skipped, 1 resumed; yield: 0 resumed; negative errno. */
	int (*park)(void *scope);
	int (*yield)(void *scope);
};

/* Private serialized Linux lease. Suspend is not exit: no callbacks or owner
 * drops run in IF=0 hooks. All functions require the actual qualified CPU. */
struct stela_linux_lease {
	const struct stela_linux_owner *owner;
	unsigned long irq_flags;
};
void stela_linux_lease_snapshot(struct stela_linux_lease *lease);
bool stela_linux_lease_matches(const struct stela_linux_lease *lease);
void stela_linux_lease_suspend(const struct stela_linux_lease *lease);
bool stela_linux_lease_resume(const struct stela_linux_lease *lease);

/* Allocation/release run in qualified process context, outside Linux entry.
 * Attach/leave/arrive/complete/detach are bounded IF=0 Runtime switch hooks.
 * Return failure before mutation; corruption after a committed switch traps. */
struct stela_linux_task *stela_linux_task_allocate(void);
int stela_linux_task_attach(struct stela_linux_task *task,
	const struct stela_linux_task_context *context,
	const struct stela_linux_task_ops *ops, void *binding);
int stela_linux_task_still_blocked(struct stela_linux_task *task,
	const struct stela_linux_task_context *context);
int stela_linux_task_leave(struct stela_linux_task *task,
	const struct stela_linux_task_context *context, unsigned int reason);
int stela_linux_task_arrive(struct stela_linux_task *task,
	const struct stela_linux_task_context *context, bool new_job);
int stela_linux_task_complete(struct stela_linux_task *task,
	const struct stela_linux_task_context *context);
int stela_linux_task_detach(struct stela_linux_task *task,
	const struct stela_linux_task_context *context);
void stela_linux_task_release(struct stela_linux_task *task);

int stela_linux_task_scope_begin(struct stela_linux_task *task,
	const struct stela_linux_task_scope_ops *ops, void *scope);
int stela_linux_task_scope_end(struct stela_linux_task *task);
/* Internal adapters only; these are not Linux schedule/wake exports. A true
 * schedule_preempt_disabled adapter must prove it owns the sole preempt level;
 * count==1 by itself cannot distinguish that level from an outer RCU reader. */
int stela_linux_task_park(bool scheduler_preempt_disabled);
int stela_linux_task_yield(void);
struct task_struct *stela_linux_current(void);
struct thread_info *stela_linux_thread_info(void);
#endif
