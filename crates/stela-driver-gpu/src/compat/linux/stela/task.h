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

struct stela_linux_task_rank {
	u32 policy, realtime;
	s32 effective;
	s32 nice;
};
_Static_assert(sizeof(struct stela_linux_task_rank) == 16, "Linux task rank ABI");

struct stela_linux_task_ops {
	/* Actual CPU/IRQ/RSP/current ticket validation, bounded and allocation-
	 * free. The retained binding/code outlive this attached task. */
	bool (*is_current)(void *binding, const struct stela_linux_task_context *context);
	/* Exact active-job signal; caller already proved a real same-CPU C
	 * current and retained target lifetime. No allocation/switch/final drop. */
	int (*wake_target)(void *binding, u64 expected_sequence);
	/* Immutable real Runtime reservation; never caller-controlled task flags.
	 * Used only after first waker publication and target generation validation. */
	bool (*service_reserved)(void *binding);
	/* Same-queue retained task's original PI/policy commit, or its private
	 * exit normalization. Records are copied synchronously; no C pointer is
	 * stored by Runtime. Update must succeed before C commits its fields. */
	int (*rank)(void *binding, u64 expected_sequence,
		    const struct stela_linux_task_rank *before,
		    const struct stela_linux_task_rank *after, bool head);
};
_Static_assert(sizeof(struct stela_linux_task_ops) == 32, "Linux task callbacks ABI");

struct stela_linux_task_scope_ops {
	/* Retained shared Runtime borrow on this actual stack. No unwind or
	 * escape. park: 0 skipped, 1 resumed; yield: 0 resumed; negative errno. */
	int (*park)(void *scope);
	int (*yield)(void *scope);
	int (*reschedule)(void *scope);
	/* Read actual pending wake/due service state only at eligible process
	 * boundaries. A failed/closed provider is terminal, never false. */
	bool (*reschedule_requested)(void *scope);
};

/* Private serialized Linux lease. Suspend is not exit: no callbacks or owner
 * drops run in IF=0 hooks. All functions require the actual qualified CPU. */
struct stela_linux_lease {
	const struct stela_linux_owner *owner;
	unsigned long irq_flags;
	u64 generation;
};
void stela_linux_lease_snapshot(struct stela_linux_lease *lease);
bool stela_linux_lease_matches(const struct stela_linux_lease *lease);
void stela_linux_lease_suspend(const struct stela_linux_lease *lease);
bool stela_linux_lease_resume(const struct stela_linux_lease *lease);

/* Allocation/release run in qualified process context, outside Linux entry.
 * Attach/leave/arrive/complete/detach are bounded IF=0 Runtime switch hooks.
 * Return failure before mutation; corruption after a committed switch traps. */
unsigned int stela_linux_task_catalog_capacity(void);
size_t stela_linux_task_stack_bytes(void);
size_t stela_linux_task_stack_alignment(void);
size_t stela_linux_task_stack_guard(void);
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
/* Internal prepared transition hooks. The selected original mutex scheduler
 * adapter owns the sole preempt level; count==1 alone does not distinguish
 * that level from an outer RCU reader. Generic schedule enters at count0 and
 * never borrows the normal-mutex level. Non-PREEMPT_RT mutex waits use this
 * process boundary after their distinct pre-schedule worker preparation. */
int stela_linux_task_park(bool scheduler_preempt_disabled);
int stela_linux_task_yield(void);
struct task_struct *stela_linux_current(void);
/* Borrowed actual task owning this complete live-generation stack range on
 * the current real Runtime queue; NULL for unowned/closed/overflowing ranges.
 * Requires actual entered same-CPU current before any catalog/storage access.
 * Reads no storage bytes. Bounds exclude guards and non-stack metadata. This
 * proves neither an inner frame's lifetime nor arbitrary pointer ownership.
 * A timer consumer must independently retain its original storage/frame,
 * arm/task reference and real producer lifetime through cancel/drain. */
struct task_struct *stela_linux_task_stack_owner(const void *storage, size_t bytes);
struct thread_info *stela_linux_thread_info(void);
/* Narrow kernel-wait cancellation, not POSIX process/siginfo delivery. Values
 * 1/2 post actual SIGUSR1/SIGKILL bits. Target metadata is retained separately;
 * an old sequence returns -ESTALE before reading future-job state. */
int stela_linux_task_signal(struct stela_linux_task *task, u64 expected_sequence,
	unsigned int kind);
int stela_linux_task_ack_signal(unsigned int kind);
unsigned int stela_linux_task_pending_signals(void);
unsigned int stela_linux_task_waiting_io(void);
unsigned int stela_linux_task_waiting_load(void);
#endif
