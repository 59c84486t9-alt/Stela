/* SPDX-License-Identifier: MIT */
#ifndef STELA_TASK_BOOTSTRAP_H
#define STELA_TASK_BOOTSTRAP_H
#include <linux/types.h>
struct stela_linux_owner;
struct task_struct;
struct kernel_clone_args;
/* Defined and born ONLY in the actual original dup_task_struct factory after
 * successful original slab allocation+arch copy. Definition/constructor stay
 * private to that source unit; no task-pointer adoption API is exposed. */
struct stela_linux_task_birth;
int stela_linux_task_birth_take(struct stela_linux_task_birth *birth,
    struct task_struct **task, u64 *generation);
/* REQUIRED actual native child producer ABI. No provider implementation or
 * success stub is supplied by this source-only C bootstrap slice. Allocation
 * returns errno ONLY with actual no-accept/canceled-escrow proof; unknown
 * publication retains/fatals before original C is allowed to reclaim owners.
 * The actual original dup_task_struct owns the supplied fresh task object.
 * Native pin/frame/page-descriptor ownership must precede tsk->stack install. */
int stela_linux_task_stack_allocate(struct stela_linux_task_birth *birth, int node,
    bool *unexposed);
/* After original reverse-unwind has really run, on the SAME creator's real
 * sleepable current: join original stack/task/RCU release and cancel native
 * owned escrow. Must retain/fatal on refusal, never infer this from errno.
 * Zero means the actual source factory created no native birth. Generation is
 * lookup/freshness only; it constructs no owner or no-publication permission. */
void stela_linux_task_fork_abort(u64 source_birth_generation);
int stela_linux_task_thread_prepare(struct task_struct *task,
    const struct kernel_clone_args *args);
/* No allocation/wait/original rollback after nativeDormant accepted. Exact
 * source resource snapshot +native/page capacity preflight precedes Cpub. */
void stela_linux_task_fork_publish(struct task_struct *task);
void stela_linux_task_fork_visible(struct task_struct *task);
/* Before-free validates retained native/source phase while task is live.
 * After-free accepts OPAQUE IDENTITY ONLY and must never dereference task. */
u64 stela_linux_task_free_prepare(struct task_struct *task);
void stela_linux_task_source_freed(u64 source_birth_generation);
struct stela_linux_task;
/* REQUIRED actual typed producer. Source-freed callback is IRQ-safe record+
 * wake only; abort joins actual cancel and must retain/fatal on uncertainty. */
void stela_linux_task_native_source_freed(struct stela_linux_task *task,
    const struct stela_linux_owner *owner, u64 generation);
/* One genuine final source callback-tail release event. Same actual RaisedWork
 * only, no C entry/finalize/drop/wait/inline process callback from this tail. */
void stela_linux_task_native_source_tail(struct stela_linux_task *task,
    const struct stela_linux_owner *owner, u64 generation);
void stela_linux_task_native_abort(struct stela_linux_task *task,
    const struct stela_linux_owner *owner, u64 generation);
struct stela_linux_task_rank;
int stela_linux_task_native_thread_prepare(struct stela_linux_task *task,
    const struct stela_linux_owner *owner, int (*entry)(void *), void *argument);
void stela_linux_task_native_publish(struct stela_linux_task *task,
    const struct stela_linux_owner *owner, const struct stela_linux_task_rank *rank);
void stela_linux_task_native_activate(struct stela_linux_task *task,
    const struct stela_linux_owner *owner);
/* Actual native physical-successor event only; record+wake, no C current,
 * allocation/drop/wait or original sleeping reaper work on dispatcher. */
void stela_linux_task_native_terminal_returned(struct stela_linux_task *task,
    const struct stela_linux_owner *owner, u64 generation);
/* Required permanent process service entry, called only after genuine PID1,
 * PID2 body completion and actual full original workqueue initialization.
 * Request/reaper owner graph must already be retained, no transient native
 * permit may span this possibly blocking nonreturning body. The genuine C
 * supervisor loop below consumes the REQUIRED same-adapter pending/process
 * operations; registration alone supplies no online/Ready success. */
/* SAME actual typed adapter owns these bounded pending/process operations.
 * pending is an actual queue predicate, never a readiness default. One step
 * runs on actual PID1 and may execute original reaper waits after dropping all
 * native/row/mutation borrows. Unknown publication retains its request graph. */
bool stela_linux_task_native_pending(const struct stela_linux_owner *owner);
int stela_linux_task_native_process_one(const struct stela_linux_owner *owner);
void __noreturn stela_linux_task_native_supervisor(const struct stela_linux_owner *owner);
/* Called only by canonical ACTUAL process service after native RaisedWork
 * delivery, never from native IRQ/dispatcher/leaf callback. */
int stela_linux_task_source_broker_wake(const struct stela_linux_owner *owner);
void stela_linux_task_kthreadd_started(void);
int stela_linux_task_bootstrap_threads(const struct stela_linux_owner *owner);
void stela_linux_task_wake_new(struct task_struct *task);
void __noreturn stela_linux_task_run_original(void *context);

/* Private source bootstrap only, called after exact Initial/current/scope
 * admission in task.c. Native allocator/page/CPU/time/IRQ source owners must
 * already be real and retained; this is no substitute producer for them.
 * Calls original helpers directly; partial effects are never reset/retried. */
int stela_linux_task_bootstrap_resources(const struct stela_linux_owner *owner);
/* Only whether that exact direct source sequence returned, NOT FullReady,
 * current, original worker progress, callback join or capacity authority. */
bool stela_linux_task_resource_roots_complete(const struct stela_linux_owner *owner);
#endif
