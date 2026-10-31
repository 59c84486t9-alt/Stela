/* SPDX-License-Identifier: MIT */
#ifndef STELA_ATOMIC_CALLBACK_H
#define STELA_ATOMIC_CALLBACK_H
#include <linux/types.h>

/* Private Timer/IRQ-work delivery scope, never passed to a callback. Only its
 * exact address is a token; all saved state stays in the serialized module.
 * It must remain live and immovable until end() returns. No copy/reset API.
 */
struct stela_linux_atomic_callback { unsigned char private; };

/* These are same-qualified-CPU internal services, not native IRQ entry or a
 * provider/admission grant. begin() requires an actual retained Linux current,
 * entered owner, enabled simulated IRQs and balanced process context. It saves
 * IRQ state and invokes Linux's original __irq_enter_raw()/__irq_exit_raw()
 * around the caller's batch. Recursive entry or mismatched/unbalanced return
 * traps. No time accounting, softirq dispatch or preemption is synthesized.
 */
void stela_linux_atomic_callback_begin(struct stela_linux_atomic_callback *scope);
void stela_linux_atomic_callback_end(struct stela_linux_atomic_callback *scope);

/* Known soft Timer callback: balanced process entry, enabled simulated IRQs;
 * supplies only SOFTIRQ_OFFSET and restores it through callback_end(). */
void stela_linux_atomic_callback_begin_soft(struct stela_linux_atomic_callback *scope);

/* Passive lifecycle guard around original softirq dispatch. Entry may retain
 * arbitrary process-only PREEMPT_MASK nesting and either simulated IRQ state.
 * Adds no nesting, IRQ transition, RCU/tick effect or dispatch. The complete
 * original body must restore the exact incoming count/IRQs/current/lease before
 * dispatch_end(). Independent active state forbids drain/suspend/owner exit
 * even if a callback rebalances public counters. Not a service-role grant.
 */
void stela_linux_atomic_softirq_dispatch_begin(struct stela_linux_atomic_callback *scope);
void stela_linux_atomic_softirq_dispatch_end(struct stela_linux_atomic_callback *scope);

/* Pure guard around one original callback already inside exactly one BH
 * disable level (SOFTIRQ_DISABLE_OFFSET plus process PREEMPT_MASK nesting).
 * Adds no count or IRQ transition. End with the exact incoming state BEFORE
 * the original local_bh_enable, permitting its genuine later softirq dispatch.
 * This is not softirq entry or a callback/Task/domain authorization grant.
 */
void stela_linux_atomic_callback_bh_begin(struct stela_linux_atomic_callback *scope);
void stela_linux_atomic_callback_bh_end(struct stela_linux_atomic_callback *scope);

/* A nonblocking process leaf on the actual retained service task. Requires
 * balanced entered process context and enabled simulated IRQs. Adds no IRQ,
 * softirq or preempt nesting; the private guard forbids sleeping/owner exit and
 * verifies exact state restoration around bounded wake/notification callbacks.
 */
void stela_linux_atomic_process_leaf_begin(struct stela_linux_atomic_callback *scope);
void stela_linux_atomic_process_leaf_end(struct stela_linux_atomic_callback *scope);

/* Independent of caller-rebalanceable preempt/IRQ counters. Owner exit,
 * quiescence, PREPARE and lease switches consult this BEFORE effects/drains.
 * It supplies no task, owner, physical ISR or execution-root authorization.
 */
bool stela_linux_atomic_callback_active(void);
#endif
