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

/* Independent of caller-rebalanceable preempt/IRQ counters. Owner exit,
 * quiescence, PREPARE and lease switches consult this BEFORE effects/drains.
 * It supplies no task, owner, physical ISR or execution-root authorization.
 */
bool stela_linux_atomic_callback_active(void);
#endif
