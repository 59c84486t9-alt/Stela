/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef STELA_SRCU_H
#define STELA_SRCU_H
#include <linux/types.h>
struct stela_linux_owner;
struct rcu_head;
struct srcu_struct;

/* Private one-shot source ownership boundary for the actual original Initial.
 * Validates same canonical/current factory record, exact init_task identity and
 * original inactive RCU scheduler. No initcall/current/resource/progress grant.
 * The source bootstrap alone calls original earlyWQ/RCU/SRCU in original order. */
int stela_linux_srcu_bind_initial(const struct stela_linux_owner *owner);

/* Probe already-initialized original SRCU/workqueues/clock on an actual owned
 * canonical task. This never calls rcu_init/srcu_init/scheduler-start itself.
 * Failure retains source ownership and original pending work. Public admission
 * still needs the separate exact Rust Bootstrap original managed-request join. */
int stela_linux_srcu_bootstrap(const struct stela_linux_owner *owner);

/* May be read by that Environment's dispatcher without entering Linux. This
 * is a shutdown refusal check, never an execution/admission capability. */
bool stela_linux_srcu_owner_bound(const struct stela_linux_owner *owner);
/* Status only; never a task/admission or completion receipt. */
bool stela_linux_srcu_bootstrapping(const struct stela_linux_owner *owner);

/* Fallible consumer prerequisite on an actual entered canonical task. Zero
 * requires original normal/high replacement-worker+timer probes AND the exact
 * original managed Bootstrap complete request join. Wrong canonical owner is EPERM; unjoined phase is
 * EAGAIN. This is neither full-task readiness nor later resource availability,
 * a callback-completion receipt, or new CPU/root/IRQ/stack permission. */
int stela_linux_srcu_current_active(const struct stela_linux_owner *owner);

/* Internal guards validate the actual source-bound task/context. Original
 * early queueing, inactive fastpaths and genuine pre-probe worker progress are
 * preserved; public joined admission is a separate predicate above. */
void stela_linux_srcu_require_bound(void);
void stela_linux_srcu_require_wait_context(void);
void stela_linux_srcu_invoke(struct rcu_head *head);
void stela_linux_srcu_cleanup_begin(struct srcu_struct *ssp);
void stela_linux_srcu_cleanup_end(struct srcu_struct *ssp);
#endif
