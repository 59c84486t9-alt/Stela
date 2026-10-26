// SPDX-License-Identifier: MIT
/* One shared nonblocking callback boundary for retained task delivery. The
 * selected UP image has no Linux entry from a native ISR or another CPU.
 * All real CPU/root/task/provider authority is retained by the delivery owner.
 */
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/task.h>

static_assert(!IS_ENABLED(CONFIG_SMP));
static_assert(!IS_ENABLED(CONFIG_PREEMPT_RT));
static_assert(IS_ENABLED(CONFIG_PREEMPT_COUNT));
static_assert(!IS_ENABLED(CONFIG_DEBUG_LOCK_ALLOC));
static_assert(!IS_ENABLED(CONFIG_TRACE_IRQFLAGS));

struct callback_state {
	const struct stela_linux_atomic_callback *scope;
	struct task_struct *task;
	struct stela_linux_lease entry, callback;
};
static struct callback_state active;

bool stela_linux_atomic_callback_active(void)
{
	return active.scope != NULL;
}

void stela_linux_atomic_callback_begin(struct stela_linux_atomic_callback *scope)
{
	/* Refuse before changing saved ownership, IRQs or original nesting. */
	if (!scope || active.scope)
		__builtin_trap();
	struct task_struct *task = stela_linux_current();
	if (!stela_linux_quiescent())
		__builtin_trap();
	struct stela_linux_lease entry;
	stela_linux_lease_snapshot(&entry);
	if (!entry.owner || !entry.generation || entry.irq_flags != ARCH_IRQ_ENABLED)
		__builtin_trap();
	active = (struct callback_state){.scope = scope, .task = task, .entry = entry};
	unsigned long flags;
	raw_local_irq_save(flags);
	if (flags != entry.irq_flags)
		__builtin_trap();
	/* Exact original raw bookkeeping: no irq_enter time/jiffies/RCU effects. */
	__irq_enter_raw();
	stela_linux_lease_snapshot(&active.callback);
}

void stela_linux_atomic_callback_end(struct stela_linux_atomic_callback *scope)
{
	/* Saved state is private; a different token cannot release this scope. */
	if (!scope || active.scope != scope || stela_linux_current() != active.task ||
	    preempt_count() != (int)HARDIRQ_OFFSET ||
	    !stela_linux_lease_matches(&active.callback))
		__builtin_trap();
	__irq_exit_raw();
	raw_local_irq_restore(active.entry.irq_flags);
	if (preempt_count() || stela_linux_current() != active.task ||
	    !stela_linux_lease_matches(&active.entry))
		__builtin_trap();
	/* Remain guarded through restoration; no callback can clear this flag. */
	active = (struct callback_state){};
}
