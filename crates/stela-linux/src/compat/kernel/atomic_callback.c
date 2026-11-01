// SPDX-License-Identifier: MIT
/* Shared serialized callback lifecycle; no native IRQ admission is supplied. */
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

enum callback_kind { CALLBACK_HARD, CALLBACK_SOFT, CALLBACK_DISPATCH, CALLBACK_BH, CALLBACK_PROCESS };
struct callback_state {
	const struct stela_linux_atomic_callback *scope;
	struct task_struct *task;
	struct stela_linux_lease entry, callback;
	enum callback_kind kind;
	int count;
};
static struct callback_state active;

bool stela_linux_atomic_callback_active(void)
{
	return active.scope != NULL;
}

static void begin(struct stela_linux_atomic_callback *scope, enum callback_kind kind)
{
	/* No saved ownership, IRQ or nesting mutation before these refusals. */
	if (!scope || active.scope)
		__builtin_trap();
	struct task_struct *task = stela_linux_current();
	int count = preempt_count();
	if (kind == CALLBACK_DISPATCH || kind == CALLBACK_BH) {
		/* Original BH enable retains one internal preempt reference plus any
		 * outer process nesting. Original dispatch supplies its own soft count.
		 */
		if (((unsigned int)count & ~PREEMPT_MASK) !=
		    (kind == CALLBACK_BH ? SOFTIRQ_DISABLE_OFFSET : 0U))
			__builtin_trap();
	} else if (!stela_linux_quiescent()) {
		__builtin_trap();
	}
	struct stela_linux_lease entry;
	stela_linux_lease_snapshot(&entry);
	if (!entry.owner || !entry.generation ||
	    (entry.irq_flags != ARCH_IRQ_ENABLED && entry.irq_flags != ARCH_IRQ_DISABLED) ||
	    (kind != CALLBACK_DISPATCH && kind != CALLBACK_BH && entry.irq_flags != ARCH_IRQ_ENABLED))
		__builtin_trap();
	active = (struct callback_state){.scope = scope, .task = task, .entry = entry,
		.kind = kind, .count = count};
	if (kind == CALLBACK_HARD) {
		unsigned long flags;
		raw_local_irq_save(flags);
		if (flags != entry.irq_flags)
			__builtin_trap();
		__irq_enter_raw();
	} else if (kind == CALLBACK_SOFT) {
		preempt_count_add(SOFTIRQ_OFFSET);
	}
	stela_linux_lease_snapshot(&active.callback);
}

void stela_linux_atomic_callback_begin(struct stela_linux_atomic_callback *scope)
{
	begin(scope, CALLBACK_HARD);
}

void stela_linux_atomic_callback_begin_soft(struct stela_linux_atomic_callback *scope)
{
	begin(scope, CALLBACK_SOFT);
}

void stela_linux_atomic_softirq_dispatch_begin(struct stela_linux_atomic_callback *scope)
{
	begin(scope, CALLBACK_DISPATCH);
}

void stela_linux_atomic_callback_bh_begin(struct stela_linux_atomic_callback *scope)
{
	begin(scope, CALLBACK_BH);
}

void stela_linux_atomic_process_leaf_begin(struct stela_linux_atomic_callback *scope)
{
	begin(scope, CALLBACK_PROCESS);
}

static void end(struct stela_linux_atomic_callback *scope, unsigned int release_kind)
{
	unsigned int kind = active.kind == CALLBACK_DISPATCH ? 1U : active.kind == CALLBACK_BH ? 2U : active.kind == CALLBACK_PROCESS ? 3U : 0U;
	if (!scope || active.scope != scope ||
	    kind != release_kind ||
	    stela_linux_current() != active.task)
		__builtin_trap();
	int expected = active.count;
	if (active.kind == CALLBACK_HARD)
		expected += (int)HARDIRQ_OFFSET;
	else if (active.kind == CALLBACK_SOFT)
		expected += (int)SOFTIRQ_OFFSET;
	if (preempt_count() != expected || !stela_linux_lease_matches(&active.callback))
		__builtin_trap();
	if (active.kind == CALLBACK_HARD) {
		__irq_exit_raw();
		raw_local_irq_restore(active.entry.irq_flags);
	} else if (active.kind == CALLBACK_SOFT) {
		preempt_count_sub(SOFTIRQ_OFFSET);
	}
	if (preempt_count() != active.count || stela_linux_current() != active.task ||
	    !stela_linux_lease_matches(&active.entry))
		__builtin_trap();
	/* Remain guarded through exact restoration, including passive dispatch. */
	active = (struct callback_state){};
}

void stela_linux_atomic_callback_end(struct stela_linux_atomic_callback *scope)
{
	end(scope, 0);
}

void stela_linux_atomic_softirq_dispatch_end(struct stela_linux_atomic_callback *scope)
{
	end(scope, 1);
}

void stela_linux_atomic_callback_bh_end(struct stela_linux_atomic_callback *scope)
{
	end(scope, 2);
}

void stela_linux_atomic_process_leaf_end(struct stela_linux_atomic_callback *scope)
{
	end(scope, 3);
}
