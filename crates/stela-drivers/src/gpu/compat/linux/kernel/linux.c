// SPDX-License-Identifier: MIT
/* The execution Stela gives Linux code: one owner at a time, on one context
 * that nothing preempts or interrupts. */
#include <linux/irqflags.h>
#include <linux/bottom_half.h>
#include <linux/processor.h>
#include <linux/preempt.h>
#include <linux/thread_info.h>
#include <stela/linux.h>
#include <stela/page.h>

static const struct stela_linux_services no_services;
const struct stela_linux_owner stela_linux_bare = {.services = &no_services};

static bool running;
static const struct stela_linux_owner *owner;
/* No interrupt reaches Linux code. This is only its simulated local state. */
static unsigned long irq_flags = ARCH_IRQ_ENABLED;
/* Linux headers keep actual nested atomic/read-side state here. */
struct thread_info stela_thread_info;

bool stela_linux_try_enter(const struct stela_linux_owner *next)
{
	if (!next || !next->services)
		__builtin_trap();
	bool expected = false;
	if (!__atomic_compare_exchange_n(&running, &expected, true, false,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return false;
	if (owner || preempt_count() || irq_flags != ARCH_IRQ_ENABLED)
		__builtin_trap();
	owner = next;
	return true;
}

void stela_linux_enter(const struct stela_linux_owner *next)
{
	while (!stela_linux_try_enter(next))
		cpu_relax();
}

void stela_linux_exit(void)
{
	if (!stela_linux_quiescent())
		__builtin_trap();
	stela_linux_rcu_finish();
	stela_linux_pages_finish();
	if (!stela_linux_quiescent())
		__builtin_trap();
	owner = NULL;
	__atomic_store_n(&running, false, __ATOMIC_RELEASE);
}

const struct stela_linux_owner *stela_linux_owner(void)
{
	if (!owner)
		__builtin_trap();
	return owner;
}

void stela_linux_unsupported(const char *operation)
{
	const struct stela_linux_owner *current_owner = stela_linux_owner();
	if (!current_owner->services->unsupported)
		__builtin_trap();
	current_owner->services->unsupported(current_owner->context, operation);
}

void stela_linux_warn(const char *file, int line, const char *condition, unsigned int flags)
{
	const struct stela_linux_owner *current_owner = stela_linux_owner();
	(void)flags;
	if (current_owner->services->warn)
		current_owner->services->warn(current_owner->context, file, line, condition);
}

unsigned long arch_local_save_flags(void)
{
	(void)stela_linux_owner();
	return irq_flags;
}

void arch_local_irq_restore(unsigned long flags)
{
	(void)stela_linux_owner();
	if (flags != ARCH_IRQ_ENABLED && flags != ARCH_IRQ_DISABLED)
		__builtin_trap();
	irq_flags = flags;
}

bool stela_linux_quiescent(void)
{
	(void)stela_linux_owner();
	return !preempt_count() && irq_flags == ARCH_IRQ_ENABLED;
}

/* Only depth bookkeeping is needed in this nonpreemptible, non-interrupting
 * context. RCU work is deferred until a checked quiescent boundary, never
 * invoked from inside another atomic/read-side section. */
static void enable_bh(unsigned int count)
{
	(void)stela_linux_owner();
	int nesting = preempt_count();
	if (nesting < 0 || !count || (count & ~(SOFTIRQ_MASK | PREEMPT_MASK)) ||
	    softirq_count() < (count & SOFTIRQ_MASK) ||
	    ((unsigned int)nesting & PREEMPT_MASK) < (count & PREEMPT_MASK))
		__builtin_trap();
	barrier();
	preempt_count_sub((int)count);
}

void _local_bh_enable(void)
{
	enable_bh(SOFTIRQ_DISABLE_OFFSET);
}

void __local_bh_enable_ip(unsigned long ip, unsigned int count)
{
	(void)ip;
	if (irqs_disabled() || in_hardirq())
		__builtin_trap();
	enable_bh(count);
}
