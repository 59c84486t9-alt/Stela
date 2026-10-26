// SPDX-License-Identifier: MIT
/* The execution Stela gives Linux code: one owner at a time, on one context
 * that nothing preempts or interrupts. */
#include <linux/bug.h>
#include <linux/irqflags.h>
#include <linux/bottom_half.h>
#include <linux/processor.h>
#include <linux/preempt.h>
#include <linux/thread_info.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/task.h>

static const struct stela_linux_services no_services;
const struct stela_linux_owner stela_linux_bare = {.services = &no_services};

static bool running;
static const struct stela_linux_owner *owner;
/* Logical entry identity. A qualified task switch preserves this generation;
 * a complete exit/reenter always issues a fresh one, even for the same owner. */
static u64 entry_serial, entry_generation;
/* No interrupt reaches Linux code. This is only its simulated local state. */
static unsigned long irq_flags = ARCH_IRQ_ENABLED;
/* Linux headers keep actual nested atomic/read-side state here. */
struct thread_info stela_thread_info;

/* Only the task adapter calls these under the real same-CPU switch exclusion.
 * A suspended task retains its borrowed owner/context and critical metadata. */
void stela_linux_lease_snapshot(struct stela_linux_lease *lease)
{
	bool entered = __atomic_load_n(&running, __ATOMIC_ACQUIRE);
	if (entered != (owner != NULL) || entered != (entry_generation != 0))
		__builtin_trap();
	*lease = (struct stela_linux_lease){.owner = owner, .irq_flags = irq_flags,
		.generation = entry_generation};
}

bool stela_linux_lease_matches(const struct stela_linux_lease *lease)
{
	return __atomic_load_n(&running, __ATOMIC_ACQUIRE) == (lease->owner != NULL) &&
	       owner == lease->owner && irq_flags == lease->irq_flags &&
	       entry_generation == lease->generation &&
	       (lease->owner != NULL) == (lease->generation != 0);
}

void stela_linux_lease_suspend(const struct stela_linux_lease *lease)
{
	if (stela_linux_atomic_callback_active() || !stela_linux_lease_matches(lease))
		__builtin_trap();
	owner = NULL;
	entry_generation = 0;
	irq_flags = ARCH_IRQ_ENABLED;
	if (lease->owner)
		__atomic_store_n(&running, false, __ATOMIC_RELEASE);
}

bool stela_linux_lease_resume(const struct stela_linux_lease *lease)
{
	/* Validate the saved continuation before ANY mutation. The internal task
	 * state machine additionally owns resume-once/actual-owner authority. */
	if (stela_linux_atomic_callback_active() ||
	    (lease->owner != NULL) != (lease->generation != 0) ||
	    lease->generation > entry_serial ||
	    (lease->irq_flags != ARCH_IRQ_ENABLED && lease->irq_flags != ARCH_IRQ_DISABLED) ||
	    (!lease->owner && lease->irq_flags != ARCH_IRQ_ENABLED) || owner || entry_generation ||
	    irq_flags != ARCH_IRQ_ENABLED)
		return false;
	if (!lease->owner)
		return !__atomic_load_n(&running, __ATOMIC_ACQUIRE);
	bool expected = false;
	if (!__atomic_compare_exchange_n(&running, &expected, true, false,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return false;
	owner = lease->owner;
	entry_generation = lease->generation;
	irq_flags = lease->irq_flags;
	return true;
}

bool stela_linux_try_enter(const struct stela_linux_owner *next)
{
	if (!next || !next->services)
		__builtin_trap();
	bool expected = false;
	if (!__atomic_compare_exchange_n(&running, &expected, true, false,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return false;
	if (owner || entry_generation || preempt_count() || irq_flags != ARCH_IRQ_ENABLED)
		__builtin_trap();
	if (entry_serial == ~(u64)0)
		__builtin_trap(); /* Never wrap/reissue a logical entry identity. */
	owner = next;
	entry_generation = ++entry_serial;
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
	entry_generation = 0;
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
	if (current_owner->services->warn)
		current_owner->services->warn(current_owner->context, file, line, condition);
	/* Same taint encoding consumed by original BUG_GET_TAINT. */
	add_taint(flags >> 8, LOCKDEP_STILL_OK);
}

/* A terminal selected-domain stop, not Linux panic/reboot/crash dumping. */
void stela_linux_fatal(const char *message)
{
	const struct stela_linux_owner *current_owner = stela_linux_owner();
	if (current_owner->services->log)
		current_owner->services->log(current_owner->context, LOGLEVEL_EMERG, message);
	/* A returning logger cannot turn this failure into a successful return. */
	__builtin_trap();
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
	return !stela_linux_atomic_callback_active() &&
	       !stela_linux_rcu_callback_active() &&
	       !preempt_count() && irq_flags == ARCH_IRQ_ENABLED;
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

#ifdef STELA_LINUX_ENTRY_GENERATION_TEST
#include <stela/test.h>
static void exhaust_generation(void)
{
 entry_serial = ~(u64)0;
 stela_linux_enter(&stela_linux_bare);
}
int main(void)
{
 struct stela_linux_lease taskless, first, same, other, restored;
 stela_linux_lease_snapshot(&taskless);
 assert(!taskless.owner && !taskless.generation && stela_linux_lease_matches(&taskless));
 stela_linux_enter(&stela_linux_bare);
 stela_linux_lease_snapshot(&first);
 assert(first.owner == &stela_linux_bare && first.generation);
 stela_linux_exit();
 assert(!stela_linux_lease_matches(&first));
 stela_linux_enter(&stela_linux_bare);
 stela_linux_lease_snapshot(&same);
 assert(same.generation > first.generation && !stela_linux_lease_matches(&first));
 /* A task switch is continuation, unlike exit: an intervening owner gets a
  * fresh serial, then resume restores the exact saved logical entry. */
 stela_linux_lease_suspend(&same);
 stela_linux_lease_snapshot(&taskless);
 assert(!taskless.owner && !taskless.generation);
 const struct stela_linux_services services = {};
 const struct stela_linux_owner different = {.services=&services,.context=&other};
 stela_linux_enter(&different);
 stela_linux_lease_snapshot(&other);
 assert(other.owner==&different && other.generation > same.generation);
 stela_linux_exit();
 struct stela_linux_lease invalid = same;
 invalid.generation=0;
 assert(!stela_linux_lease_resume(&invalid) && stela_linux_lease_matches(&taskless));
 invalid=taskless; invalid.generation=first.generation;
 assert(!stela_linux_lease_resume(&invalid) && stela_linux_lease_matches(&taskless));
 invalid=same; invalid.generation=~(u64)0;
 assert(!stela_linux_lease_resume(&invalid) && stela_linux_lease_matches(&taskless));
 assert(stela_linux_lease_resume(&same));
 stela_linux_lease_snapshot(&restored);
 assert(restored.owner==same.owner && restored.generation==same.generation &&
	    stela_linux_lease_matches(&same) && !stela_linux_lease_matches(&other));
 assert(!stela_linux_lease_resume(&other) && stela_linux_lease_matches(&same));
 stela_linux_exit();
 assert(stela_test_traps(exhaust_generation));
 stela_linux_lease_snapshot(&taskless);
 assert(!taskless.owner && !taskless.generation);
 printf("Linux entry generation: real entry identity, task continuation and no wrap fixtures passed\n");
 return 0;
}
#endif
