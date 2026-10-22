// SPDX-License-Identifier: MIT
/* The execution Stela gives Linux code: one owner at a time, on one context
 * that nothing preempts or interrupts. */
#include <linux/irqflags.h>
#include <linux/processor.h>
#include <linux/preempt.h>
#include <linux/thread_info.h>
#include <stela/linux.h>

static const struct stela_linux_services no_services;
const struct stela_linux_owner stela_linux_bare = {.services = &no_services};

static bool running;
static const struct stela_linux_owner *owner;

void stela_linux_enter(const struct stela_linux_owner *next)
{
	if (!next || !next->services)
		__builtin_trap();
	while (__atomic_exchange_n(&running, true, __ATOMIC_ACQUIRE))
		cpu_relax();
	owner = next;
}

void stela_linux_exit(void)
{
	if (!owner)
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

/* Linux code's single context, with its preemption count and thread flags. */
int __preempt_count;
struct thread_info stela_thread_info;

/* The interrupt flag local_irq_save() and its kind keep. No interrupt reaches
 * Linux code either way. */
static unsigned long irq_flags = ARCH_IRQ_ENABLED;

unsigned long arch_local_save_flags(void)
{
	return irq_flags;
}

void arch_local_irq_restore(unsigned long flags)
{
	irq_flags = flags;
}
