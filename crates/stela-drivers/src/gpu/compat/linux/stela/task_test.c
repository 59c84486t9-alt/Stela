// SPDX-License-Identifier: MIT
/* Callable mechanics fixtures. These use real Runtime stacks/current tasks;
 * the separately retained Rust test CPU is a hosted model, not native entry. */
#include <linux/bottom_half.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
#include <stela/linux.h>
#include <stela/task.h>
#include <stela/test.h>

void stela_linux_task_test_taskless(void);
void stela_linux_task_test_unprepared_begin(void);
void stela_linux_task_test_unprepared_end(void);
void stela_linux_task_test_foreground(void *context);
void stela_linux_task_test_worker(void *context);

static unsigned int callbacks;
static const struct stela_linux_owner *callback_owner;
static struct task_struct *foreground_task;
static bool worker_done;
static struct rcu_head retirement;

static void taskless_current(void)
{
	(void)READ_ONCE(current->flags);
}

void stela_linux_task_test_taskless(void)
{
	assert(stela_test_traps(taskless_current));
}

static const struct stela_linux_services unprepared_services;
static const struct stela_linux_owner unprepared_owner = {.services = &unprepared_services};

void stela_linux_task_test_unprepared_begin(void)
{
	stela_linux_enter(&unprepared_owner);
	assert(stela_linux_quiescent());
	assert(current->flags == PF_KTHREAD);
}

void stela_linux_task_test_unprepared_end(void)
{
	assert(stela_linux_owner() == &unprepared_owner);
	assert(stela_linux_quiescent());
	assert(current->flags == PF_KTHREAD);
	stela_linux_exit();
}

static void retired(struct rcu_head *head)
{
	assert(head == &retirement);
	assert(stela_linux_owner() == callback_owner);
	assert(current == foreground_task);
	/* Original rcu_barrier invokes each callback under its real softirq
	 * accounting; process PREPARE rechecks quiescence after that drain. */
	assert(preempt_count() == (int)SOFTIRQ_OFFSET && !irqs_disabled());
	assert(!stela_linux_quiescent());
	callbacks++;
}

static void check_current(void)
{
	struct task_struct *task = current;
	unsigned long pointer;
	asm volatile("mov %%rsp, %0" : "=r"(pointer));
	assert(task_thread_info(task) == current_thread_info());
	assert(task->thread_info.task == task);
	assert(task->flags == PF_KTHREAD);
	assert(task->stack && pointer >= (unsigned long)task->stack);
	assert(pointer - (unsigned long)task->stack < THREAD_SIZE);
	assert(!task_stack_end_corrupted(task));
	assert(refcount_read(&task->stack_refcount) == 1);
}

void stela_linux_task_test_foreground(void *context)
{
	(void)context;
	const struct stela_linux_services services = {};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	check_current();
	foreground_task = current;
	callback_owner = &owner;
	assert(stela_linux_quiescent());
	preempt_disable();
	assert(stela_linux_task_yield() == -EBUSY);
	assert(preempt_count() == 1 && current == foreground_task);
	preempt_enable();
	local_bh_disable();
	int bh_count = preempt_count();
	assert(stela_linux_task_yield() == -EBUSY);
	assert(preempt_count() == bh_count);
	local_bh_enable();
	local_irq_disable();
	assert(stela_linux_task_yield() == -EBUSY);
	assert(irqs_disabled());
	local_irq_enable();
	rcu_read_lock();
	assert(stela_linux_task_yield() == -EBUSY);
	assert(preempt_count() == 1);
	rcu_read_unlock();
	/* Real predicate skips a TASK_RUNNING park without switching/leaving. */
	assert(!stela_linux_task_park(false));
	assert(!worker_done && current == foreground_task);
	/* This one known preempt level is this fixture's scheduler level, never
	 * an outer RCU/BH/IRQ critical section. The original Linux scheduler
	 * exports remain unadmitted by this mechanics-only fixture. */
	set_current_state(TASK_UNINTERRUPTIBLE);
	preempt_disable();
	call_rcu(&retirement, retired);
	assert(!callbacks);
	assert(stela_linux_task_park(true) == 1);
	assert(callbacks == 1 && worker_done && preempt_count() == 1);
	assert(current == foreground_task && current->__state == TASK_RUNNING);
	assert(stela_linux_owner() == &owner);
	preempt_enable();
	assert(!stela_linux_task_yield());
	check_current();
	assert(stela_linux_quiescent());
	callback_owner = NULL;
	stela_linux_exit();
}

void stela_linux_task_test_worker(void *context)
{
	(void)context;
	const struct stela_linux_services services = {};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	check_current();
	assert(current != foreground_task && callbacks == 1);
	assert(!preempt_count() && !irqs_disabled());
	assert(stela_linux_owner() == &owner);
	worker_done = true;
	stela_linux_exit();
}
