// SPDX-License-Identifier: MIT
/* Called on the existing fixture's real retained Runtime/current/stack.
 * Forked failure observers inherit that complete hosted CPU model; no native
 * IRQ, Timer service or irq_work delivery producer is supplied by these tests.
 */
#include <linux/errno.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/task.h>
#include <stela/test.h>

void stela_linux_atomic_callback_fixture(void);
void stela_linux_atomic_callback_taskless_fixture(void);
void stela_linux_atomic_callback_prepared_fixture(struct stela_linux_task *task,
	const struct stela_linux_task_context *context);

static struct rcu_head retirement;
static unsigned int retired;
static struct task_struct *expected_task;
static const struct stela_linux_owner *expected_owner;

static void counted_retirement(struct rcu_head *head)
{
	assert(head == &retirement && current == expected_task);
	assert(stela_linux_owner() == expected_owner);
	assert(!stela_linux_atomic_callback_active());
	assert(preempt_count() == (int)SOFTIRQ_OFFSET && !irqs_disabled());
	retired++;
}

static void forbidden_retirement(struct rcu_head *head)
{
	(void)head;
	/* SIGABRT is deliberately not the SIGILL contract-trap observer's pass.
	 * Thus a missing before-effect guard cannot pass by draining this first
	 * and only trapping later on callback/owner restoration.
	 */
	assert(false);
}

static void taskless_begin(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
}

void stela_linux_atomic_callback_taskless_fixture(void)
{
	assert(!stela_linux_atomic_callback_active());
	assert(stela_test_traps(taskless_begin));
	assert(!stela_linux_atomic_callback_active());
}

static void recursive_begin(void)
{
	struct stela_linux_atomic_callback first, second;
	stela_linux_atomic_callback_begin(&first);
	stela_linux_atomic_callback_begin(&second);
}

static void wrong_end(void)
{
	struct stela_linux_atomic_callback first, second;
	stela_linux_atomic_callback_begin(&first);
	stela_linux_atomic_callback_end(&second);
}

static void duplicate_end(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
	stela_linux_atomic_callback_end(&scope);
	stela_linux_atomic_callback_end(&scope);
}

static void nested_process_begin(void)
{
	struct stela_linux_atomic_callback scope;
	preempt_disable();
	stela_linux_atomic_callback_begin(&scope);
}

static void disabled_irq_begin(void)
{
	struct stela_linux_atomic_callback scope;
	local_irq_disable();
	stela_linux_atomic_callback_begin(&scope);
}

static void unbalanced_preempt_end(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
	preempt_disable();
	stela_linux_atomic_callback_end(&scope);
}

static void enabled_irq_end(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
	local_irq_enable();
	stela_linux_atomic_callback_end(&scope);
}

/* Deliberately undo the public numeric state while the independent private
 * callback guard remains live. This is not a legitimate callback operation.
 */
static void rebalance_counters(void)
{
	__irq_exit_raw();
	raw_local_irq_enable();
	assert(preempt_count() == 0 && !irqs_disabled());
	assert(stela_linux_atomic_callback_active() && !stela_linux_quiescent());
}

static void rebalanced_exit(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
	call_rcu(&retirement, forbidden_retirement);
	rebalance_counters();
	stela_linux_exit();
}

static void rebalanced_rcu(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
	call_rcu(&retirement, forbidden_retirement);
	rebalance_counters();
	rcu_barrier();
}

static void rebalanced_suspend(void)
{
	struct stela_linux_atomic_callback scope;
	struct stela_linux_lease lease;
	stela_linux_atomic_callback_begin(&scope);
	rebalance_counters();
	stela_linux_lease_snapshot(&lease);
	stela_linux_lease_suspend(&lease);
}

static void rebalanced_prepare(void)
{
	struct stela_linux_atomic_callback scope;
	struct stela_linux_lease lease;
	stela_linux_atomic_callback_begin(&scope);
	call_rcu(&retirement, forbidden_retirement);
	rebalance_counters();
	stela_linux_lease_snapshot(&lease);
	assert(stela_linux_task_park(false) == -EBUSY);
	assert(stela_linux_task_yield() == -EBUSY);
	assert(stela_linux_lease_matches(&lease));
	assert(current == expected_task && retired == 1);
	assert(stela_linux_atomic_callback_active());
	/* A returning error must precede RCU/page drainage and all lease mutation.
	 * End this child with a distinct status, without claiming callback cleanup.
	 */
	stela_test_witness_passed();
}

static void rebalanced_schedule(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
	call_rcu(&retirement, forbidden_retirement);
	rebalance_counters();
	schedule();
}

struct prepared_scope {
	struct stela_linux_task *task;
	const struct stela_linux_task_context *context;
};

/* Exercise the other ordering: a real task already passed PREPARE when its
 * retained park callback begins delivery. Public counter rebalance must not
 * let still_blocked/leave consume that older prepared snapshot. */
static int prepared_park(void *opaque)
{
	const struct prepared_scope *prepared = opaque;
	struct task_struct *task = current;
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_begin(&scope);
	__irq_exit_raw();
	raw_local_irq_enable();
	struct stela_linux_lease before;
	stela_linux_lease_snapshot(&before);
	for (unsigned int reason = 0; reason < 2; reason++) {
		unsigned int state = reason ? TASK_UNINTERRUPTIBLE : TASK_RUNNING;
		WRITE_ONCE(task->__state, state);
		assert(stela_linux_task_still_blocked(prepared->task, prepared->context) == -EBUSY);
		assert(stela_linux_task_leave(prepared->task, prepared->context, reason) == -EBUSY);
		assert(current == task && task->on_cpu == 1 && task->on_rq == 1);
		assert(READ_ONCE(task->__state) == state && !task->is_blocked);
		assert(!stela_linux_task_waiting_io() && !stela_linux_task_waiting_load());
		assert(stela_linux_lease_matches(&before) && !preempt_count());
	}
	WRITE_ONCE(task->__state, TASK_RUNNING);
	raw_local_irq_disable();
	__irq_enter_raw();
	stela_linux_atomic_callback_end(&scope);
	return 0;
}

static bool prepared_no_domain(void *opaque)
{
	(void)opaque;
	/* This mechanics fixture runs on the original constructor, without an
	 * optional domain. It claims no clock, inspection or delivery provider. */
	return false;
}

void stela_linux_atomic_callback_prepared_fixture(struct stela_linux_task *task,
	const struct stela_linux_task_context *context)
{
	const struct stela_linux_task_scope_ops ops = {.park = prepared_park, .yield = prepared_park,
		.reschedule = prepared_park, .reschedule_requested = prepared_no_domain};
	struct prepared_scope prepared = {.task = task, .context = context};
	assert(!stela_linux_task_scope_begin(task, &ops, &prepared));
	stela_linux_enter(&stela_linux_bare);
	assert(!stela_linux_task_park(false));
	assert(stela_linux_quiescent() && !stela_linux_atomic_callback_active());
	stela_linux_exit();
	assert(!stela_linux_task_scope_end(task));
}

static void passive_wrong_end(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_softirq_dispatch_begin(&scope);
	stela_linux_atomic_callback_end(&scope);
}

static void passive_unbalanced_end(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_softirq_dispatch_begin(&scope);
	preempt_disable();
	stela_linux_atomic_softirq_dispatch_end(&scope);
}

static void passive_hard_entry(void)
{
	struct stela_linux_atomic_callback hard, passive;
	stela_linux_atomic_callback_begin(&hard);
	stela_linux_atomic_softirq_dispatch_begin(&passive);
}

static void passive_rebalanced_prepare(void)
{
	struct stela_linux_atomic_callback scope;
	preempt_disable();
	preempt_disable();
	raw_local_irq_disable();
	stela_linux_atomic_softirq_dispatch_begin(&scope);
	preempt_count_sub(2);
	raw_local_irq_enable();
	call_rcu(&retirement, forbidden_retirement);
	assert(stela_linux_task_park(false) == -EBUSY);
	assert(stela_linux_task_yield() == -EBUSY);
	assert(stela_linux_atomic_callback_active());
	stela_test_witness_passed();
}

static void bh_wrong_end(void)
{
	struct stela_linux_atomic_callback scope;
	preempt_count_add(SOFTIRQ_DISABLE_OFFSET);
	stela_linux_atomic_callback_bh_begin(&scope);
	stela_linux_atomic_callback_end(&scope);
}

static void bh_missing_disable(void)
{
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_bh_begin(&scope);
}

static void bh_rebalanced_prepare(void)
{
	struct stela_linux_atomic_callback scope;
	preempt_count_add(SOFTIRQ_DISABLE_OFFSET);
	stela_linux_atomic_callback_bh_begin(&scope);
	preempt_count_sub(SOFTIRQ_DISABLE_OFFSET);
	call_rcu(&retirement, forbidden_retirement);
	assert(stela_linux_task_park(false) == -EBUSY);
	assert(stela_linux_task_yield() == -EBUSY);
	assert(stela_linux_atomic_callback_active());
	stela_test_witness_passed();
}

static void bh_callback_fixture(void)
{
	struct stela_linux_atomic_callback scope;
	for (unsigned int depth = 0; depth < 4; depth++) {
		preempt_count_add(SOFTIRQ_DISABLE_OFFSET + depth);
		struct stela_linux_lease before;
		stela_linux_lease_snapshot(&before);
		stela_linux_atomic_callback_bh_begin(&scope);
		assert(preempt_count() == (int)(SOFTIRQ_DISABLE_OFFSET + depth));
		assert(stela_linux_lease_matches(&before));
		preempt_disable();
		preempt_enable_no_resched();
		assert(stela_linux_task_yield() == -EBUSY);
		stela_linux_atomic_callback_bh_end(&scope);
		assert(preempt_count() == (int)(SOFTIRQ_DISABLE_OFFSET + depth));
		assert(stela_linux_lease_matches(&before) && !stela_linux_atomic_callback_active());
		preempt_count_sub(SOFTIRQ_DISABLE_OFFSET + depth);
	}
	assert(stela_test_traps(bh_wrong_end));
	assert(stela_test_traps(bh_missing_disable));
	assert(stela_test_witnessed(bh_rebalanced_prepare));
}

static void soft_and_passive_fixture(void)
{
	struct stela_linux_atomic_callback scope;
	struct stela_linux_lease entry;
	stela_linux_lease_snapshot(&entry);
	stela_linux_atomic_callback_begin_soft(&scope);
	assert(preempt_count() == (int)SOFTIRQ_OFFSET && !irqs_disabled());
	assert(stela_linux_atomic_callback_active() && !stela_linux_quiescent());
	assert(stela_linux_task_park(false) == -EBUSY);
	stela_linux_atomic_callback_end(&scope);
	assert(stela_linux_lease_matches(&entry) && !preempt_count());
	for (unsigned int depth = 0; depth < 4; depth++) {
		for (unsigned int disabled = 0; disabled < 2; disabled++) {
			preempt_count_add(depth);
			if (disabled)
				raw_local_irq_disable();
			struct stela_linux_lease before;
			stela_linux_lease_snapshot(&before);
			stela_linux_atomic_softirq_dispatch_begin(&scope);
			assert(preempt_count() == (int)depth);
			assert(stela_linux_lease_matches(&before));
			/* Model only bookkeeping here; whole original dispatch is tested
			 * by its producer's separate complete-source fixtures. */
			preempt_count_add(SOFTIRQ_OFFSET);
			raw_local_irq_enable();
			assert(stela_linux_task_yield() == -EBUSY);
			preempt_count_sub(SOFTIRQ_OFFSET);
			if (disabled)
				raw_local_irq_disable();
			stela_linux_atomic_softirq_dispatch_end(&scope);
			assert(preempt_count() == (int)depth && stela_linux_lease_matches(&before));
			assert(current == expected_task && !stela_linux_atomic_callback_active());
			raw_local_irq_enable();
			preempt_count_sub(depth);
		}
	}
	assert(stela_test_traps(passive_wrong_end));
	assert(stela_test_traps(passive_unbalanced_end));
	assert(stela_test_traps(passive_hard_entry));
	assert(stela_test_witnessed(passive_rebalanced_prepare));
	assert(stela_linux_lease_matches(&entry) && stela_linux_quiescent());
}

void stela_linux_atomic_callback_fixture(void)
{
	struct stela_linux_atomic_callback scope;
	struct stela_linux_lease lease;
	DEFINE_RAW_SPINLOCK(lock);
	retired = 0;
	expected_task = current;
	expected_owner = stela_linux_owner();
	assert(!stela_linux_atomic_callback_active() && stela_linux_quiescent());
	stela_linux_lease_snapshot(&lease);
	stela_linux_atomic_callback_begin(&scope);
	assert(stela_linux_atomic_callback_active() && !stela_linux_quiescent());
	assert(current == expected_task && stela_linux_owner() == expected_owner);
	assert(preempt_count() == (int)HARDIRQ_OFFSET && irqs_disabled());
	raw_spin_lock(&lock);
	assert(preempt_count() == (int)(HARDIRQ_OFFSET + 1));
	raw_spin_unlock(&lock);
	rcu_read_lock();
	assert(preempt_count() == (int)(HARDIRQ_OFFSET + 1));
	rcu_read_unlock();
	assert(stela_linux_task_yield() == -EBUSY);
	assert(stela_linux_task_park(false) == -EBUSY);
	call_rcu(&retirement, counted_retirement);
	assert(!retired);
	stela_linux_atomic_callback_end(&scope);
	assert(!stela_linux_atomic_callback_active() && stela_linux_quiescent());
	assert(stela_linux_lease_matches(&lease) && current == expected_task);
	stela_linux_rcu_finish();
	assert(retired == 1);
	assert(stela_test_traps(recursive_begin));
	assert(stela_test_traps(wrong_end));
	assert(stela_test_traps(duplicate_end));
	assert(stela_test_traps(nested_process_begin));
	assert(stela_test_traps(disabled_irq_begin));
	assert(stela_test_traps(unbalanced_preempt_end));
	assert(stela_test_traps(enabled_irq_end));
	assert(stela_test_traps(rebalanced_exit));
	assert(stela_test_traps(rebalanced_rcu));
	assert(stela_test_traps(rebalanced_suspend));
	assert(stela_test_traps(rebalanced_schedule));
	assert(stela_test_witnessed(rebalanced_prepare));
	assert(!stela_linux_atomic_callback_active() && stela_linux_quiescent());
	assert(stela_linux_lease_matches(&lease) && current == expected_task);
	soft_and_passive_fixture();
	bh_callback_fixture();
	printf("Linux atomic callback: retained current, exact restoration and before-effect guards passed\n");
}
