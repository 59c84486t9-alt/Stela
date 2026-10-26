// SPDX-License-Identifier: MIT
/* RCU for the single serialized, nonpreemptible Linux execution context.
 * No native IRQ or external reader can enter it. A checked quiescent point
 * therefore ends every preexisting reader, including sched/BH/IRQ-disabled
 * sections. Never infer that point merely from a call_rcu invocation. */
#include <linux/limits.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <stela/linux.h>
#include <stela/allocation.h>

/* Cookies are opaque. Odd 1 denotes already completed; real epochs are even.
 * Exhaustion stops rather than making an old cookie appear current again. */
#define COMPLETED_COOKIE 1UL
#define EPOCH_STEP 2UL

static struct rcu_head *pending;
static struct rcu_head **tail = &pending;
static unsigned long epoch;
static bool requested;
static bool invoking;
static const struct rcu_head *invoking_head;

bool stela_linux_rcu_callback_current(const struct rcu_head *head)
{
 (void)stela_linux_owner();
 return invoking && head && invoking_head == head;
}

/* Independent lifecycle state, never inferred from public nesting counters.
 * The entered single-CPU owner serializes access, including callback delivery.
 * This is an observation only; it supplies no task/owner/root authority. */
bool stela_linux_rcu_callback_active(void)
{
	(void)stela_linux_owner();
	return invoking;
}

static void require_quiescence(void)
{
	if (!stela_linux_quiescent() || invoking)
		__builtin_trap();
}

static void complete_grace_period(void)
{
	require_quiescence();
	if (epoch > ULONG_MAX - EPOCH_STEP)
		__builtin_trap();
	/* Both sides of the grace-period API order memory, even in this
	 * serialized environment. The execution lock orders other owners. */
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	epoch += EPOCH_STEP;
	requested = false;
}

void call_rcu(struct rcu_head *head, rcu_callback_t function)
{
	(void)stela_linux_owner();
	if (!head || !function)
		__builtin_trap();
	/* The caller owns head until its callback, and must not queue it twice.
	 * Neither head nor its containing object is inspected after invocation. */
	head->func = function;
	head->next = NULL;
	*tail = head;
	tail = &head->next;
	requested = true;
}

void synchronize_rcu(void)
{
	complete_grace_period();
}

void rcu_barrier(void)
{
	require_quiescence();
	/* Detach exactly the callbacks preceding this barrier. Callbacks may
	 * enqueue another generation; those get a separate grace period. */
	struct rcu_head *list = pending;
	pending = NULL;
	tail = &pending;
	complete_grace_period();
	const struct stela_linux_owner *owner = stela_linux_owner();
	invoking = true;
	while (list) {
		struct rcu_head *next = list->next;
		rcu_callback_t function = list->func;
		list->func = NULL;
		list->next = NULL;
		/* Match the callback's nonblocking softirq execution contract,
		 * without pretending a physical softirq/IRQ was delivered. */
		invoking_head = list;
		preempt_count_add(SOFTIRQ_OFFSET);
		function(list);
		if (stela_linux_owner() != owner || preempt_count() != (int)SOFTIRQ_OFFSET ||
		    irqs_disabled())
			__builtin_trap();
		preempt_count_sub(SOFTIRQ_OFFSET);
		invoking_head = NULL;
		list = next;
	}
	invoking = false;
}

void stela_linux_rcu_finish(void)
{
	require_quiescence();
	while (pending || requested)
		rcu_barrier();
}

unsigned long get_completed_synchronize_rcu(void)
{
	(void)stela_linux_owner();
	return COMPLETED_COOKIE;
}

void get_completed_synchronize_rcu_full(struct rcu_gp_oldstate *state)
{
	state->rgos_norm = get_completed_synchronize_rcu();
}

unsigned long get_state_synchronize_rcu(void)
{
	(void)stela_linux_owner();
	return epoch;
}

unsigned long start_poll_synchronize_rcu(void)
{
	unsigned long cookie = get_state_synchronize_rcu();
	requested = true;
	return cookie;
}

bool poll_state_synchronize_rcu(unsigned long cookie)
{
	(void)stela_linux_owner();
	if (requested && stela_linux_quiescent() && !invoking)
		complete_grace_period();
	return cookie == COMPLETED_COOKIE || cookie != epoch;
}

#ifdef STELA_LINUX_RCU_TEST
#include <linux/delay.h>
#include <linux/slab.h>
#include <stela/test.h>

struct callback {
	struct rcu_head head;
	unsigned int id;
	struct callback *successor;
	bool allocated;
};

static unsigned int observed[16];
static unsigned int count;
static unsigned int atomic_delays;
static unsigned int sleeps;
static const struct stela_linux_owner *expected_owner;

static void delay_service(void *context, u64 minimum, u64 maximum, bool atomic)
{
	(void)context;
	assert(minimum <= maximum && minimum <= 100000);
	if (atomic) {
		assert(in_serving_softirq());
		atomic_delays++;
		s64 deadline = stela_test_now_ns() + (s64)(minimum * 1000);
		while (stela_test_now_ns() < deadline)
			cpu_relax();
	} else {
		assert(stela_linux_quiescent());
		sleeps++;
		stela_test_sleep_us(minimum);
	}
}

static void record(struct rcu_head *head)
{
	struct callback *callback = container_of(head, struct callback, head);
	assert(stela_linux_owner() == expected_owner);
	assert(in_serving_softirq() && !in_hardirq() && !irqs_disabled());
	assert(preempt_count() == (int)SOFTIRQ_OFFSET);
	assert(!stela_linux_quiescent());
	udelay(1);
	assert(count < ARRAY_SIZE(observed));
	observed[count++] = callback->id;
	if (callback->successor)
		call_rcu(&callback->successor->head, record);
	if (callback->allocated)
		kfree(callback);
}

static void readers_and_barriers(void)
{
	struct callback first = {.id = 1}, second = {.id = 2}, later = {.id = 3};
	first.successor = &later;
	rcu_read_lock();
	rcu_read_lock_sched();
	rcu_read_lock_bh();
	unsigned long cookie = start_poll_synchronize_rcu();
	call_rcu(&first.head, record);
	call_rcu(&second.head, record);
	assert(count == 0 && !stela_linux_quiescent());
	assert(!poll_state_synchronize_rcu(cookie));
	rcu_read_unlock_bh();
	rcu_read_unlock_sched();
	assert(!poll_state_synchronize_rcu(cookie));
	rcu_read_unlock();
	assert(stela_linux_quiescent() && count == 0);
	synchronize_rcu();
	assert(poll_state_synchronize_rcu(cookie) && count == 0);
	rcu_barrier();
	assert(count == 2 && observed[0] == 1 && observed[1] == 2);
	assert(stela_linux_quiescent());
	rcu_barrier();
	assert(count == 3 && observed[2] == 3);
}

static void irq_disabled_readers_and_polling(void)
{
	unsigned long flags;
	local_irq_save(flags);
	unsigned long cookie = start_poll_synchronize_rcu();
	assert(!stela_linux_quiescent() && !poll_state_synchronize_rcu(cookie));
	local_irq_restore(flags);
	assert(poll_state_synchronize_rcu(cookie));
	struct rcu_gp_oldstate state;
	get_completed_synchronize_rcu_full(&state);
	assert(poll_state_synchronize_rcu_full(&state));
	preempt_disable();
	cookie = start_poll_synchronize_rcu();
	assert(!poll_state_synchronize_rcu(cookie));
	preempt_enable();
	assert(poll_state_synchronize_rcu(cookie));
}

static void barrier_in_reader(void)
{
	stela_linux_enter(&stela_linux_bare);
	rcu_read_lock();
	rcu_barrier();
}

static void synchronize_with_irqs_disabled(void)
{
	stela_linux_enter(&stela_linux_bare);
	local_irq_disable();
	synchronize_rcu();
}

static void exit_with_reader(void)
{
	stela_linux_enter(&stela_linux_bare);
	rcu_read_lock();
	stela_linux_exit();
}

static void exit_with_irqs_disabled(void)
{
	stela_linux_enter(&stela_linux_bare);
	local_irq_disable();
	stela_linux_exit();
}

static void unbalanced_callback(struct rcu_head *head)
{
	(void)head;
	preempt_disable();
}

static void callback_leaves_read_state(void)
{
	struct rcu_head head;
	stela_linux_enter(&stela_linux_bare);
	call_rcu(&head, unbalanced_callback);
	stela_linux_exit();
}

static void sleeping_callback(struct rcu_head *head)
{
	(void)head;
	msleep(1);
}

static void callback_attempts_sleep(void)
{
	const struct stela_linux_services services = {.delay_us = delay_service};
	const struct stela_linux_owner owner = {.services = &services};
	struct rcu_head head;
	stela_linux_enter(&owner);
	call_rcu(&head, sleeping_callback);
	stela_linux_exit();
}

static unsigned int balanced_calls;

static void balanced_callback(struct rcu_head *head)
{
	assert(stela_linux_rcu_callback_current(head));
	assert(stela_linux_rcu_callback_active());
	assert(preempt_count() == (int)SOFTIRQ_OFFSET && !irqs_disabled());
	const struct stela_linux_owner *before = stela_linux_owner();
	preempt_count_sub(SOFTIRQ_OFFSET);
	/* Same owner and genuinely balanced public counters are insufficient to
	 * manufacture a process/quiescent allocation, sleep or root-entry grant. */
	assert(!preempt_count() && !irqs_disabled());
	assert(stela_linux_owner() == before && !stela_linux_quiescent());
	assert(stela_linux_rcu_callback_active());
	balanced_calls++;
	preempt_count_add(SOFTIRQ_OFFSET);
}

static void entered_forbidden_delay(void *context, u64 minimum, u64 maximum, bool atomic)
{
	(void)context; (void)minimum; (void)maximum; (void)atomic;
	/* Distinct witness status is NOT the expected SIGILL. A missing early
	 * refusal cannot pass by entering this provider then trapping in cleanup. */
	stela_test_witness_passed();
}

static void balanced_sleep_callback(struct rcu_head *head)
{
	(void)head;
	preempt_count_sub(SOFTIRQ_OFFSET);
	msleep(1);
}

static void balanced_callback_attempts_sleep(void)
{
	const struct stela_linux_services services = {.delay_us = entered_forbidden_delay};
	const struct stela_linux_owner owner = {.services = &services};
	struct rcu_head head;
	stela_linux_enter(&owner);
	call_rcu(&head, balanced_sleep_callback);
	rcu_barrier();
	stela_linux_exit();
}

int main(void)
{
	const struct stela_linux_services services = {.delay_us = delay_service};
	const struct stela_linux_owner owner = {.services = &services};
	expected_owner = &owner;
	stela_linux_enter(&owner);
	msleep(1);
	assert(sleeps == 1);
	readers_and_barriers();
	irq_disabled_readers_and_polling();
	struct callback last = {.id = 4}, chained = {.id = 5};
	last.successor = &chained;
	call_rcu(&last.head, record);
	struct callback *allocated = kmalloc(sizeof(*allocated), GFP_KERNEL);
	assert(allocated);
	*allocated = (struct callback){.id = 6, .allocated = true};
	call_rcu(&allocated->head, record);
	assert(count == 3);
	unsigned long cookie = start_poll_synchronize_rcu();
	stela_linux_exit();
	assert(count == 6 && observed[3] == 4 && observed[4] == 6 && observed[5] == 5);
	assert(atomic_delays == count && sleeps == 1);
	stela_linux_enter(&owner);
	assert(poll_state_synchronize_rcu(cookie));
	rcu_barrier();
	assert(count == 6 && stela_linux_quiescent());
	stela_linux_exit();
	assert(stela_test_traps(barrier_in_reader));
	assert(stela_test_traps(synchronize_with_irqs_disabled));
	assert(stela_test_traps(exit_with_reader));
	assert(stela_test_traps(exit_with_irqs_disabled));
	assert(stela_test_traps(callback_leaves_read_state));
	assert(stela_test_traps(callback_attempts_sleep));
	assert(stela_test_traps(balanced_callback_attempts_sleep));
	stela_linux_enter(&owner);
	assert(!stela_linux_rcu_callback_active() && stela_linux_quiescent());
	struct rcu_head balanced;
	call_rcu(&balanced, balanced_callback);
	rcu_barrier();
	assert(balanced_calls == 1 && !stela_linux_rcu_callback_active());
	assert(stela_linux_quiescent() && !preempt_count());
	stela_linux_exit();
	printf("Serialized Linux RCU: nested readers, deferred FIFO callbacks, barriers, owner retirement and invalid contexts\n");
	return 0;
}
#endif
