// SPDX-License-Identifier: MIT
/* Original RT mutexes and FIFO/PI ranks on distinct real Runtime stacks.
 * No waiter, owner, priority or task state is fabricated by this fixture. */
#include <linux/errno.h>
#include <linux/rtmutex.h>
#include <linux/sched.h>
#include <stela/linux.h>
#include <stela/task.h>
#include <stela/test.h>

struct rt_call {
	u32 scenario, role;
	void *context;
	void (*checkpoint)(void *context, u32 event);
};
void stela_linux_rt_mutex_test_run(void *opaque);

static struct rt_mutex first, second;
static unsigned int high_entered, high_done, middle_done, medium_done;
static struct task_struct *owner, *middle, *high_task;

static void wait_for(const unsigned int *value, unsigned int expected)
{
	unsigned int yields = 0;
	while (READ_ONCE(*value) != expected) {
		assert(yields++ < 64);
		assert(!stela_linux_task_yield());
	}
}

static void foreground(const struct rt_call *call)
{
	rt_mutex_init(&first);
	rt_mutex_init(&second);
	high_entered = high_done = middle_done = medium_done = 0;
	owner = current;
	middle = NULL;
	high_task = NULL;
	assert(current->policy == SCHED_NORMAL && current->prio == DEFAULT_PRIO);
	assert(rt_mutex_trylock(&first));
	assert(!rt_mutex_trylock(&first));
	call->checkpoint(call->context, 1);
	wait_for(&high_entered, 1);
	if (call->scenario == 14) {
		assert(high_task && current->prio == DEFAULT_PRIO);
		assert(high_task->pi_blocked_on && high_task->prio == DEFAULT_PRIO);
		sched_set_fifo(high_task);
	}
	assert(current->prio == 49 && current->normal_prio == DEFAULT_PRIO);
	assert(current->pi_top_task && !current->pi_blocked_on);
	assert(!medium_done && !high_done);
	if (call->scenario == 12) {
		assert(middle && middle->prio == 49 && middle->normal_prio == DEFAULT_PRIO);
		assert(current->pi_top_task == middle && middle->pi_top_task);
	}
	if (call->scenario == 13) {
		call->checkpoint(call->context, 2); /* retained expected-job SIGUSR1 */
		wait_for(&high_done, 1);
		assert(current->prio == DEFAULT_PRIO && !current->pi_top_task);
	}
	rt_mutex_unlock(&first);
	assert(current->prio == DEFAULT_PRIO && !current->pi_top_task);
	wait_for(&high_done, 1);
	if (call->scenario == 12)
		wait_for(&middle_done, 1);
	if (call->scenario == 11 || call->scenario == 12)
		wait_for(&medium_done, 1);
	assert(rt_mutex_trylock(&first));
	rt_mutex_unlock(&first);
}

static void high(const struct rt_call *call)
{
	if (call->scenario == 14) {
		assert(current->policy == SCHED_NORMAL && current->prio == DEFAULT_PRIO);
	} else {
		sched_set_fifo(current);
		assert(current->policy == SCHED_FIFO && current->rt_priority == 50);
		assert(current->prio == 49 && current->normal_prio == 49);
	}
	high_task = current;
	high_entered = 1;
	struct rt_mutex *lock = call->scenario == 12 ? &second : &first;
	if (call->scenario == 13) {
		assert(rt_mutex_lock_interruptible(lock) == -EINTR);
		assert(!stela_linux_task_ack_signal(1));
	} else {
		rt_mutex_lock(lock);
		assert(!medium_done);
		rt_mutex_unlock(lock);
	}
	assert(!current->pi_blocked_on && !current->pi_top_task && current->prio == 49);
	high_done = 1;
}

void stela_linux_rt_mutex_test_run(void *opaque)
{
	const struct rt_call *call = opaque;
	const struct stela_linux_services services = {};
	const struct stela_linux_owner service_owner = {.services = &services};
	stela_linux_enter(&service_owner);
	assert(call->scenario >= 11 && call->scenario <= 14 && call->role < 4);
	if (!call->role) {
		foreground(call);
	} else if (call->scenario == 12 && call->role == 1) {
		middle = current;
		rt_mutex_lock(&second);
		call->checkpoint(call->context, 9);
		rt_mutex_lock(&first);
		assert(current->prio == 49 && current->pi_top_task);
		rt_mutex_unlock(&first);
		rt_mutex_unlock(&second);
		assert(current->prio == DEFAULT_PRIO && !current->pi_top_task);
		middle_done = 1;
	} else if (call->role == (call->scenario == 12 ? 2U : 1U)) {
		high(call);
	} else {
		assert(high_done);
		medium_done = 1;
	}
	assert(!current->pi_blocked_on && !current->pi_top_task && !preempt_count());
	assert(!stela_linux_task_pending_signals());
	stela_linux_exit();
}
