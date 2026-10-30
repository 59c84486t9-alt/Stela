// SPDX-License-Identifier: MIT
/* Linux's rt_mutex, for the buses that lock with one. Linux code runs in one
 * context at a time and tasks have no priorities here, so there is nothing to
 * inherit: this is a sleeping lock on the owner word, with the interface of
 * Linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/locking/rtmutex_api.c. */
#include <linux/rtmutex.h>
#include <linux/sched.h>
#include <linux/wait_bit.h>

void __rt_mutex_init(struct rt_mutex *lock, const char *name, struct lock_class_key *key)
{
	(void)name;
	(void)key;
	lock->rtmutex.owner = NULL;
}

int rt_mutex_trylock(struct rt_mutex *lock)
{
	if (lock->rtmutex.owner)
		return 0;
	lock->rtmutex.owner = current;
	return 1;
}

void rt_mutex_lock(struct rt_mutex *lock)
{
	wait_var_event(&lock->rtmutex.owner, rt_mutex_trylock(lock));
}

void rt_mutex_unlock(struct rt_mutex *lock)
{
	WARN_ON(lock->rtmutex.owner != current);
	lock->rtmutex.owner = NULL;
	wake_up_var(&lock->rtmutex.owner);
}
