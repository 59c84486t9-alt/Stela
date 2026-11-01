// SPDX-License-Identifier: MIT
/* Linux's reader-writer semaphores, with the interface of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/locking/rwsem.c. Linux code
 * runs in one context at a time, so count needs no atomicity of its own: it
 * holds the writer bit or the reader count, and waiters sleep on it. */
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/wait_bit.h>

#define READER (RWSEM_WRITER_LOCKED << 1)

void __init_rwsem(struct rw_semaphore *sem, const char *name, struct lock_class_key *key)
{
	(void)name;
	(void)key;
	atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
	atomic_long_set(&sem->owner, 0);
	raw_spin_lock_init(&sem->wait_lock);
	sem->first_waiter = NULL;
}

int down_read_trylock(struct rw_semaphore *sem)
{
	unsigned long count = (unsigned long)atomic_long_read(&sem->count);

	if (count & RWSEM_WRITER_LOCKED)
		return 0;
	atomic_long_set(&sem->count, (long)(count + READER));
	return 1;
}

int down_write_trylock(struct rw_semaphore *sem)
{
	if (atomic_long_read(&sem->count) != RWSEM_UNLOCKED_VALUE)
		return 0;
	atomic_long_set(&sem->count, RWSEM_WRITER_LOCKED);
	return 1;
}

void down_read(struct rw_semaphore *sem)
{
	wait_var_event(&sem->count, down_read_trylock(sem));
}

void down_write(struct rw_semaphore *sem)
{
	wait_var_event(&sem->count, down_write_trylock(sem));
}

void up_read(struct rw_semaphore *sem)
{
	unsigned long count = (unsigned long)atomic_long_read(&sem->count);

	WARN_ON(count < READER);
	atomic_long_set(&sem->count, (long)(count - READER));
	if (count == READER)
		wake_up_var(&sem->count);
}

void up_write(struct rw_semaphore *sem)
{
	WARN_ON(atomic_long_read(&sem->count) != RWSEM_WRITER_LOCKED);
	atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
	wake_up_var(&sem->count);
}

void downgrade_write(struct rw_semaphore *sem)
{
	WARN_ON(atomic_long_read(&sem->count) != RWSEM_WRITER_LOCKED);
	atomic_long_set(&sem->count, READER);
	wake_up_var(&sem->count);
}
