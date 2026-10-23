/* SPDX-License-Identifier: MIT */
/* Linux mutexes inside Stela's serialized, non-preemptible execution domain.
 * An owner cannot sleep or reenter Linux while holding one. Contention in
 * this domain is recursive acquisition, so it is an invariant failure rather
 * than a pretend successful lock. These are real atomic lock transitions. */
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <stela/linux.h>

static long mutex_owner(void)
{
    unsigned long token = (unsigned long)stela_linux_owner();
    /* Linux reserves the low three bits for owner flags. */
    if (token & 7) __builtin_trap();
    return (long)token;
}

void mutex_init_generic(struct mutex *lock)
{
    atomic_long_set(&lock->owner, 0);
    raw_spin_lock_init(&lock->wait_lock);
    lock->first_waiter = NULL;
}

void mutex_lock(struct mutex *lock)
{
    if (atomic_long_cmpxchg_acquire(&lock->owner, 0, mutex_owner()) != 0)
        __builtin_trap();
}

void mutex_unlock(struct mutex *lock)
{
    long token = mutex_owner();
    if (atomic_long_cmpxchg_release(&lock->owner, token, 0) != token)
        __builtin_trap();
}

bool mutex_is_locked(struct mutex *lock)
{
    return atomic_long_read(&lock->owner) != 0;
}
