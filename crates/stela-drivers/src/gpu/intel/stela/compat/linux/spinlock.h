/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_SPINLOCK_H
#define STELA_LINUX_SPINLOCK_H
#include <linux/mutex.h>
/* Each Stela GPU owner is exclusive and runs without interrupts, so a lock
 * is never contended; contention is an ownership bug and stops. */
static inline void spin_lock_init(spinlock_t *lock)
{
	lock->stela_owner = 0;
}
static inline void stela_spin_lock(spinlock_t *lock)
{
	if (__atomic_exchange_n(&lock->stela_owner, 1, __ATOMIC_ACQUIRE))
		__builtin_trap();
}
static inline void spin_unlock(spinlock_t *lock)
{
	__atomic_store_n(&lock->stela_owner, 0, __ATOMIC_RELEASE);
}
#define spin_lock(lock) stela_spin_lock(lock)
#define spin_lock_irqsave(lock, flags) ((flags) = 0, stela_spin_lock(lock))
#define spin_unlock_irqrestore(lock, flags) ((void)(flags), spin_unlock(lock))
#endif
