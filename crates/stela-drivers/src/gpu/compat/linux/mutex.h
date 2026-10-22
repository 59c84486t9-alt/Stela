/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_MUTEX_H
#define STELA_LINUX_MUTEX_H
/* Lock types named by driver structures. A source that takes one declares
 * the operation it uses as an adapter service.
 */
typedef struct {
	int stela_owner;
} spinlock_t;
struct mutex {
	int stela_owner;
};
#define __MUTEX_INITIALIZER(lockname) { .stela_owner = 0 }
static void mutex_lock(struct mutex *lock);
static void mutex_unlock(struct mutex *lock);
#endif
