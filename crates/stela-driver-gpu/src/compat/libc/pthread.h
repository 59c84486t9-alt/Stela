/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_PTHREAD_H
#define STELA_LIBC_PTHREAD_H
#include <sched.h>
#include <sys/types.h>
#include <time.h>
typedef unsigned long pthread_t;
typedef struct {
	int kind;
} pthread_mutexattr_t;
typedef struct {
	int unused;
} pthread_condattr_t;
typedef struct {
	int unused;
} pthread_attr_t;
typedef struct {
	volatile int locked;
	int kind;
	unsigned long owner;
	int depth;
} pthread_mutex_t;
typedef struct {
	volatile unsigned int generation;
} pthread_cond_t;
typedef struct {
	volatile int state;
} pthread_once_t;
typedef unsigned int pthread_key_t;
typedef struct {
	/* Readers, or -1 for a writer. */
	volatile int state;
} pthread_rwlock_t;
typedef struct {
	int unused;
} pthread_rwlockattr_t;
typedef struct {
	volatile unsigned int arrived, generation;
	unsigned int count;
} pthread_barrier_t;
typedef struct {
	int unused;
} pthread_barrierattr_t;
#define PTHREAD_MUTEX_INITIALIZER {0, 0, 0, 0}
#define PTHREAD_COND_INITIALIZER {0}
#define PTHREAD_ONCE_INIT {0}
#define PTHREAD_RWLOCK_INITIALIZER {0}
#define PTHREAD_BARRIER_SERIAL_THREAD -1
#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1
int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int kind);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_condattr_init(pthread_condattr_t *attr);
int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock);
int pthread_condattr_destroy(pthread_condattr_t *attr);
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
			   const struct timespec *deadline);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_once(pthread_once_t *once, void (*function)(void));
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *deadline);
int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr);
int pthread_rwlock_destroy(pthread_rwlock_t *lock);
int pthread_rwlock_rdlock(pthread_rwlock_t *lock);
int pthread_rwlock_wrlock(pthread_rwlock_t *lock);
int pthread_rwlock_unlock(pthread_rwlock_t *lock);
int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr,
			 unsigned int count);
int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_wait(pthread_barrier_t *barrier);
int pthread_getcpuclockid(pthread_t thread, clockid_t *clock);
#define PTHREAD_CANCEL_ASYNCHRONOUS 1
int pthread_setcanceltype(int type, int *old);
int pthread_cancel(pthread_t thread);
pthread_t pthread_self(void);
int pthread_equal(pthread_t a, pthread_t b);
int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);
int pthread_attr_setdetachstate(pthread_attr_t *attr, int state);
/* Refused: PEs run Mesa, and nothing here can schedule another thread. */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*body)(void *),
		   void *argument);
int pthread_join(pthread_t thread, void **result);
int pthread_detach(pthread_t thread);
_Noreturn void pthread_exit(void *result);
int pthread_setname_np(pthread_t thread, const char *name);
#endif
