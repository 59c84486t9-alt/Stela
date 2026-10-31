// SPDX-License-Identifier: MIT
/* A caller of Mesa is a host processor, one for each PE in the GPU's gate, and a
 * thread Mesa starts is a task of the Linux environment on the boot CPU. Each
 * waits its own way in stela_libc_wait: a processor spins, and a task sleeps. */
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stela/host.h>

/* Wait while the 32-bit word at `word` holds `value`. */
static void wait_while(const volatile void *word, int value, uint64_t deadline)
{
	stela_libc_wait((const volatile unsigned int *)word, (unsigned int)value, deadline);
}

static void wake(const volatile void *word)
{
	stela_libc_wake((const volatile unsigned int *)word);
}

pthread_t pthread_self(void)
{
	return stela_libc_core() + 1;
}

int pthread_getcpuclockid(pthread_t thread, clockid_t *clock)
{
	(void)thread;
	if (!clock)
		return EINVAL;
	/* No per-thread CPU clock is supplied. Keep a deterministic unsupported
	 * ID for callers that neglect this error; clock_gettime rejects it too. */
	*clock = CLOCK_THREAD_CPUTIME_ID;
	return ENOTSUP;
}

int pthread_equal(pthread_t a, pthread_t b)
{
	return a == b;
}

int pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
	attr->kind = PTHREAD_MUTEX_NORMAL;
	return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int kind)
{
	if (kind != PTHREAD_MUTEX_NORMAL && kind != PTHREAD_MUTEX_RECURSIVE)
		return EINVAL;
	attr->kind = kind;
	return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
	(void)attr;
	return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
	*mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	if (attr) {
		if (attr->kind != PTHREAD_MUTEX_NORMAL && attr->kind != PTHREAD_MUTEX_RECURSIVE)
			return EINVAL;
		mutex->kind = attr->kind;
	}
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	(void)mutex;
	return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	pthread_t self = pthread_self();
	if (mutex->kind == PTHREAD_MUTEX_RECURSIVE && __atomic_load_n(&mutex->owner, __ATOMIC_RELAXED) == self) {
		mutex->depth++;
		return 0;
	}
	if (__atomic_exchange_n(&mutex->locked, 1, __ATOMIC_ACQUIRE))
		return EBUSY;
	__atomic_store_n(&mutex->owner, self, __ATOMIC_RELAXED);
	mutex->depth = 1;
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	while (pthread_mutex_trylock(mutex))
		wait_while(&mutex->locked, 1, UINT64_MAX);
	return 0;
}

/* Convert only representable nonnegative absolute monotonic deadlines. The
 * host reserves UINT64_MAX for an untimed wait, not a finite timestamp. */
static int deadline_ns(const struct timespec *deadline, uint64_t *until)
{
	if (!deadline || deadline->tv_sec < 0 || deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000)
		return EINVAL;
	uint64_t seconds = (uint64_t)deadline->tv_sec;
	uint64_t nanos = (uint64_t)deadline->tv_nsec;
	if (seconds > (UINT64_MAX - 1 - nanos) / 1000000000)
		return EOVERFLOW;
	*until = seconds * 1000000000 + nanos;
	return 0;
}

int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *deadline)
{
	/* POSIX mutex timedlock uses CLOCK_REALTIME, which the host lacks.
	 * An immediately available lock still needs no timeout or clock. */
	int result = pthread_mutex_trylock(mutex);
	if (!result)
		return 0;
	uint64_t until;
	result = deadline_ns(deadline, &until);
	return result ? result : ENOTSUP;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if (--mutex->depth)
		return 0;
	__atomic_store_n(&mutex->owner, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&mutex->locked, 0, __ATOMIC_RELEASE);
	wake(&mutex->locked);
	return 0;
}

int pthread_condattr_init(pthread_condattr_t *attr)
{
	attr->clock = CLOCK_REALTIME;
	return 0;
}

int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock)
{
	if (clock != CLOCK_MONOTONIC)
		return clock == CLOCK_REALTIME || clock == CLOCK_PROCESS_CPUTIME_ID || clock == CLOCK_THREAD_CPUTIME_ID ? ENOTSUP : EINVAL;
	attr->clock = clock;
	return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *attr)
{
	(void)attr;
	return 0;
}

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
	clockid_t clock = attr ? attr->clock : CLOCK_REALTIME;
	if (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC)
		return EINVAL;
	cond->generation = 0;
	cond->clock = clock;
	return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
	(void)cond;
	return 0;
}

static int cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex,
		     const struct timespec *deadline)
{
	unsigned int generation = __atomic_load_n(&cond->generation, __ATOMIC_ACQUIRE);
	uint64_t until = UINT64_MAX;
	if (deadline) {
		int error = deadline_ns(deadline, &until);
		if (error)
			return error;
		if (cond->clock != CLOCK_MONOTONIC)
			return cond->clock == CLOCK_REALTIME ? ENOTSUP : EINVAL;
	}
	int result = 0;
	pthread_mutex_unlock(mutex);
	while (__atomic_load_n(&cond->generation, __ATOMIC_ACQUIRE) == generation) {
		if (stela_libc_now_ns() >= until) {
			result = ETIMEDOUT;
			break;
		}
		wait_while(&cond->generation, (int)generation, until);
	}
	pthread_mutex_lock(mutex);
	return result;
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
			   const struct timespec *deadline)
{
	return deadline ? cond_wait(cond, mutex, deadline) : EINVAL;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	return cond_wait(cond, mutex, NULL);
}

int pthread_cond_broadcast(pthread_cond_t *cond)
{
	__atomic_add_fetch(&cond->generation, 1, __ATOMIC_RELEASE);
	wake(&cond->generation);
	return 0;
}

int pthread_cond_signal(pthread_cond_t *cond)
{
	return pthread_cond_broadcast(cond);
}

int pthread_once(pthread_once_t *once, void (*function)(void))
{
	enum { NOT_RUN, RUNNING, DONE };
	int expected = NOT_RUN;
	if (__atomic_compare_exchange_n(&once->state, &expected, RUNNING, 0, __ATOMIC_ACQUIRE,
					__ATOMIC_ACQUIRE)) {
		function();
		__atomic_store_n(&once->state, DONE, __ATOMIC_RELEASE);
		wake(&once->state);
		return 0;
	}
	while (__atomic_load_n(&once->state, __ATOMIC_ACQUIRE) != DONE)
		wait_while(&once->state, RUNNING, UINT64_MAX);
	return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr)
{
	(void)attr;
	lock->state = 0;
	return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *lock)
{
	(void)lock;
	return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *lock)
{
	for (;;) {
		int state = __atomic_load_n(&lock->state, __ATOMIC_RELAXED);
		if (state >= 0 && __atomic_compare_exchange_n(&lock->state, &state, state + 1, 0,
							      __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			return 0;
		if (state < 0)
			wait_while(&lock->state, state, UINT64_MAX);
	}
}

int pthread_rwlock_wrlock(pthread_rwlock_t *lock)
{
	for (;;) {
		int state = 0;
		if (__atomic_compare_exchange_n(&lock->state, &state, -1, 0, __ATOMIC_ACQUIRE,
						__ATOMIC_RELAXED))
			return 0;
		wait_while(&lock->state, state, UINT64_MAX);
	}
}

int pthread_rwlock_unlock(pthread_rwlock_t *lock)
{
	if (__atomic_load_n(&lock->state, __ATOMIC_RELAXED) < 0)
		__atomic_store_n(&lock->state, 0, __ATOMIC_RELEASE);
	else
		__atomic_sub_fetch(&lock->state, 1, __ATOMIC_RELEASE);
	wake(&lock->state);
	return 0;
}

int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr,
			 unsigned int count)
{
	(void)attr;
	barrier->arrived = barrier->generation = 0;
	barrier->count = count;
	return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
	(void)barrier;
	return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier)
{
	unsigned int generation = __atomic_load_n(&barrier->generation, __ATOMIC_ACQUIRE);
	if (__atomic_add_fetch(&barrier->arrived, 1, __ATOMIC_ACQ_REL) == barrier->count) {
		__atomic_store_n(&barrier->arrived, 0, __ATOMIC_RELAXED);
		__atomic_add_fetch(&barrier->generation, 1, __ATOMIC_RELEASE);
		wake(&barrier->generation);
		return PTHREAD_BARRIER_SERIAL_THREAD;
	}
	while (__atomic_load_n(&barrier->generation, __ATOMIC_ACQUIRE) == generation)
		wait_while(&barrier->generation, (int)generation, UINT64_MAX);
	return 0;
}

#define KEYS 64
static void *specific[STELA_LIBC_CORES][KEYS];
static struct {
	int used;
	void (*destructor)(void *);
} keys[KEYS];
static pthread_mutex_t key_lock = PTHREAD_MUTEX_INITIALIZER;

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *))
{
	pthread_mutex_lock(&key_lock);
	for (unsigned int index = 0; index < KEYS; index++) {
		if (keys[index].used)
			continue;
		keys[index].used = 1;
		keys[index].destructor = destructor;
		*key = index;
		pthread_mutex_unlock(&key_lock);
		return 0;
	}
	pthread_mutex_unlock(&key_lock);
	return EAGAIN;
}

int pthread_key_delete(pthread_key_t key)
{
	pthread_mutex_lock(&key_lock);
	if (key >= KEYS || !keys[key].used) {
		pthread_mutex_unlock(&key_lock);
		return EINVAL;
	}
	keys[key].used = 0;
	keys[key].destructor = NULL;
	for (unsigned int core = 0; core < STELA_LIBC_CORES; core++)
		specific[core][key] = NULL;
	pthread_mutex_unlock(&key_lock);
	return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
	pthread_mutex_lock(&key_lock);
	void *value = key < KEYS && keys[key].used ? specific[stela_libc_core()][key] : NULL;
	pthread_mutex_unlock(&key_lock);
	return value;
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
	pthread_mutex_lock(&key_lock);
	int result = EINVAL;
	if (key < KEYS && keys[key].used) {
		specific[stela_libc_core()][key] = (void *)value;
		result = 0;
	}
	pthread_mutex_unlock(&key_lock);
	return result;
}

/* Destructors may set a value again or create/delete keys. Clear the value
 * before calling out, with no registry lock held, as POSIX requires. */
static void destroy_specific(void)
{
	unsigned int core = stela_libc_core();
	for (unsigned int pass = 0; pass < PTHREAD_DESTRUCTOR_ITERATIONS; pass++) {
		int called = 0;
		for (unsigned int key = 0; key < KEYS; key++) {
			pthread_mutex_lock(&key_lock);
			void *value = specific[core][key];
			void (*destructor)(void *) = keys[key].destructor;
			specific[core][key] = NULL;
			pthread_mutex_unlock(&key_lock);
			if (value && destructor) {
				called = 1;
				destructor(value);
			}
		}
		if (!called)
			break;
	}
	pthread_mutex_lock(&key_lock);
	for (unsigned int key = 0; key < KEYS; key++)
		specific[core][key] = NULL;
	pthread_mutex_unlock(&key_lock);
}

int pthread_attr_init(pthread_attr_t *attr)
{
	attr->detachstate = PTHREAD_CREATE_JOINABLE;
	return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr)
{
	(void)attr;
	return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int state)
{
	if (state != PTHREAD_CREATE_JOINABLE && state != PTHREAD_CREATE_DETACHED)
		return EINVAL;
	attr->detachstate = state;
	return 0;
}

enum thread_state { FREE, JOINABLE, JOINING, DETACHED };
struct thread {
	void *(*body)(void *);
	void *argument, *result;
	volatile unsigned int finished;
	enum thread_state state;
	jmp_buf exit;
};

static struct thread threads[STELA_LIBC_THREADS];
static pthread_mutex_t thread_lock = PTHREAD_MUTEX_INITIALIZER;

static void thread_main(void *context)
{
	struct thread *thread = context;
	if (!setjmp(thread->exit))
		thread->result = thread->body(thread->argument);
	destroy_specific();
	stela_libc_thread_cleanup();
	pthread_mutex_lock(&thread_lock);
	__atomic_store_n(&thread->finished, 1, __ATOMIC_RELEASE);
	if (thread->state == DETACHED)
		thread->state = FREE;
	pthread_mutex_unlock(&thread_lock);
	wake(&thread->finished);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*body)(void *),
		   void *argument)
{
	if (attr && attr->detachstate != PTHREAD_CREATE_JOINABLE && attr->detachstate != PTHREAD_CREATE_DETACHED)
		return EINVAL;
	pthread_mutex_lock(&thread_lock);
	unsigned int index;
	for (index = 0; index < STELA_LIBC_THREADS; index++) {
		if (threads[index].state == FREE)
			break;
	}
	if (index == STELA_LIBC_THREADS) {
		pthread_mutex_unlock(&thread_lock);
		return EAGAIN;
	}
	struct thread *created = &threads[index];
	created->state = attr && attr->detachstate == PTHREAD_CREATE_DETACHED ? DETACHED : JOINABLE;
	created->body = body;
	created->argument = argument;
	created->result = NULL;
	__atomic_store_n(&created->finished, 0, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&thread_lock);
	unsigned int core = STELA_LIBC_PROCESSORS + index;
	int error = stela_libc_thread_start(thread_main, created, core);
	if (error) {
		pthread_mutex_lock(&thread_lock);
		created->state = FREE;
		pthread_mutex_unlock(&thread_lock);
		return -error;
	}
	*thread = core + 1;
	return 0;
}

int pthread_setcanceltype(int type, int *old)
{
	if (type != PTHREAD_CANCEL_DEFERRED)
		return ENOTSUP;
	if (old)
		*old = PTHREAD_CANCEL_DEFERRED;
	return 0;
}

int pthread_cancel(pthread_t thread)
{
	if (thread <= STELA_LIBC_PROCESSORS || thread > STELA_LIBC_CORES)
		return ESRCH;
	pthread_mutex_lock(&thread_lock);
	int result = threads[thread - STELA_LIBC_PROCESSORS - 1].state == FREE ? ESRCH : ENOTSUP;
	pthread_mutex_unlock(&thread_lock);
	return result;
}

int pthread_join(pthread_t thread, void **result)
{
	if (thread == pthread_self())
		return EDEADLK;
	if (thread <= STELA_LIBC_PROCESSORS || thread > STELA_LIBC_CORES)
		return EINVAL;
	struct thread *joined = &threads[thread - STELA_LIBC_PROCESSORS - 1];
	pthread_mutex_lock(&thread_lock);
	if (joined->state != JOINABLE) {
		pthread_mutex_unlock(&thread_lock);
		return EINVAL;
	}
	joined->state = JOINING;
	pthread_mutex_unlock(&thread_lock);
	while (!__atomic_load_n(&joined->finished, __ATOMIC_ACQUIRE))
		wait_while(&joined->finished, 0, UINT64_MAX);
	pthread_mutex_lock(&thread_lock);
	if (result)
		*result = joined->result;
	joined->state = FREE;
	pthread_mutex_unlock(&thread_lock);
	return 0;
}

int pthread_detach(pthread_t thread)
{
	if (thread <= STELA_LIBC_PROCESSORS || thread > STELA_LIBC_CORES)
		return EINVAL;
	struct thread *detached = &threads[thread - STELA_LIBC_PROCESSORS - 1];
	pthread_mutex_lock(&thread_lock);
	int result = EINVAL;
	if (detached->state == JOINABLE) {
		detached->state = __atomic_load_n(&detached->finished, __ATOMIC_ACQUIRE) ? FREE : DETACHED;
		result = 0;
	}
	pthread_mutex_unlock(&thread_lock);
	return result;
}

_Noreturn void pthread_exit(void *result)
{
	unsigned int core = stela_libc_core();
	if (core < STELA_LIBC_PROCESSORS || core >= STELA_LIBC_CORES)
		stela_libc_fatal("pthread_exit outside a Mesa thread");
	struct thread *thread = &threads[core - STELA_LIBC_PROCESSORS];
	thread->result = result;
	longjmp(thread->exit, 1);
}

int pthread_setname_np(pthread_t thread, const char *name)
{
	(void)thread;
	(void)name;
	return ENOTSUP;
}

/* Win64's preserved integer/vector state is a superset of SysV's. Hosted
 * tests pass arguments in SysV registers; the freestanding COFF image uses
 * Win64's. Both save the post-return stack pointer and resume address. */
__asm__(".text\n"
	".globl setjmp\n"
	"setjmp:\n"
#if !defined(__CYGWIN64__) && !defined(_WIN32)
	"\tmov %rdi, %rcx\n"
#endif
	"	mov %rbx, 0(%rcx)\n"
	"	mov %rbp, 8(%rcx)\n"
	"	mov %rdi, 16(%rcx)\n"
	"	mov %rsi, 24(%rcx)\n"
	"	mov %r12, 32(%rcx)\n"
	"	mov %r13, 40(%rcx)\n"
	"	mov %r14, 48(%rcx)\n"
	"	mov %r15, 56(%rcx)\n"
	"	lea 8(%rsp), %rax\n"
	"	mov %rax, 64(%rcx)\n"
	"	mov (%rsp), %rax\n"
	"	mov %rax, 72(%rcx)\n"
	"	movups %xmm6, 80(%rcx)\n"
	"	movups %xmm7, 96(%rcx)\n"
	"	movups %xmm8, 112(%rcx)\n"
	"	movups %xmm9, 128(%rcx)\n"
	"	movups %xmm10, 144(%rcx)\n"
	"	movups %xmm11, 160(%rcx)\n"
	"	movups %xmm12, 176(%rcx)\n"
	"	movups %xmm13, 192(%rcx)\n"
	"	movups %xmm14, 208(%rcx)\n"
	"	movups %xmm15, 224(%rcx)\n"
	"	stmxcsr 240(%rcx)\n"
	"	fnstcw 244(%rcx)\n"
	"	xor %eax, %eax\n"
	"	ret\n"
	".globl longjmp\n"
	"longjmp:\n"
#if !defined(__CYGWIN64__) && !defined(_WIN32)
	"\tmov %rdi, %rcx\n"
	"\tmov %esi, %edx\n"
#endif
	"	mov 0(%rcx), %rbx\n"
	"	mov 8(%rcx), %rbp\n"
	"	mov 16(%rcx), %rdi\n"
	"	mov 24(%rcx), %rsi\n"
	"	mov 32(%rcx), %r12\n"
	"	mov 40(%rcx), %r13\n"
	"	mov 48(%rcx), %r14\n"
	"	mov 56(%rcx), %r15\n"
	"	mov 64(%rcx), %rsp\n"
	"	movups 80(%rcx), %xmm6\n"
	"	movups 96(%rcx), %xmm7\n"
	"	movups 112(%rcx), %xmm8\n"
	"	movups 128(%rcx), %xmm9\n"
	"	movups 144(%rcx), %xmm10\n"
	"	movups 160(%rcx), %xmm11\n"
	"	movups 176(%rcx), %xmm12\n"
	"	movups 192(%rcx), %xmm13\n"
	"	movups 208(%rcx), %xmm14\n"
	"	movups 224(%rcx), %xmm15\n"
	"	ldmxcsr 240(%rcx)\n"
	"	fldcw 244(%rcx)\n"
	"	mov %edx, %eax\n"
	"	test %eax, %eax\n"
	"	jnz 1f\n"
	"	inc %eax\n"
	"1:	jmp *72(%rcx)\n");
