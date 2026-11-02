// SPDX-License-Identifier: GPL-2.0+
/* Native ownership/progress boundaries for original Tiny SRCU. */
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/srcu.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <stela/atomic_callback.h>
#include <stela/catalogue.h>
#include <stela/linux.h>
#include <stela/srcu.h>
#include <stela/task.h>

static_assert(IS_ENABLED(CONFIG_TINY_SRCU));
static_assert(IS_ENABLED(CONFIG_TINY_RCU));
static_assert(!IS_ENABLED(CONFIG_TREE_SRCU));
static_assert(!IS_ENABLED(CONFIG_TREE_RCU));
static_assert(!IS_ENABLED(CONFIG_SMP));
static_assert(!IS_ENABLED(CONFIG_PREEMPTION));
static_assert(!IS_ENABLED(CONFIG_PREEMPT_RT));
static_assert(!IS_ENABLED(CONFIG_DEBUG_LOCK_ALLOC));

enum phase { UNBOUND, SOURCE_BOUND, PROBING, REFUSED, ACTIVE };
static enum phase phase;
static bool native_bootstrap_joined;
#define PROBE_TICKS (HZ > 1 ? HZ : 1)

struct pool_probe {
	struct work_struct first, second;
	struct completion second_done, first_done;
	struct task_struct *first_task;
	struct workqueue_struct *queue;
	const struct stela_linux_owner *owner;
	int error;
};
struct clock_probe {
	struct timer_list timer;
	struct completion delivered;
};

/* Called only by the one retained original Initial bootstrap. Source-bound
 * is ownership, never an assertion that rcu_init/srcu_init/workers ran. The
 * actual source sequence remains in the original task bootstrap owner. */
int stela_linux_srcu_bind_initial(const struct stela_linux_owner *owner)
{
    if (!owner)
        return -EINVAL;
    int error = stela_linux_require_current(owner);
    if (error)
        return error;
    if (current != &init_task || rcu_scheduler_active != RCU_SCHEDULER_INACTIVE)
        return -EPERM;
    enum phase expected = UNBOUND;
    return __atomic_compare_exchange_n(&phase, &expected, SOURCE_BOUND, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 0 : -EALREADY;
}
bool stela_linux_srcu_owner_bound(const struct stela_linux_owner *owner)
{
	return owner && stela_linux_kernel_catalogue_active() &&
	       stela_linux_kernel_owner_allowed(owner) &&
	       __atomic_load_n(&phase, __ATOMIC_ACQUIRE) != UNBOUND;
}
/* Private Rust Bootstrap::join ABI. Caller first proves its exact retained
 * original managed request fully joined and its C result succeeded. This bounded
 * atomic acknowledgement performs no C task/owner entry or callback. No
 * original driver header exports a constructor for this completion receipt. */
int stela_linux_srcu_bootstrap_joined(const struct stela_linux_owner *owner);
int stela_linux_srcu_bootstrap_joined(const struct stela_linux_owner *owner)
{
    if (!owner || !stela_linux_kernel_catalogue_active() ||
        !stela_linux_kernel_owner_allowed(owner) ||
        __atomic_load_n(&phase, __ATOMIC_ACQUIRE) != ACTIVE)
        return -EPERM;
    bool expected = false;
    return __atomic_compare_exchange_n(&native_bootstrap_joined, &expected, true, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 0 : -EALREADY;
}
int stela_linux_srcu_current_active(const struct stela_linux_owner *owner)
{
    if (!owner)
        return -EINVAL;
    if (!stela_linux_kernel_catalogue_active() || !stela_linux_kernel_owner_allowed(owner))
        return -EPERM;
    if (__atomic_load_n(&phase, __ATOMIC_ACQUIRE) != ACTIVE ||
        !__atomic_load_n(&native_bootstrap_joined, __ATOMIC_ACQUIRE))
        return -EAGAIN;
    /* The one actual source current predicate is separate from subsystem
     * readiness and remains valid in original atomic callback scopes. */
    return stela_linux_require_current(owner);
}
bool stela_linux_srcu_bootstrapping(const struct stela_linux_owner *owner)
{
	return stela_linux_srcu_owner_bound(owner) && __atomic_load_n(&phase, __ATOMIC_ACQUIRE) == PROBING;
}
void stela_linux_srcu_require_bound(void)
{
	(void)stela_linux_current();
	if (stela_linux_require_current(stela_linux_owner()) ||
            !stela_linux_srcu_owner_bound(stela_linux_owner()))
		__builtin_trap();
}
void stela_linux_srcu_require_wait_context(void)
{
	stela_linux_srcu_require_bound();
	if (!stela_linux_quiescent())
		__builtin_trap();
}
void stela_linux_srcu_invoke(struct rcu_head *head)
{
	stela_linux_srcu_require_bound();
	/* Original caller disabled BH; preserve that exact context and end before
	 * its original local_bh_enable. A callback may free head. */
	struct stela_linux_atomic_callback scope;
	stela_linux_atomic_callback_bh_begin(&scope);
	head->func(head);
	stela_linux_atomic_callback_bh_end(&scope);
}
static void probe_context(const struct stela_linux_owner *owner)
{
	(void)stela_linux_current();
	if (stela_linux_require_current(owner) || !stela_linux_quiescent())
		__builtin_trap();
}
static void probe_second(struct work_struct *work)
{
	struct pool_probe *probe = container_of(work, struct pool_probe, second);
	probe_context(probe->owner);
	/* On replacement refusal the first work can time out and its worker then
	 * takes this still-pending second work itself. That is a typed failed
	 * readiness probe, not corrupt current/context or a successful replacement. */
	if (!probe->first_task)
		probe->error = -EIO;
	else if (current == probe->first_task)
		probe->error = -EAGAIN;
	complete(&probe->second_done);
}
static void probe_first(struct work_struct *work)
{
	struct pool_probe *probe = container_of(work, struct pool_probe, first);
	probe_context(probe->owner);
	probe->first_task = current;
	if (!queue_work(probe->queue, &probe->second))
		probe->error = -EIO;
	else if (!wait_for_completion_timeout(&probe->second_done, PROBE_TICKS))
		probe->error = -ETIMEDOUT;
	complete(&probe->first_done);
}
static void pool_init(struct pool_probe *probe,
		      const struct stela_linux_owner *owner,
		      struct workqueue_struct *queue)
{
	*probe = (struct pool_probe){.queue = queue, .owner = owner};
	init_completion(&probe->second_done);
	init_completion(&probe->first_done);
	INIT_WORK(&probe->first, probe_first);
	INIT_WORK(&probe->second, probe_second);
}
static void pool_join(struct pool_probe *probe)
{
	/* A started first work has a bounded wait and may still enqueue second.
	 * Join/cancel first before canceling second; never free a live stack probe.
	 * If clock/progress is lost these waits retain this actual task/frame. */
	cancel_work_sync(&probe->first);
	cancel_work_sync(&probe->second);
	flush_work(&probe->first);
	flush_work(&probe->second);
}
static void clock_delivered(struct timer_list *timer)
{
	struct clock_probe *probe = container_of(timer, struct clock_probe, timer);
	complete(&probe->delivered);
}
int stela_linux_srcu_bootstrap(const struct stela_linux_owner *owner)
{
	(void)stela_linux_current();
	if (!owner || stela_linux_owner() != owner ||
	    !stela_linux_kernel_catalogue_active() ||
	    !stela_linux_kernel_owner_allowed(owner))
		return -EPERM;
	int current_error = stela_linux_require_current(owner);
	if (current_error)
		return current_error;
	if (!stela_linux_srcu_owner_bound(owner) ||
            rcu_scheduler_active == RCU_SCHEDULER_INACTIVE)
		return -EAGAIN;
	if (!stela_linux_quiescent())
		return -EBUSY;
	/* Pointer presence is only a cold-init refusal gate. Actual worker and
	 * clock probes below remain the functional readiness evidence. */
	if (!system_wq || !system_highpri_wq)
		return -EAGAIN;
	if (__atomic_load_n(&phase, __ATOMIC_ACQUIRE) == ACTIVE)
		return -EALREADY;
	if (__atomic_load_n(&phase, __ATOMIC_ACQUIRE) == PROBING)
		return -EBUSY;
	__atomic_store_n(&phase, PROBING, __ATOMIC_RELEASE);
	struct pool_probe normal, high;
	pool_init(&normal, owner, system_wq);
	pool_init(&high, owner, system_highpri_wq);
	struct clock_probe clock;
	init_completion(&clock.delivered);
	timer_setup(&clock.timer, clock_delivered, 0);
	mod_timer(&clock.timer, jiffies + 1);
	int error = 0;
	if (!queue_work(normal.queue, &normal.first) ||
	    !queue_work(high.queue, &high.first))
		error = -EIO;
	if (!error && (!wait_for_completion_timeout(&normal.first_done, PROBE_TICKS) ||
		       !wait_for_completion_timeout(&high.first_done, PROBE_TICKS) ||
		       !wait_for_completion_timeout(&clock.delivered, PROBE_TICKS)))
		error = -ETIMEDOUT;
	pool_join(&normal);
	pool_join(&high);
	timer_delete_sync(&clock.timer);
	if (normal.error || high.error)
		error = normal.error ? normal.error : high.error;
	if (error) {
		__atomic_store_n(&phase, REFUSED, __ATOMIC_RELEASE);
		return error;
	}
	/* Only probe completion is published here. The one original source boot
         * path already ran rcu_init/srcu_init and started its actual scheduler;
         * calling those again here would corrupt their original boot ordering. */
	__atomic_store_n(&phase, ACTIVE, __ATOMIC_RELEASE);
	return 0;
}
void stela_linux_srcu_cleanup_begin(struct srcu_struct *ssp)
{
	stela_linux_srcu_require_wait_context();
	/* Original cleanup's reader warning is not a storage-release receipt. */
	if (READ_ONCE(ssp->srcu_lock_nesting[0]) || READ_ONCE(ssp->srcu_lock_nesting[1]))
		__builtin_trap();
}
void stela_linux_srcu_cleanup_end(struct srcu_struct *ssp)
{
	/* Called only after original irq_work_sync + flush_work. Producers must
	 * already be stopped by their owning original subsystem. */
	if (READ_ONCE(ssp->srcu_lock_nesting[0]) || READ_ONCE(ssp->srcu_lock_nesting[1]) ||
	    ssp->srcu_gp_running || ssp->srcu_gp_waiting || ssp->srcu_cb_head ||
	    ssp->srcu_cb_tail != &ssp->srcu_cb_head ||
	    ssp->srcu_idx != ssp->srcu_idx_max || (ssp->srcu_idx & 1))
		__builtin_trap();
}
