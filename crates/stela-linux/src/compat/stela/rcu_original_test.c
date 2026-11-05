// SPDX-License-Identifier: MIT
/* Hosted control entry, called only on the real joined source Runtime fixture.
 * No main/bare-current/softirq daemon substitute is supplied here. */
#include <linux/bottom_half.h>
#include <linux/interrupt.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <stela/allocation.h>
#include <stela/atomic_callback.h>
#include <stela/linux.h>
#include <stela/task.h>
#include <stela/test.h>

static unsigned int callbacks, descendants;
static struct rcu_head nested, reused;
static unsigned int reused_calls, freed_calls;
struct freed_callback { struct rcu_head head; u64 marker; };
static void reuse_head(struct rcu_head *head)
{
	assert(head == &reused && stela_linux_rcu_callback_current(head));
	assert(++reused_calls <= 2);
	if (reused_calls == 1)
		call_rcu(head, reuse_head);
}
static void free_container(struct rcu_head *head)
{
	struct freed_callback *object = container_of(head, struct freed_callback, head);
	assert(stela_linux_rcu_callback_current(head));
	assert(object->marker == 0xa8435df1e972602bULL);
	freed_calls++;
	kfree(object);
	/* Neither this callback nor the boundary observer reads the freed head. */
}
static void synchronize_reader(void)
{
	assert(!stela_linux_require_current(stela_linux_owner()));
	rcu_read_lock();
	assert(!stela_linux_require_current(stela_linux_owner()));
	assert(!stela_linux_quiescent());
	synchronize_rcu();
}
static void barrier_bh(void)
{
	assert(!stela_linux_require_current(stela_linux_owner()));
	local_bh_disable();
	assert(!stela_linux_require_current(stela_linux_owner()));
	assert(!stela_linux_quiescent());
	rcu_barrier();
}
static void barrier_irqs(void)
{
	assert(!stela_linux_require_current(stela_linux_owner()));
	local_irq_disable();
	assert(!stela_linux_require_current(stela_linux_owner()));
	assert(!stela_linux_quiescent());
	rcu_barrier();
}
static void schedule_reader(void)
{
	assert(!stela_linux_require_current(stela_linux_owner()));
	rcu_read_lock();
	assert(!stela_linux_require_current(stela_linux_owner()));
	assert(!stela_linux_quiescent());
	schedule();
}
static void synchronize_balanced_callback(void)
{
	/* Public count balancing never ends the independent original dispatch. */
	preempt_count_sub(SOFTIRQ_OFFSET);
	assert(!stela_linux_require_current(stela_linux_owner()));
	assert(stela_linux_atomic_softirq_dispatch_active());
	assert(stela_linux_rcu_callback_active() && !stela_linux_quiescent());
	synchronize_rcu();
}
static void descendant(struct rcu_head *head)
{
	assert(head == &nested && stela_linux_rcu_callback_current(head));
	assert(stela_linux_atomic_softirq_dispatch_active() && in_serving_softirq());
	descendants++;
}
static void callback(struct rcu_head *head)
{
	assert(stela_linux_rcu_callback_current(head));
	assert(stela_linux_rcu_callback_active() && in_serving_softirq());
	assert(stela_linux_atomic_softirq_dispatch_active() && !irqs_disabled());
	assert(stela_test_traps(synchronize_balanced_callback));
	callbacks++;
	call_rcu(&nested, descendant);
}

int stela_test_original_rcu(void)
{
	assert(!stela_linux_require_current(stela_linux_owner()));
	assert(stela_linux_quiescent());
	assert(!callbacks && !descendants && !reused_calls && !freed_calls);
	assert(stela_test_traps(synchronize_reader));
	assert(stela_test_traps(barrier_bh));
	assert(stela_test_traps(barrier_irqs));
	assert(stela_test_traps(schedule_reader));

	struct rcu_head head;
	unsigned long cookie = get_state_synchronize_rcu();
	call_rcu(&head, callback);
	/* No source switch/IRQ/softirq entry occurs within this straight-line
	 * observation. Repeating the original poll cannot manufacture a QS. */
	for (unsigned int i = 0; i < 8; i++)
		assert(!poll_state_synchronize_rcu(cookie));
	assert(!callbacks && !descendants);
	rcu_barrier();
	assert(callbacks == 1 && poll_state_synchronize_rcu(cookie));
	/* The descendant may run before this process resumes. Independently join
	 * the callback enqueued by callback(), retaining both heads until done. */
	rcu_barrier();
	assert(descendants == 1 && stela_linux_quiescent());
	assert(!stela_linux_rcu_callback_active());
	call_rcu(&reused, reuse_head);
	rcu_barrier();
	rcu_barrier();
	assert(reused_calls == 2);
	struct freed_callback *object = kmalloc(sizeof(*object), GFP_KERNEL);
	assert(object);
	object->marker = 0xa8435df1e972602bULL;
	call_rcu(&object->head, free_container);
	rcu_barrier();
	assert(freed_calls == 1 && stela_linux_quiescent());
	return 0;
}
