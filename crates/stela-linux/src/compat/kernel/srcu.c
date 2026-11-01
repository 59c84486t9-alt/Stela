// SPDX-License-Identifier: MIT
/* Tiny SRCU's grace periods, following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 kernel/rcu/srcutiny.c. Nothing
 * Stela builds calls call_srcu, so no work or irq_work is ever queued and a
 * grace period runs in its synchronize_srcu. */
#include <linux/mutex.h>
#include <linux/srcu.h>
#include <linux/swait.h>

static DEFINE_MUTEX(grace_periods);

void __srcu_read_unlock(struct srcu_struct *ssp, int idx)
{
	short nesting = (short)(READ_ONCE(ssp->srcu_lock_nesting[idx]) - 1);

	WRITE_ONCE(ssp->srcu_lock_nesting[idx], nesting);
	if (!nesting && READ_ONCE(ssp->srcu_gp_waiting) && in_task())
		swake_up_one(&ssp->srcu_wq);
}

void synchronize_srcu(struct srcu_struct *ssp)
{
	might_sleep();
	mutex_lock(&grace_periods);
	int idx = (int)((ssp->srcu_idx & 0x2) / 2);

	WRITE_ONCE(ssp->srcu_idx, ssp->srcu_idx + 1);
	WRITE_ONCE(ssp->srcu_gp_waiting, true);
	swait_event_exclusive(ssp->srcu_wq, !READ_ONCE(ssp->srcu_lock_nesting[idx]));
	WRITE_ONCE(ssp->srcu_gp_waiting, false);
	WRITE_ONCE(ssp->srcu_idx, ssp->srcu_idx + 1);
	mutex_unlock(&grace_periods);
}

/* What call_srcu would queue, which DEFINE_SRCU's initializers name. */
void srcu_drive_gp(struct work_struct *wp)
{
	(void)wp;
	WARN_ON_ONCE(1);
}

void srcu_tiny_irq_work(struct irq_work *irq_work)
{
	(void)irq_work;
	WARN_ON_ONCE(1);
}
