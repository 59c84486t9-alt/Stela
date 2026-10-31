/* SPDX-License-Identifier: MIT */
/* What Linux's scheduler-internal kernel/sched/sched.h gives the scheduler's
 * shared units Stela builds unchanged (wait.c, swait.c, completion.c): the
 * declarations they share, and the wake core of Stela's scheduler in
 * kernel/task.c. */
#ifndef STELA_KERNEL_SCHED_H
#define STELA_KERNEL_SCHED_H
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/swait.h>
#include <linux/wait.h>

/* Wake hints. One CPU runs Linux code, so neither changes a wake. */
#define WF_SYNC 0x10
#define WF_CURRENT_CPU 0x40

/* Wake a task in one of the given states; 1 when it was in one. */
int try_to_wake_up(struct task_struct *task, unsigned int state, int wake_flags);

/* swait.c's helpers for completion.c, which hold the queue's lock. */
void swake_up_all_locked(struct swait_queue_head *q);
void __prepare_to_swait(struct swait_queue_head *q, struct swait_queue *wait);
#endif
