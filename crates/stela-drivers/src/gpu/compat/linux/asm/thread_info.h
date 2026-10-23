/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_THREAD_INFO_H
#define _ASM_STELA_THREAD_INFO_H
/* Linux code under Stela runs in one thread at a time, the context of the
 * owner it runs for; that thread's flags are asm-generic's, its task is
 * asm-generic/current.h's current, and its preemption count is
 * asm-generic/preempt.h's. Nothing preempts it and no reschedule is pending. */
#include <asm-generic/thread_info_tif.h>
#include <asm/page.h>

/* x86-64's kernel stack size; Stela allocates no thread stacks. */
#define THREAD_SIZE (PAGE_SIZE << 2)

struct task_struct;

struct thread_info {
	struct task_struct *task;
	unsigned long flags;
	int preempt_count;
};

extern struct thread_info stela_thread_info;
#define current_thread_info() (&stela_thread_info)
#endif
