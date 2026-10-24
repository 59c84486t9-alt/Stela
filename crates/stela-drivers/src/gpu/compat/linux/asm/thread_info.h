/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_THREAD_INFO_H
#define _ASM_STELA_THREAD_INFO_H
/* Actual Runtime-bound Linux tasks use embedded metadata. Taskless leaf
 * services use independent explicit metadata and acquire no current task. */
#include <asm-generic/thread_info_tif.h>
#include <asm/page.h>

/* Exact admitted Linux usable stack size; Runtime retains the real backing. */
#define THREAD_SIZE (PAGE_SIZE << 2)

struct task_struct;

struct thread_info {
	struct task_struct *task;
	unsigned long flags;
	int preempt_count;
};

extern struct thread_info stela_thread_info;
struct thread_info *stela_linux_thread_info(void);
/* Override Linux's CONFIG_THREAD_INFO_IN_TASK default at the arch boundary so
 * explicit taskless leaf bookkeeping never fabricates current. */
#undef current_thread_info
#define current_thread_info() stela_linux_thread_info()
#endif
