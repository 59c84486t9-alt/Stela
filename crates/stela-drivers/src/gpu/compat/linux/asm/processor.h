/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_PROCESSOR_H
#define _ASM_STELA_PROCESSOR_H
/* The processor services Linux code uses, from x86's asm/processor.h. */
#include <linux/compiler.h>

/* Linux code never switches threads under Stela, so a thread keeps no CPU
 * state of its own. */
struct thread_struct {
};

struct pt_regs;
struct task_struct;
/* Nor does a thread keep user registers. */
struct pt_regs *task_pt_regs(struct task_struct *task);

/* Busy-wait loops relax with x86's PAUSE, which is also a compiler barrier
 * as Linux's is. */
static __always_inline void cpu_relax(void)
{
	asm volatile("pause" ::: "memory");
}
#endif
