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

/* Copyright Linux kernel contributors; from asm/vdso/processor.h. */
static __always_inline void cpu_relax(void)
{
	asm volatile("rep; nop" ::: "memory");
}
#endif
