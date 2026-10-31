/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_PROCESSOR_H
#define _ASM_STELA_PROCESSOR_H
/* The processor services Linux code uses, from x86's asm/processor.h. */
#include <linux/compiler.h>
#include <linux/types.h>

/* Runtime owns the actual saved CPU frame and retained stack. This Linux
 * task metadata contains no duplicate architecture context switch state. */
struct thread_struct {
};
/* There is genuinely no duplicate CPU frame in this native metadata. This
 * initializer does not construct x86 thread.sp, pt_regs or ret_from_fork. */
#define INIT_THREAD {}

/* The one CPU model fact Linux code here reads: family 6, past the i386. */
static const struct {
	u8 x86;
} boot_cpu_data __maybe_unused = {.x86 = 6};

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
