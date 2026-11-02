/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM_STELA_MMU_CONTEXT_H
#define ASM_STELA_MMU_CONTEXT_H

struct mm_struct;
struct task_struct;

/* The original x86 interface. Native address-space switching requires its
 * owning root provider; a declaration does not supply a no-op switch. */
extern void switch_mm(struct mm_struct *prev, struct mm_struct *next,
		      struct task_struct *tsk);

#include <asm-generic/mmu_context.h>

#endif
