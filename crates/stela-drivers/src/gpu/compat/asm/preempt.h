/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H
/* asm-generic/preempt.h for Stela, where Linux code runs for one owner at a
 * time and is never preempted: the count belongs to that single context, as
 * x86's per-CPU __preempt_count does, and no reschedule is ever pending. */
#include <linux/compiler.h>

extern int __preempt_count;

#define PREEMPT_ENABLED	(0)

static __always_inline int preempt_count(void)
{
	return READ_ONCE(__preempt_count);
}

static __always_inline volatile int *preempt_count_ptr(void)
{
	return &__preempt_count;
}

static __always_inline void preempt_count_set(int pc)
{
	*preempt_count_ptr() = pc;
}

static __always_inline void set_preempt_need_resched(void)
{
}

static __always_inline void clear_preempt_need_resched(void)
{
}

static __always_inline bool test_preempt_need_resched(void)
{
	return false;
}

static __always_inline void __preempt_count_add(int val)
{
	*preempt_count_ptr() += val;
}

static __always_inline void __preempt_count_sub(int val)
{
	*preempt_count_ptr() -= val;
}

static __always_inline bool __preempt_count_dec_and_test(void)
{
	--*preempt_count_ptr();
	return false;
}

static __always_inline bool should_resched(int preempt_offset)
{
	return false;
}
#endif
