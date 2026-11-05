/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_TLBFLUSH_H
#define _ASM_STELA_TLBFLUSH_H
/* Original x86 TLB contracts, DECLARATIONS ONLY. Required native providers
 * are UNPROVIDED: this header performs no flush, invalidation or ownership
 * admission, and must not be mistaken for the !MMU generic implementation. */
#include <linux/types.h>
struct mm_struct;
struct vm_area_struct;

void __flush_tlb_all(void);
#define TLB_FLUSH_ALL -1UL
extern void flush_tlb_all(void);
extern void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned int stride_shift,
				bool freed_tables);
extern void flush_tlb_kernel_range(unsigned long start, unsigned long end);
/* Original x86 public wrapper still calls the required real range provider. */
#define flush_tlb_mm(mm) \
	flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, 0UL, true)
/* Signatures of the original x86 inline public interfaces. Their actual
 * architecture implementations remain required, not supplied here. */
extern void flush_tlb_page(struct vm_area_struct *vma, unsigned long a);

#endif
