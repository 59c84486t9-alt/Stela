/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_PGTABLE_H
#define _ASM_STELA_PGTABLE_H
/* x86-64's four-level page table format, from arch/x86/include/asm's
 * pgtable_64_types.h and pgtable_types.h, with which Linux's MM headers
 * describe mappings. Linux code under Stela owns no address space and edits
 * no CPU page table: its memory owners map memory. */
#include <linux/const.h>
#include <asm/page.h>
#include <asm-generic/pgtable-nop4d.h>

#define PGDIR_SHIFT	39
#define PTRS_PER_PGD	512
#define PUD_SHIFT	30
#define PTRS_PER_PUD	512
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512
#define PTRS_PER_PTE	512

#define PGDIR_SIZE	(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))
#define PUD_SIZE	(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))
#define PMD_SIZE	(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))

#define _PAGE_PRESENT	(_AT(pteval_t, 1) << 0)
#define _PAGE_RW	(_AT(pteval_t, 1) << 1)
#define _PAGE_USER	(_AT(pteval_t, 1) << 2)
#define _PAGE_PWT	(_AT(pteval_t, 1) << 3)
#define _PAGE_PCD	(_AT(pteval_t, 1) << 4)
#define _PAGE_ACCESSED	(_AT(pteval_t, 1) << 5)
#define _PAGE_DIRTY	(_AT(pteval_t, 1) << 6)
#define _PAGE_PSE	(_AT(pteval_t, 1) << 7)
#define _PAGE_NX	(_AT(pteval_t, 1) << 63)

#define PFN_PTE_SHIFT	PAGE_SHIFT
/* x86-64's 52 physical address bits. */
#define PTE_PFN_MASK	(((_AT(pteval_t, 1) << 52) - 1) & PAGE_MASK)

#define pte_val(x)	((x).pte)
#define pmd_val(x)	((x).pmd)
#define pud_val(x)	((x).pud)
#define pgd_val(x)	((x).pgd)
#define pgprot_val(x)	((x).pgprot)
#define __pte(x)	((pte_t) { (x) })
#define __pmd(x)	((pmd_t) { (x) })
#define __pud(x)	((pud_t) { (x) })
#define __pgd(x)	((pgd_t) { (x) })
#define __pgprot(x)	((pgprot_t) { (x) })

static inline int pte_present(pte_t pte) { return pte_val(pte) & _PAGE_PRESENT; }
static inline int pte_write(pte_t pte) { return !!(pte_val(pte) & _PAGE_RW); }
static inline int pte_young(pte_t pte) { return !!(pte_val(pte) & _PAGE_ACCESSED); }
static inline int pte_dirty(pte_t pte) { return !!(pte_val(pte) & _PAGE_DIRTY); }
static inline pte_t pte_set_flags(pte_t pte, pteval_t set) { return __pte(pte_val(pte) | set); }
static inline pte_t pte_clear_flags(pte_t pte, pteval_t clear)
{
	return __pte(pte_val(pte) & ~clear);
}
static inline pte_t pte_mkyoung(pte_t pte) { return pte_set_flags(pte, _PAGE_ACCESSED); }
static inline pte_t pte_mkold(pte_t pte) { return pte_clear_flags(pte, _PAGE_ACCESSED); }
static inline pte_t pte_mkdirty(pte_t pte) { return pte_set_flags(pte, _PAGE_DIRTY); }
static inline pte_t pte_mkclean(pte_t pte) { return pte_clear_flags(pte, _PAGE_DIRTY); }
static inline pte_t pte_mkwrite_novma(pte_t pte) { return pte_set_flags(pte, _PAGE_RW); }
static inline pte_t pte_wrprotect(pte_t pte) { return pte_clear_flags(pte, _PAGE_RW); }
static inline unsigned long pte_pfn(pte_t pte)
{
	return (pte_val(pte) & PTE_PFN_MASK) >> PAGE_SHIFT;
}
static inline pte_t pfn_pte(unsigned long pfn, pgprot_t prot)
{
	return __pte(((pteval_t)pfn << PAGE_SHIFT) | pgprot_val(prot));
}
static inline void set_pte(pte_t *ptep, pte_t pte) { WRITE_ONCE(*ptep, pte); }
static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	set_pte(ptep, __pte(0));
}

static inline int pmd_none(pmd_t pmd) { return !pmd_val(pmd); }
static inline int pmd_present(pmd_t pmd) { return pmd_val(pmd) & _PAGE_PRESENT; }
static inline int pmd_bad(pmd_t pmd) { return !(pmd_val(pmd) & _PAGE_PRESENT); }
static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(pmd_val(pmd) & PTE_PFN_MASK);
}
static inline int pud_none(pud_t pud) { return !pud_val(pud); }
static inline int pud_present(pud_t pud) { return pud_val(pud) & _PAGE_PRESENT; }
static inline int pud_bad(pud_t pud) { return !(pud_val(pud) & _PAGE_PRESENT); }
static inline pmd_t *pud_pgtable(pud_t pud)
{
	return (pmd_t *)__va(pud_val(pud) & PTE_PFN_MASK);
}
static inline int p4d_none(p4d_t p4d) { return !p4d_val(p4d); }
static inline int p4d_present(p4d_t p4d) { return p4d_val(p4d) & _PAGE_PRESENT; }
static inline int p4d_bad(p4d_t p4d) { return !(p4d_val(p4d) & _PAGE_PRESENT); }
static inline pud_t *p4d_pgtable(p4d_t p4d)
{
	return (pud_t *)__va(p4d_val(p4d) & PTE_PFN_MASK);
}

#define PAGE_NONE	__pgprot(0)
#define PAGE_KERNEL	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | \
				 _PAGE_DIRTY | _PAGE_NX)
#endif
