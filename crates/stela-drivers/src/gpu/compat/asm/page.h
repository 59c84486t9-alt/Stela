/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_PAGE_H
#define _ASM_STELA_PAGE_H
/* x86-64's 4 KiB base page and its page table entry types, from
 * arch/x86/include/asm/pgtable_64_types.h. Stela's memory owners, not a
 * kernel direct map, hold memory, so the arch translates no addresses
 * between pages, frames and kernel virtual addresses, and Linux code edits
 * no CPU page tables. */
#include <linux/const.h>
#include <linux/pfn.h>
#include <linux/types.h>
#include <vdso/page.h>

struct page;

typedef unsigned long	pteval_t;
typedef unsigned long	pmdval_t;
typedef unsigned long	pudval_t;
typedef unsigned long	pgdval_t;
typedef unsigned long	pgprotval_t;

typedef struct { pteval_t pte; } pte_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pudval_t pud; } pud_t;
typedef struct { pgdval_t pgd; } pgd_t;
typedef struct pgprot { pgprotval_t pgprot; } pgprot_t;

typedef struct page *pgtable_t;

/* x86-64's user address space; Linux code under Stela serves none. */
#define TASK_SIZE_MAX	((_AC(1, UL) << 47) - PAGE_SIZE)
#define TASK_SIZE	TASK_SIZE_MAX

/* Stela has no kernel direct map: the platform translates between physical
 * and virtual addresses. */
extern unsigned long __phys_addr(unsigned long);
extern void *__phys_to_virt(phys_addr_t);
#define __pa(x)		__phys_addr((unsigned long)(x))
#define __va(x)		__phys_to_virt((phys_addr_t)(x))

/* Nor does Stela keep an array of struct page: the platform describes each
 * frame. */
struct page *pfn_to_page(unsigned long pfn);
unsigned long page_to_pfn(const struct page *page);
#define pfn_to_page pfn_to_page
#define page_to_pfn page_to_pfn
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
#define page_to_phys(page)	PFN_PHYS(page_to_pfn(page))
#define __pfn_to_phys(pfn)	PFN_PHYS(pfn)
#define __phys_to_pfn(paddr)	PHYS_PFN(paddr)
#define phys_to_page(phys)	pfn_to_page(PHYS_PFN(phys))

/* Pages are ordinary memory to Linux code, which clears and copies them
 * with the compiler's memset and memcpy. */
#define clear_page(page)	__builtin_memset((page), 0, PAGE_SIZE)
#define copy_page(to,from)	__builtin_memcpy((to), (from), PAGE_SIZE)
#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

#include <asm-generic/getorder.h>
#endif
