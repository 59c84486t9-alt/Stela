/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_ASM_PAGE_H
#define STELA_ASM_PAGE_H
/* x86-64's base page, from asm/page_types.h. */
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif
