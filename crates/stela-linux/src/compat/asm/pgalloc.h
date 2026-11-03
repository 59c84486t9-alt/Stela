/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_PGALLOC_H
#define _ASM_STELA_PGALLOC_H
#include <asm-generic/pgalloc.h>

/* Original x86 root allocation interface. A native owner must supply it. */
extern pgd_t *pgd_alloc(struct mm_struct *mm);

#endif
