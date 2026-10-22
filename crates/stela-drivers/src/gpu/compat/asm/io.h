/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_IO_H
#define _ASM_STELA_IO_H
/* asm-generic's MMIO accessors: volatile accesses with x86's fences. Device
 * memory is mapped by Stela's device owners, so the kernel-API's ioremap()
 * maps nothing. */
#include <linux/types.h>

void __iomem *ioremap(phys_addr_t offset, size_t size);
#define ioremap ioremap
void iounmap(volatile void __iomem *addr);
#define iounmap iounmap

#include <asm-generic/io.h>
#endif
