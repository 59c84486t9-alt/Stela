/* SPDX-License-Identifier: GPL-2.0 */
/* Stela's interrupt state is asm-generic's: no interrupt reaches Linux code,
 * so the state is a flag that the kernel-API keeps for local_irq_save(). */
#include <asm-generic/irqflags.h>
