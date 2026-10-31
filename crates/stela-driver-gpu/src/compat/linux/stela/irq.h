/* SPDX-License-Identifier: MIT */
#ifndef STELA_IRQ_H
#define STELA_IRQ_H

/* Run the handlers of a raised line, on the owner's service task. */
void stela_linux_irq_run(unsigned int irq);
#endif
