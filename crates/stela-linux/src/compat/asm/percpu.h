/* SPDX-License-Identifier: MIT */
#ifndef STELA_ASM_PERCPU_H
#define STELA_ASM_PERCPU_H
/* Per-CPU variables on Stela's uniprocessor arch are ordinary objects in the
 * platform's default sections, like every object (see stela/compiler.h);
 * Mach-O hosts would also reject Linux's section names. Their attributes are
 * redefined before the generic arch can name a section, so any per-CPU
 * declaration either has these or fails to build. */
#include <linux/percpu-defs.h>

#undef __PCPU_ATTRS
#define __PCPU_ATTRS(sec) __percpu PER_CPU_ATTRIBUTES

#include <asm-generic/percpu.h>
#endif
