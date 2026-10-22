/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_SIGNAL_H
#define _ASM_STELA_SIGNAL_H
/* x86-64's signal set, from arch/x86/include/asm/signal.h. Linux code under
 * Stela never delivers a signal. */
#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef unsigned long old_sigset_t;

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* x86-64's signal numbers and actions, from its uapi header. */
#include_next <asm/signal.h>

#define __ARCH_HAS_SA_RESTORER
#endif
