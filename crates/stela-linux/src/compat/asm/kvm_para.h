/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM_STELA_KVM_PARA_H
#define ASM_STELA_KVM_PARA_H

/* No KVM paravirtualized service is selected by the native architecture.
 * Enabling it requires its owning hypervisor interface, not feature bits. */
#ifdef CONFIG_KVM_GUEST
#error "Stela KVM guest services require a native hypervisor provider"
#endif
#include <asm-generic/kvm_para.h>

#endif
