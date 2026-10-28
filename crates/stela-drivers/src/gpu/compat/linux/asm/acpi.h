/* SPDX-License-Identifier: MIT */
#ifndef _ASM_STELA_ACPI_H
#define _ASM_STELA_ACPI_H
/* Architecture declarations for Linux ACPI clients. They do not expose the
 * interpreter or install native services. Missing providers stay link/admission
 * requirements, never successful zero root addresses or ignored mutations. */
#include <linux/types.h>
#include <stela/acpi_client.h>
extern int acpi_disabled;
extern int acpi_noirq;
extern int acpi_pci_disabled;
#define ACPI_HAVE_ARCH_SET_ROOT_POINTER
#define ACPI_HAVE_ARCH_GET_ROOT_POINTER
void acpi_arch_set_root_pointer(u64 address);
u64 acpi_arch_get_root_pointer(void);
#endif
