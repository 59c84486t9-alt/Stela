/* SPDX-License-Identifier: MIT */
#ifndef _ASM_STELA_ACENV_H
#define _ASM_STELA_ACENV_H
/* Kernel clients consume public ACPICA types only. The boot-owned interpreter
 * has its own environment; no cache/global-lock/interpreter operations are
 * supplied or silently emulated by this client architecture boundary. */
#include <stela/acpi_client.h>
/* Generic ACPICA defaults would claim a global-lock acquisition or silently
 * omit a cache flush. Those interpreter operations are not client services. */
void stela_linux_acpi_interpreter_operation(void)
    __attribute__((error("ACPICA interpreter operations require the boot-owned Session")));
#define ACPI_ACQUIRE_GLOBAL_LOCK(pointer, acquired) \
    do { stela_linux_acpi_interpreter_operation(); } while (0)
#define ACPI_RELEASE_GLOBAL_LOCK(pointer, pending) \
    do { stela_linux_acpi_interpreter_operation(); } while (0)
#define ACPI_FLUSH_CPU_CACHE() stela_linux_acpi_interpreter_operation()
#endif
