/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_ACPI_CLIENT_H
#define STELA_LINUX_ACPI_CLIENT_H
/* Forced into kernel clients before public ACPICA declarations. Boot owns the
 * separate interpreter and its namespace guard. A kernel client must reach the
 * retained portal, never resolve these calls to that interpreter's raw exports.
 * These names supply no implementation or admission authority. Original Linux
 * evaluate_dsm/check_dsm helpers remain over this redirected evaluate boundary.
 */
#if defined(BUILDING_ACPICA) || defined(STELA_ACPI)
#error "The kernel ACPI client boundary cannot compile an ACPICA interpreter"
#endif
#define acpi_get_handle stela_linux_acpi_get_handle
#define acpi_evaluate_object stela_linux_acpi_evaluate_object
#endif
