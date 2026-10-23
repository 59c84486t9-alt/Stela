/* SPDX-License-Identifier: MIT */
/* The pinned core includes this diagnostic-only header. Configuration-disabled
 * leak annotation exports no Linux kernel/OSL service and has no AML effects. */
#ifndef STELA_ACPI_DISABLED_KMEMLEAK
#define STELA_ACPI_DISABLED_KMEMLEAK
#define kmemleak_not_leak(pointer) ((void)(pointer))
#endif
