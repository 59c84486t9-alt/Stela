/* SPDX-License-Identifier: MIT */
#ifndef STELA_ACPI_BRIDGE_H
#define STELA_ACPI_BRIDGE_H
#include "acpi/acpi.h"
/* Every callback is mandatory, even in interpreter mode. Missing operations must
 * return their real ACPICA error; void callbacks must fulfil their contract. */
struct stela_acpi_services {
    void *context;
    acpi_physical_address root;
    u64 capabilities;
    void *(*allocate)(void *, u64);
    void (*free)(void *, void *);
    void *(*map)(void *, u64, u64);
    void (*unmap)(void *, void *, u64);
    acpi_status (*create_lock)(void *, void **);
    void (*delete_lock)(void *, void *);
    u64 (*acquire_lock)(void *, void *);
    void (*release_lock)(void *, void *, u64);
    acpi_status (*create_semaphore)(void *, u32, u32, void **);
    acpi_status (*delete_semaphore)(void *, void *);
    acpi_status (*wait_semaphore)(void *, void *, u32, u16);
    acpi_status (*signal_semaphore)(void *, void *, u32);
    acpi_status (*install_interrupt)(void *, u32, acpi_osd_handler, void *);
    acpi_status (*remove_interrupt)(void *, u32, acpi_osd_handler);
    u64 (*thread_id)(void *);
    acpi_status (*execute)(void *, u32, acpi_osd_exec_callback, void *);
    void (*drain_work)(void *);
    void (*sleep)(void *, u64);
    void (*stall)(void *, u32);
    acpi_status (*read_port)(void *, u64, u32 *, u32);
    acpi_status (*write_port)(void *, u64, u32, u32);
    acpi_status (*read_memory)(void *, u64, u64 *, u32);
    acpi_status (*write_memory)(void *, u64, u64, u32);
    acpi_status (*read_pci)(void *, struct acpi_pci_id *, u32, u64 *, u32);
    acpi_status (*write_pci)(void *, struct acpi_pci_id *, u32, u64, u32);
    u64 (*timer)(void *);
    acpi_status (*signal)(void *, u32, void *);
    void (*log)(void *, const char *, u64);
    void (*flush_cache)(void *);
    /* Close work admission, mask/synchronize SCI/OpRegion callbacks, then drain.
     * On failure ownership is permanently quarantined, never freed/reused. */
    acpi_status (*quiesce)(void *);
    void (*destroy)(void *);
    void (*fatal)(void *, acpi_status); /* must not return */
};
#define STELA_ACPI_FULL_CAPABILITIES 15ull /* SCI, deferred work, regions, IRQ-safe allocation */
acpi_status stela_acpi_start(const struct stela_acpi_services *, u8);
acpi_status stela_acpi_stop(void);
acpi_status stela_acpi_evaluate(acpi_handle, const char *, union acpi_object *, u32, struct acpi_buffer *);
acpi_status stela_acpi_walk(const char *, acpi_walk_callback, void *);
u64 stela_acpi_layout(u32);
acpi_status stela_acpi_guard_enter(void **, u64 *);
void stela_acpi_guard_leave(void *);
u8 stela_acpi_namespace_valid(void);
acpi_status stela_acpi_bind_node(acpi_handle, u64);
#endif
