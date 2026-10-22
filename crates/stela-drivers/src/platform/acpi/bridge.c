/* SPDX-License-Identifier: MIT */
#include "bridge.h"
#include "accommon.h"
static struct stela_acpi_services services;
static u8 active;
static u8 hardware_enabled;
static u8 core_started;
static void *allocation_lock;
struct allocation { struct allocation *previous, *next; u64 reserved[2]; };
static struct allocation *allocations;
/* These guards participate in ACPICA's actual table-deletion reader/writer lock.
 * They never hold the interpreter mutex. UNLOAD invalidates the whole facade;
 * native driver rebinding after deletion is not implemented. */
struct namespace_guard {
    struct namespace_guard *next;
    u64 thread;
    u8 reader;
};
static struct namespace_guard *namespace_guards;
static u8 namespace_invalid;
static u64 namespace_epoch;
u8 stela_acpi_namespace_valid(void) {
    return active && !__atomic_load_n(&namespace_invalid, __ATOMIC_ACQUIRE);
}
acpi_status stela_acpi_guard_enter(void **out, u64 *epoch) {
    if (!stela_acpi_namespace_valid()) return AE_SUPPORT;
    acpi_status status = acpi_ut_acquire_read_lock(&acpi_gbl_namespace_rw_lock);
    if (ACPI_FAILURE(status)) return status;
    struct namespace_guard *guard = acpi_os_allocate(sizeof(*guard));
    if (!guard) {
        (void)acpi_ut_release_read_lock(&acpi_gbl_namespace_rw_lock);
        return AE_NO_MEMORY;
    }
    guard->thread = services.thread_id(services.context);
    guard->reader = 1;
    u64 flags = services.acquire_lock(services.context, allocation_lock);
    guard->next = namespace_guards;
    namespace_guards = guard;
    *epoch = __atomic_load_n(&namespace_epoch, __ATOMIC_ACQUIRE);
    services.release_lock(services.context, allocation_lock, flags);
    *out = guard;
    if (!stela_acpi_namespace_valid()) {
        stela_acpi_guard_leave(guard);
        *out = 0;
        return AE_SUPPORT;
    }
    return AE_OK;
}
void stela_acpi_guard_leave(void *raw) {
    struct namespace_guard *guard = raw;
    u64 flags = services.acquire_lock(services.context, allocation_lock);
    struct namespace_guard **link = &namespace_guards;
    while (*link && *link != guard) link = &(*link)->next;
    if (*link) *link = guard->next;
    u8 reader = guard->reader;
    guard->reader = 0;
    services.release_lock(services.context, allocation_lock, flags);
    if (reader) (void)acpi_ut_release_read_lock(&acpi_gbl_namespace_rw_lock);
    acpi_os_free(guard);
}
static acpi_status namespace_table_event(u32 event, void *table, void *context) {
    (void)table; (void)context;
    if (event == ACPI_TABLE_EVENT_LOAD) {
        __atomic_fetch_add(&namespace_epoch, 1, __ATOMIC_ACQ_REL);
        return AE_OK;
    }
    if (event != ACPI_TABLE_EVENT_UNLOAD) return AE_OK;
    /* tb_unload_table invokes this BEFORE namespace deletion. Native callers
     * must enter table deletion outside active interpreter frames/callbacks.
     * The pinned core rejects AML Unload; Load returns an integer, not a DDB
     * handle. Stop new facade readers and release this thread's read leases
     * before the core takes its namespace writer lock. Other readers remain
     * protected until their calls finish; the unchanged core waits for them. */
    __atomic_store_n(&namespace_invalid, 1, __ATOMIC_RELEASE);
    __atomic_fetch_add(&namespace_epoch, 1, __ATOMIC_ACQ_REL);
    u64 thread = services.thread_id(services.context);
    u32 released = 0;
    u64 flags = services.acquire_lock(services.context, allocation_lock);
    for (struct namespace_guard *guard = namespace_guards; guard; guard = guard->next) {
        if (guard->thread == thread && guard->reader) {
            guard->reader = 0;
            ++released;
        }
    }
    services.release_lock(services.context, allocation_lock, flags);
    while (released--) (void)acpi_ut_release_read_lock(&acpi_gbl_namespace_rw_lock);
    /* Quiesce must close admission, synchronize producers and other running work,
     * and drain queued work, excluding the current callback itself. It never
     * destroys services. A table-handler return cannot veto upstream Unload. */
    acpi_status status = services.quiesce(services.context);
    if (ACPI_FAILURE(status)) {
        services.fatal(services.context, status);
        __builtin_trap(); /* Fail closed even if an invalid native provider returns. */
    }
    return AE_OK;
}
acpi_status stela_acpi_bind_node(acpi_handle candidate, u64 epoch) {
    if (!stela_acpi_namespace_valid() || epoch != __atomic_load_n(&namespace_epoch, __ATOMIC_ACQUIRE)) return AE_SUPPORT;
    if (candidate == ACPI_ROOT_OBJECT) return AE_OK;
    acpi_status status = acpi_ut_acquire_mutex(ACPI_MTX_NAMESPACE);
    if (ACPI_FAILURE(status)) return status;
    /* Compare pointer identity only. Never validate/dereference an untrusted
     * returned reference until finding the node in the currently locked tree.
     * Temporary method nodes and their descendants cannot outlive a method. */
    struct acpi_namespace_node *node = acpi_gbl_root_node;
    status = AE_SUPPORT;
    while (node) {
        if (!(node->flags & ANOBJ_TEMPORARY)) {
            if ((acpi_handle)node == candidate) { status = AE_OK; break; }
            if (node->child) { node = node->child; continue; }
        }
        while (node != acpi_gbl_root_node && !node->peer) node = node->parent;
        if (node == acpi_gbl_root_node) break;
        node = node->peer;
    }
    (void)acpi_ut_release_mutex(ACPI_MTX_NAMESPACE);
    return status;
}
_Static_assert(sizeof(struct allocation) == 32, "allocator alignment");
_Static_assert(sizeof(struct stela_acpi_services) == 280, "OSL vtable ABI");
_Static_assert(ACPI_OFFSET(struct stela_acpi_services, destroy) == 264, "OSL callback ABI");
_Static_assert(sizeof(union acpi_object) == 24, "ACPICA object ABI");
_Static_assert(sizeof(struct acpi_buffer) == 16, "ACPICA buffer ABI");
_Static_assert(sizeof(struct acpi_pci_id) == 8, "ACPICA PCI ABI");
_Static_assert(sizeof(acpi_cpu_flags) == 8, "ACPICA IRQ flags ABI");
#define CTX services.context
acpi_status stela_acpi_start(const struct stela_acpi_services *input, u8 hardware) {
    if (active) return AE_ALREADY_EXISTS;
    if (!input || !input->root) return AE_BAD_PARAMETER;
    if (hardware && (input->capabilities & STELA_ACPI_FULL_CAPABILITIES) != STELA_ACPI_FULL_CAPABILITIES) return AE_SUPPORT;
    memcpy(&services, input, sizeof(services));
    active = 1;
    hardware_enabled = 0;
    core_started = 0;
    allocations = 0;
    namespace_guards = 0;
    __atomic_store_n(&namespace_invalid, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&namespace_epoch, 1, __ATOMIC_RELEASE);
    allocation_lock = 0;
    acpi_status status = services.create_lock(CTX, &allocation_lock);
    if (ACPI_FAILURE(status)) return status;
    core_started = 1;
    status = acpi_initialize_subsystem();
    if (ACPI_FAILURE(status)) return status;
    status = acpi_install_table_handler(namespace_table_event, 0);
    if (ACPI_FAILURE(status)) return status;
    status = acpi_initialize_tables(0, 32, TRUE);
    if (ACPI_FAILURE(status)) return status;
    status = acpi_load_tables();
    if (ACPI_FAILURE(status)) return status;
    u32 flags = hardware ? 0 : ACPI_NO_FACS_INIT | ACPI_NO_ACPI_ENABLE | ACPI_NO_HARDWARE_INIT | ACPI_NO_EVENT_INIT | ACPI_NO_HANDLER_INIT;
    status = acpi_enable_subsystem(flags);
    if (ACPI_FAILURE(status)) return status;
    status = acpi_initialize_objects(hardware ? 0 : ACPI_NO_DEVICE_INIT);
    if (ACPI_SUCCESS(status) && hardware) hardware_enabled = 1;
    if (ACPI_SUCCESS(status) && !stela_acpi_namespace_valid()) return AE_SUPPORT;
    return status;
}
acpi_status stela_acpi_enable_hardware(void) {
    if (!active) return AE_NOT_EXIST;
    if (hardware_enabled) return AE_ALREADY_EXISTS;
    if ((services.capabilities & STELA_ACPI_FULL_CAPABILITIES) != STELA_ACPI_FULL_CAPABILITIES) return AE_SUPPORT;
    hardware_enabled = 1; /* A failed activation cannot safely be retried in place. */
    acpi_status status = acpi_enable_subsystem(0);
    if (ACPI_FAILURE(status)) return status;
    status = acpi_initialize_objects(0);
    if (ACPI_SUCCESS(status)) hardware_enabled = 1;
    return status;
}
acpi_status stela_acpi_stop(void) {
    if (!active) return AE_NOT_EXIST;
    acpi_status status = services.quiesce(CTX);
    if (ACPI_FAILURE(status)) return status; /* Keep all C/provider state alive. */
    if (core_started) {
        status = acpi_terminate();
        if (ACPI_FAILURE(status)) return status;
    }
    /* The OSL owns every allocation, including objects retained by the core on
     * partial/error paths. Quiescence + termination makes arena reclamation safe. */
    while (allocations) {
        struct allocation *next = allocations->next;
        services.free(CTX, allocations);
        allocations = next;
    }
    if (allocation_lock) services.delete_lock(CTX, allocation_lock);
    allocation_lock = 0;
    services.destroy(CTX);
    memset(&services, 0, sizeof(services));
    active = 0;
    return AE_OK;
}
acpi_status stela_acpi_evaluate(acpi_handle handle, const char *path, union acpi_object *args, u32 count, struct acpi_buffer *result) {
    struct acpi_object_list list = {count, args};
    return acpi_evaluate_object(handle, (char *)path, count ? &list : 0, result);
}
acpi_status stela_acpi_walk(const char *hid, acpi_walk_callback callback, void *context) {
    return acpi_get_devices((char *)hid, callback, context, 0);
}
u64 stela_acpi_layout(u32 field) {
    switch(field) {
    case 0: return sizeof(struct stela_acpi_services);
    case 1: return sizeof(union acpi_object);
    case 2: return sizeof(struct acpi_buffer);
    case 3: return sizeof(struct acpi_pci_id);
    case 4: return ACPI_OFFSET(union acpi_object, integer.value);
    case 5: return ACPI_OFFSET(union acpi_object, buffer.pointer);
    case 6: return ACPI_OFFSET(struct stela_acpi_services, destroy);
    case 7: return ACPI_OFFSET(struct acpi_buffer, pointer);
    case 8: return sizeof(acpi_cpu_flags);
    case 9: return ACPI_OFFSET(struct stela_acpi_services, fatal);
    default: return ~0ull;
    }
}
acpi_status acpi_os_initialize(void) { return AE_OK; } /* Provider ownership was transferred by start. */
acpi_status acpi_os_terminate(void) { return AE_OK; } /* Destroy follows quiescence + core termination. */
acpi_physical_address acpi_os_get_root_pointer(void) { return services.root; }
acpi_status acpi_os_predefined_override(const struct acpi_predefined_names *p, acpi_string *out) {
    if (!p || !out) return AE_BAD_PARAMETER; *out = 0; return AE_OK;
}
acpi_status acpi_os_table_override(struct acpi_table_header *p, struct acpi_table_header **out) {
    if (!p || !out) return AE_BAD_PARAMETER; *out = 0; return AE_OK;
}
acpi_status acpi_os_physical_table_override(struct acpi_table_header *p, acpi_physical_address *out, u32 *length) {
    if (!p || !out || !length) return AE_BAD_PARAMETER; *out = 0; *length = 0; return AE_OK;
}
void *acpi_os_allocate(acpi_size size) {
    if (size > ~0ull - sizeof(struct allocation)) return 0;
    struct allocation *entry = services.allocate(CTX, size + sizeof(struct allocation));
    if (!entry) return 0;
    u64 flags = services.acquire_lock(CTX, allocation_lock);
    entry->previous = 0;
    entry->next = allocations;
    if (allocations) allocations->previous = entry;
    allocations = entry;
    services.release_lock(CTX, allocation_lock, flags);
    return entry + 1;
}
void acpi_os_free(void *p) {
    if (!p) return;
    struct allocation *entry = (struct allocation *)p - 1;
    u64 flags = services.acquire_lock(CTX, allocation_lock);
    if (entry->previous) entry->previous->next = entry->next;
    else allocations = entry->next;
    if (entry->next) entry->next->previous = entry->previous;
    services.release_lock(CTX, allocation_lock, flags);
    services.free(CTX, entry);
}
void *acpi_os_map_memory(acpi_physical_address p, acpi_size n) { return services.map(CTX, p, n); }
void acpi_os_unmap_memory(void *p, acpi_size n) { services.unmap(CTX, p, n); }
acpi_status acpi_os_create_lock(acpi_spinlock *out) { return services.create_lock(CTX, out); }
void acpi_os_delete_lock(acpi_spinlock lock) { services.delete_lock(CTX, lock); }
acpi_cpu_flags acpi_os_acquire_lock(acpi_spinlock lock) { return services.acquire_lock(CTX, lock); }
void acpi_os_release_lock(acpi_spinlock lock, acpi_cpu_flags flags) { services.release_lock(CTX, lock, flags); }
acpi_status acpi_os_create_semaphore(u32 max, u32 initial, acpi_semaphore *out) { return services.create_semaphore(CTX, max, initial, out); }
acpi_status acpi_os_delete_semaphore(acpi_semaphore s) { return services.delete_semaphore(CTX, s); }
acpi_status acpi_os_wait_semaphore(acpi_semaphore s, u32 n, u16 timeout) { return services.wait_semaphore(CTX, s, n, timeout); }
acpi_status acpi_os_signal_semaphore(acpi_semaphore s, u32 n) { return services.signal_semaphore(CTX, s, n); }
acpi_status acpi_os_install_interrupt_handler(u32 irq, acpi_osd_handler handler, void *context) { return services.install_interrupt(CTX, irq, handler, context); }
acpi_status acpi_os_remove_interrupt_handler(u32 irq, acpi_osd_handler handler) { return services.remove_interrupt(CTX, irq, handler); }
acpi_thread_id acpi_os_get_thread_id(void) { return services.thread_id(CTX); }
acpi_status acpi_os_execute(acpi_execute_type type, acpi_osd_exec_callback callback, void *context) { return services.execute(CTX, type, callback, context); }
void acpi_os_wait_events_complete(void) { services.drain_work(CTX); }
void acpi_os_sleep(u64 ms) { services.sleep(CTX, ms); }
void acpi_os_stall(u32 us) { services.stall(CTX, us); }
acpi_status acpi_os_read_port(acpi_io_address port, u32 *value, u32 width) { return services.read_port(CTX, port, value, width); }
acpi_status acpi_os_write_port(acpi_io_address port, u32 value, u32 width) { return services.write_port(CTX, port, value, width); }
acpi_status acpi_os_read_memory(acpi_physical_address p, u64 *value, u32 width) { return services.read_memory(CTX, p, value, width); }
acpi_status acpi_os_write_memory(acpi_physical_address p, u64 value, u32 width) { return services.write_memory(CTX, p, value, width); }
acpi_status acpi_os_read_pci_configuration(struct acpi_pci_id *id, u32 reg, u64 *value, u32 width) { return services.read_pci(CTX, id, reg, value, width); }
acpi_status acpi_os_write_pci_configuration(struct acpi_pci_id *id, u32 reg, u64 value, u32 width) { return services.write_pci(CTX, id, reg, value, width); }
u64 acpi_os_get_timer(void) { return services.timer(CTX); }
acpi_status acpi_os_signal(u32 kind, void *info) { return services.signal(CTX, kind, info); }
acpi_status acpi_os_enter_sleep(u8 state, u32 a, u32 b) { (void)state; (void)a; (void)b; return AE_SUPPORT; } /* No public system-sleep API yet. */
void stela_acpi_flush_cpu_cache(void) { services.flush_cache(CTX); }
void acpi_os_vprintf(const char *format, va_list args) {
    char buffer[512];
    int n = vsnprintf(buffer, sizeof(buffer), format, args);
    if (n > 0) services.log(CTX, buffer, (u64)n < sizeof(buffer) ? (u64)n : sizeof(buffer)-1);
}
void ACPI_INTERNAL_VAR_XFACE acpi_os_printf(const char *format, ...) {
    va_list args; va_start(args, format); acpi_os_vprintf(format, args); va_end(args);
}
