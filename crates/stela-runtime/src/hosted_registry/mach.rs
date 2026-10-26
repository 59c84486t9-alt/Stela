//! Shared Mach trap and MIG dispatcher selection and requirement metadata.

pub(crate) mod server {
    /// The extra reference a hosted thread's port name carries.
    pub(crate) const THREAD_PORT_LIMIT: &str =
        "the new thread's port name also carries its host thread library's reference";

    /// What setting the task's exception ports does not reach.
    pub(crate) const EXCEPTION_PORT_LIMITS: &str = "a guest exception delivered with EXCEPTION_DEFAULT or \
         EXCEPTION_STATE_IDENTITY without developer mode (whose read ports are not served) or with \
         MACH_EXCEPTION_BACKTRACE_PREFERRED stops the run, and delivery carries no voucher; the host \
         kernel's EXC_CRASH, EXC_RESOURCE and EXC_GUARD reports go to the ports the process \
         inherited; a fork, exec or spawn after a change stops the run; a platform-restricted task's \
         policy violation stops the run";

    /// What setting a thread's exception ports does not reach.
    pub(crate) const THREAD_EXCEPTION_PORT_LIMITS: &str = "a guest exception delivered with EXCEPTION_DEFAULT \
         or EXCEPTION_STATE_IDENTITY without developer mode (whose read ports are not served) or with \
         MACH_EXCEPTION_BACKTRACE_PREFERRED stops the run, and delivery carries no voucher; the host \
         kernel's EXC_CRASH, EXC_RESOURCE and EXC_GUARD reports pass the thread's ports for the \
         task's; a platform-restricted task's policy violation stops the run";

    pub(crate) const CPU_ACCOUNTING_LIMIT: &str = "native logical CPU ticks are not assigned physical-core \
        accounting for shared execution; HOST_CPU_LOAD_INFO remains unsupported without a qualified mapping";

    pub(crate) const HARDENED_EXCEPTION_LIMITS: &str = "registration and adoption use actual native kernel port \
        resources with ARM flavors kept separately; a native resource-policy divergence or guest \
        policy requiring fatal guard delivery stops the run; delivery retains the exception family's \
        read-port, voucher, backtrace and host-report limits, and changing a reply's general-state \
        encoding is refused; header admission requires COPY_SEND destination, MAKE_SEND_ONCE or absent \
        reply and no voucher; truncated/non-port complex descriptor layouts stop before admission; \
        fork, exec and spawn after registration are refused";

    /// Which kernel object a request names.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Object {
        Task,
        Thread,
        Host,
        /// The default processor set's name port (`processor_set_default`).
        ProcessorSet,
    }

    /// The routines `serve` answers or forwards, by object, with the named
    /// limit of a routine served only in part (other arguments stop the run
    /// naming them).
    pub(crate) const SERVED: &[(Object, &str, Option<&str>)] = &[
        (Object::Host, "host_info", None),
        (Object::Host, "host_kernel_version", None),
        (Object::Host, "_host_page_size", None),
        (Object::Host, "mach_memory_object_memory_entry", None),
        (Object::Host, "mach_memory_object_memory_entry_64", None),
        (Object::Host, "host_request_notification", None),
        (Object::Host, "_kernelrpc_host_create_mach_voucher", None),
        (Object::Host, "kmod_get_info", None),
        (Object::Host, "host_virtual_physical_table_info", None),
        (Object::Host, "host_lockgroup_info", None),
        (Object::Host, "mach_zone_info", None),
        (Object::Host, "mach_zone_info_for_zone", None),
        (Object::Host, "mach_memory_info", None),
        (Object::Host, "mach_memory_info_redacted", None),
        (
            Object::Host,
            "host_set_atm_diagnostic_flag",
            Some(
                "a caller entitled to set the machine's diagnostic flag stops the run: the hosted \
                 runtime holds no entitlement to set the host machine's",
            ),
        ),
        (Object::Host, "host_set_multiuser_config_flags", None),
        (Object::Host, "host_get_boot_info", None),
        (Object::Host, "host_reboot", None),
        (Object::Host, "host_priv_statistics", None),
        (Object::Host, "host_default_memory_manager", None),
        (Object::Host, "vm_wire", None),
        (Object::Host, "thread_wire", None),
        (Object::Host, "host_set_special_port", None),
        (Object::Host, "host_set_exception_ports", None),
        (Object::Host, "host_get_exception_ports", None),
        (Object::Host, "host_swap_exception_ports", None),
        (Object::Host, "mach_vm_wire_external", None),
        (Object::Host, "host_set_UNDServer", None),
        (Object::Host, "host_get_UNDServer", None),
        (Object::Host, "kext_request", None),
        (
            Object::Task,
            "_kernelrpc_mach_vm_map_external",
            Some("a memory object is mapped in host pages over a reserved guest range"),
        ),
        (
            Object::Task,
            "task_get_special_port_from_user",
            Some("every port but the name, inspect and read ports"),
        ),
        (Object::Task, "task_set_special_port_from_user", None),
        (
            Object::Task,
            "_mach_make_memory_entry",
            Some(
                "a range in partial guest pages derived from a parent entry, empty, or a data \
                 address 4 KiB or more into its guest page stops the run",
            ),
        ),
        (
            Object::Host,
            "host_statistics_from_user",
            Some(CPU_ACCOUNTING_LIMIT),
        ),
        (
            Object::Host,
            "host_statistics64_from_user",
            Some(CPU_ACCOUNTING_LIMIT),
        ),
        (Object::Host, "host_get_special_port", None),
        (
            Object::Host,
            "host_processor_info",
            Some(
                "the arm64 kernel's exception counters (PROCESSOR_CPU_STAT, PROCESSOR_CPU_STAT64) \
                 stop the run: the x86 host kernel keeps none, and only the system-mode arm64 \
                 kernel takes those exceptions; shared execution also refuses native logical tick \
                 tables without a qualified physical-core attribution",
            ),
        ),
        (Object::Host, "processor_set_default", None),
        (Object::Host, "host_processor_sets", None),
        (Object::Host, "host_processor_set_priv", None),
        (Object::Host, "host_processors", None),
        (Object::ProcessorSet, "processor_set_info", None),
        (Object::ProcessorSet, "processor_set_statistics", None),
        (Object::ProcessorSet, "processor_set_tasks", None),
        (
            Object::ProcessorSet,
            "processor_set_tasks_with_flavor",
            None,
        ),
        (
            Object::Host,
            "host_get_io_main",
            Some("the IOKit main port is the host's: its registry describes the x86 host"),
        ),
        (Object::Thread, "thread_suspend", None),
        (
            Object::Thread,
            "thread_suspend2",
            Some(
                "the token's name also holds the hosted kernel's receive right of the resume port",
            ),
        ),
        (Object::Thread, "thread_resume2", None),
        (Object::Thread, "thread_resume", None),
        (Object::Thread, "thread_get_state_to_user", None),
        (
            Object::Thread,
            "thread_set_state_from_user",
            Some("a debug state enabling a breakpoint, watchpoint or single step stops the run"),
        ),
        (Object::Thread, "act_get_state_to_user", None),
        (
            Object::Thread,
            "act_set_state_from_user",
            Some("a debug state enabling a breakpoint, watchpoint or single step stops the run"),
        ),
        (Object::Task, "task_create_identity_token", None),
        (Object::Task, "task_threads_from_user", None),
        (Object::Task, "task_policy_set", None),
        (Object::Task, "task_policy_get", None),
        (Object::Task, "_kernelrpc_mach_ports_register3", None),
        (Object::Task, "_kernelrpc_mach_ports_lookup3", None),
        (Object::Task, "task_info_from_user", None),
        (Object::Task, "task_restartable_ranges_register", None),
        (Object::Task, "task_restartable_ranges_synchronize", None),
        (
            Object::Task,
            "mach_vm_deferred_reclamation_buffer_allocate",
            None,
        ),
        (
            Object::Task,
            "mach_vm_deferred_reclamation_buffer_flush",
            None,
        ),
        (
            Object::Task,
            "mach_vm_deferred_reclamation_buffer_resize",
            None,
        ),
        (
            Object::Task,
            "mach_vm_deferred_reclamation_buffer_query",
            None,
        ),
        (Object::Task, "task_terminate", None),
        (Object::Task, "task_set_info", None),
        (Object::Task, "task_suspend", None),
        (Object::Task, "task_resume", None),
        (Object::Task, "task_suspend2_mig", None),
        (Object::Task, "task_resume2_mig", None),
        (Object::Task, "task_get_mach_voucher", None),
        (Object::Task, "task_set_mach_voucher", None),
        (Object::Task, "task_swap_mach_voucher", None),
        (Object::Task, "task_register_dyld_image_infos", None),
        (Object::Task, "task_unregister_dyld_image_infos", None),
        (Object::Task, "task_get_dyld_image_infos", None),
        (
            Object::Task,
            "task_register_dyld_shared_cache_image_info",
            None,
        ),
        (Object::Task, "task_register_dyld_set_dyld_state", None),
        (Object::Task, "task_register_dyld_get_process_state", None),
        (Object::Task, "task_get_exc_guard_behavior", None),
        (Object::Task, "task_set_exc_guard_behavior", None),
        (Object::Task, "_kernelrpc_mach_task_is_self", None),
        (Object::Task, "task_dyld_process_info_notify_register", None),
        (
            Object::Task,
            "task_dyld_process_info_notify_deregister",
            None,
        ),
        (Object::Task, "task_identity_token_get_task_port", None),
        (Object::Task, "task_test_sync_upcall", None),
        (Object::Task, "task_test_async_upcall_propagation", None),
        (Object::Task, "task_set_corpse_forking_behavior", None),
        (Object::Task, "task_purgable_info", None),
        (Object::Task, "task_set_phys_footprint_limit", None),
        (Object::Task, "task_get_state", None),
        (
            Object::Task,
            "task_set_state",
            Some(
                "a debug state enabling a breakpoint, watchpoint or single step for new threads \
                 stops the run",
            ),
        ),
        (Object::Task, "task_inspect", None),
        (
            Object::Task,
            "thread_create_from_user",
            Some(THREAD_PORT_LIMIT),
        ),
        (
            Object::Task,
            "thread_create_running_from_user",
            Some(THREAD_PORT_LIMIT),
        ),
        (
            Object::Task,
            "task_set_exception_ports",
            Some(EXCEPTION_PORT_LIMITS),
        ),
        (
            Object::Task,
            "task_swap_exception_ports",
            Some(EXCEPTION_PORT_LIMITS),
        ),
        (Object::Task, "task_get_exception_ports_from_user", None),
        (Object::Task, "task_get_exception_ports_info", None),
        (
            Object::Task,
            "task_register_hardened_exception_handler",
            Some(HARDENED_EXCEPTION_LIMITS),
        ),
        (
            Object::Thread,
            "thread_terminate_from_user",
            Some(
                "a thread waiting in a call the hosted kernel models finishes the call before it \
                 ends",
            ),
        ),
        (
            Object::Thread,
            "thread_abort",
            Some("a wait in a call the hosted kernel models is not interrupted"),
        ),
        (
            Object::Thread,
            "thread_abort_safely",
            Some("a wait in a call the hosted kernel models is not interrupted"),
        ),
        (Object::Thread, "thread_depress_abort_from_user", None),
        (
            Object::Thread,
            "thread_get_special_port_from_user",
            Some("the kernel port"),
        ),
        (Object::Thread, "thread_set_special_port", None),
        (Object::Thread, "thread_info", None),
        (
            Object::Thread,
            "thread_set_exception_ports",
            Some(THREAD_EXCEPTION_PORT_LIMITS),
        ),
        (
            Object::Thread,
            "thread_swap_exception_ports",
            Some(THREAD_EXCEPTION_PORT_LIMITS),
        ),
        (Object::Thread, "thread_get_exception_ports_from_user", None),
        (Object::Thread, "thread_get_exception_ports_info", None),
        (
            Object::Thread,
            "thread_adopt_exception_handler",
            Some(HARDENED_EXCEPTION_LIMITS),
        ),
        (Object::Thread, "_kernelrpc_thread_policy", None),
        (Object::Thread, "_kernelrpc_thread_policy_set", None),
        (Object::Thread, "thread_policy_get", None),
        (Object::Thread, "_kernelrpc_thread_set_policy", None),
        (Object::Thread, "thread_get_mach_voucher", None),
        (Object::Thread, "thread_set_mach_voucher", None),
        (Object::Thread, "thread_swap_mach_voucher", None),
        (Object::Thread, "thread_convert_thread_state", None),
    ];

    /// Routines of this process's kernel objects the hosted kernel refuses,
    /// with the reason.
    pub(crate) const REFUSED: &[(Object, &str, &str)] = &[
        (
            Object::Task,
            "task_generate_corpse",
            "the host kernel's corpse would hold the x86 host's thread states and the hosted \
             runtime's own memory",
        ),
        (
            Object::Task,
            "task_map_corpse_info",
            "a corpse's crash data is the host kernel's, describing an x86 process, mapped in 4 KiB \
             host pages",
        ),
        (
            Object::Task,
            "task_map_corpse_info_64",
            "a corpse's crash data is the host kernel's, describing an x86 process, mapped in 4 KiB \
             host pages",
        ),
        (
            Object::Task,
            "task_map_kcdata_object_64",
            "a kcdata object is the host kernel's report, mapped in 4 KiB host pages",
        ),
    ];

    /// The reason routine `routine` of `object` is refused, if it is named.
    pub(crate) fn refused(object: Object, routine: &str) -> Option<&'static str> {
        REFUSED
            .iter()
            .find(|&&(refused, name, _)| refused == object && name == routine)
            .map(|&(_, _, reason)| reason)
    }

    /// Why routine `routine` of `object` stops the run.
    pub(crate) fn refusal(object: Object, routine: &str) -> &'static str {
        refused(object, routine).unwrap_or("this process's kernel object does not serve it")
    }
}

pub(crate) mod message {
    /// Subsystems whose requests act only on IPC state, which this task shares
    /// with the host task, and are forwarded.
    pub(crate) const IPC_ONLY: &[&str] = &["mach_port"];

    /// Kernel-object routines whose answer is the same for an arm64 process:
    /// forwarded unchanged. `host_get_clock_service` names a clock whose
    /// `mach_timespec_t` time is the host's time base in either ABI, and
    /// requests to the clock port it returns are the host kernel's.
    /// `semaphore_create` and `semaphore_destroy` make and drop this task's own
    /// semaphores, which the forwarded semaphore traps then use.
    pub(crate) const FORWARDED_ROUTINES: &[(&str, &str)] = &[
        ("mach_host", "host_get_clock_service"),
        ("task", "semaphore_create"),
        ("task", "semaphore_destroy"),
    ];
}

pub(crate) mod vm {
    /// The limit of a routine over guest pages the host may map in parts.
    pub(crate) const SPLIT_PAGE: &str =
        "a range over a guest page the host maps in parts of differing protections is refused";

    /// The routines `serve` answers or forwards, with the named limit of a
    /// routine served only in part.
    pub(crate) const SERVED: &[(&str, Option<&str>)] = &[
        (
            "_kernelrpc_mach_vm_remap_external",
            Some(
                "from this task's own address space; a source over a guest page the host maps in \
                 parts of differing protections is refused",
            ),
        ),
        (
            "_kernelrpc_mach_vm_remap_new_external",
            Some(
                "from this task's own address space; a source over a guest page the host maps in \
                 parts of differing protections is refused",
            ),
        ),
        (
            "_kernelrpc_mach_vm_allocate_external",
            Some("VM_FLAGS_TPRO allocations are refused"),
        ),
        ("_kernelrpc_mach_vm_deallocate_external", None),
        (
            "_kernelrpc_mach_vm_reallocate",
            Some(
                "a source over a guest page the host maps in parts of differing protections is \
                 refused; JIT and TPRO source entries are not told apart from others",
            ),
        ),
        ("_kernelrpc_mach_vm_protect", None),
        ("mach_vm_inherit", None),
        (
            "mach_vm_write",
            Some(
                "a destination over a guest page the host maps in parts of differing protections, \
                 or unreadable out-of-line data, is refused",
            ),
        ),
        (
            "_kernelrpc_mach_vm_read",
            Some(
                "a range over a guest page the host maps in parts of differing protections is \
                 refused; the data's offset in its guest page is its offset in its host page, and \
                 the rest of its guest pages is zero",
            ),
        ),
        ("mach_vm_read_list", Some(SPLIT_PAGE)),
        ("mach_vm_copy", Some(SPLIT_PAGE)),
        ("mach_vm_read_overwrite", Some(SPLIT_PAGE)),
        (
            "mach_vm_msync",
            Some("VM_SYNC_KILLPAGES and VM_SYNC_REUSABLEPAGES over the shared region are refused"),
        ),
        (
            "mach_vm_behavior_set",
            Some("VM_BEHAVIOR_FREE and the reusable behaviors over the shared region are refused"),
        ),
        (
            "mach_vm_region",
            Some(
                "the basic flavors of a region outside the shared region, host regions meeting \
                 inside a guest page merged into one entry; the x86 runtime's own mappings are \
                 regions of this task",
            ),
        ),
        (
            "mach_vm_region_recurse",
            Some(
                "regions in whole guest pages outside the shared region, host regions meeting \
                 inside a guest page merged into one entry; page counts are the host's restated in \
                 guest pages, rounded up; the x86 runtime's own mappings are regions of this task",
            ),
        ),
        (
            "mach_vm_page_query",
            Some(
                "a guest page's disposition is the union of its host pages', its reference count \
                 their largest",
            ),
        ),
        (
            "mach_vm_page_info",
            Some(
                "a guest page's disposition is the union of its host pages', its reference count \
                 their largest",
            ),
        ),
        (
            "mach_vm_page_range_query",
            Some("a guest page's disposition is the union of its host pages'"),
        ),
        ("_kernelrpc_mach_vm_purgable_control_external", None),
        ("mach_vm_machine_attribute", None),
        ("mach_vm_range_create", None),
        ("_kernelrpc_mach_vm_update_pointers_with_remote_tags", None),
    ];
}

/// Traps forwarded unchanged.
pub(crate) const FORWARDED: &[&str] = &[
    "_kernelrpc_mach_vm_purgable_control_trap",
    "task_dyld_process_info_notify_get_trap",
    "_kernelrpc_mach_port_allocate_trap",
    "_kernelrpc_mach_port_deallocate_trap",
    "_kernelrpc_mach_port_mod_refs_trap",
    "_kernelrpc_mach_port_move_member_trap",
    "_kernelrpc_mach_port_insert_right_trap",
    "_kernelrpc_mach_port_insert_member_trap",
    "_kernelrpc_mach_port_extract_member_trap",
    "_kernelrpc_mach_port_construct_trap",
    "_kernelrpc_mach_port_destruct_trap",
    "_kernelrpc_mach_port_get_attributes_trap",
    "_kernelrpc_mach_port_guard_trap",
    "_kernelrpc_mach_port_unguard_trap",
    "_kernelrpc_mach_port_type_trap",
    "_kernelrpc_mach_port_request_notification_trap",
    "mach_reply_port",
    "thread_self_trap",
    "task_self_trap",
    "host_self_trap",
    "semaphore_signal_trap",
    "semaphore_signal_all_trap",
    "semaphore_signal_thread_trap",
    "semaphore_wait_trap",
    "semaphore_wait_signal_trap",
    "semaphore_timedwait_trap",
    "semaphore_timedwait_signal_trap",
    "mach_generate_activity_id",
    "task_name_for_pid",
    "task_for_pid",
    "pid_for_task",
    "thread_get_special_reply_port",
    "swtch_pri",
    "swtch",
    "thread_switch",
    "clock_sleep_trap",
    "host_create_mach_voucher_trap",
    "mach_voucher_extract_attr_recipe_trap",
    "mk_timer_create_trap",
    "mk_timer_destroy_trap",
    "debug_control_port_for_pid",
    "macx_triggers",
    "iokit_user_client_trap",
];

/// Traps the hosted kernel models: virtual memory in guest pages, the
/// guest's timebase and its deadlines, and messages to kernel objects.
pub(crate) const MODELED: &[&str] = &[
    "_kernelrpc_mach_vm_allocate_trap",
    "_kernelrpc_mach_vm_map_trap",
    "_kernelrpc_mach_vm_deallocate_trap",
    "_kernelrpc_mach_vm_protect_trap",
    "mach_vm_reclaim_update_kernel_accounting_trap",
    "mach_timebase_info_trap",
    "mach_wait_until_trap",
    "mk_timer_arm_trap",
    "mk_timer_arm_leeway_trap",
    "mk_timer_cancel_trap",
    "mach_msg_trap",
    "mach_msg_overwrite_trap",
    "mach_msg2_trap",
    "macx_swapon",
    "macx_swapoff",
    "macx_backing_store_suspend",
    "macx_backing_store_recovery",
    "_exclaves_ctl_trap",
    "pfz_exit",
];

/// Traps the 26A434 kernel adds at indices the pinned catalog reserves
/// (`kern_invalid`), with their `libsystem_kernel` stub names.
pub(crate) const ADDITIONS: &[(u32, &str)] = &[(108, "thread_set_x86_64_compat")];

/// Traps serviced with a named limit.
pub(crate) const LIMITS: &[(&str, &str)] = &[
    (
        "mach_msg2_trap",
        "requests to this task's, its threads' and the host's kernel objects are served by \
         routine (the MIG rows); received trailers carry this process's audit token",
    ),
    (
        "mach_msg_trap",
        "requests to this task's, its threads' and the host's kernel objects are served by \
         routine (the MIG rows)",
    ),
    (
        "mach_msg_overwrite_trap",
        "requests to this task's, its threads' and the host's kernel objects are served by \
         routine (the MIG rows)",
    ),
];

/// Traps the hosted kernel refuses, with the reason.
pub(crate) const REFUSED: &[(&str, &str)] = &[];

/// The 26A434 trap at reserved index `index`, if any.
pub(crate) fn addition(index: u32) -> Option<&'static str> {
    ADDITIONS
        .iter()
        .find(|&&(entry, _)| entry == index)
        .map(|&(_, name)| name)
}

/// The kernel object a subsystem's requests address in this task: the
/// task port carries task, VM, restartable-range and port-space requests,
/// a thread port thread requests, the host port host requests, the
/// default processor set's name port processor-set requests.
pub(crate) fn object_of(subsystem: &str) -> Option<server::Object> {
    Some(match subsystem {
        "task" | "mach_vm" | "task_restartable" | "mach_port" => server::Object::Task,
        "thread_act" => server::Object::Thread,
        "mach_host" | "host_priv" => server::Object::Host,
        "processor_set" => server::Object::ProcessorSet,
        _ => return None,
    })
}

pub(crate) fn object_name(object: server::Object) -> &'static str {
    match object {
        server::Object::Task => "task",
        server::Object::Thread => "thread",
        server::Object::Host => "host",
        server::Object::ProcessorSet => "processor set",
    }
}

/// How a MIG request is serviced: to this process's kernel objects as the
/// message dispatcher routes it, to any other object forwarded. Processor
/// ports come only from the privileged host port (`host_processors`),
/// which an unprivileged process does not hold, so a processor request
/// reaches no processor, as on the arm64 kernel.
pub(crate) fn mig_service(
    subsystem: &str,
    routine: &str,
) -> (super::services::Service, Option<&'static str>) {
    use super::services::Service;
    let Some(object) = object_of(subsystem) else {
        return (Service::Forwarded { overlay: None }, None);
    };
    if message::IPC_ONLY.contains(&subsystem)
        || message::FORWARDED_ROUTINES.contains(&(subsystem, routine))
    {
        return (Service::Forwarded { overlay: None }, None);
    }
    let own_vm = (subsystem == "mach_vm")
        .then(|| vm::SERVED.iter().find(|&&(name, _)| name == routine))
        .flatten()
        .map(|&(_, limit)| limit);
    match server::SERVED
        .iter()
        .find(|&&(served, name, _)| served == object && name == routine)
        .map(|&(_, _, limit)| limit)
        .or(own_vm)
    {
        Some(limit) => (
            Service::Modeled {
                family: "kernel objects",
            },
            limit,
        ),
        None => (
            Service::Refused {
                reason: server::refusal(object, routine),
            },
            None,
        ),
    }
}

/// Whether the trap `name` is forwarded (`Some(true)`), modeled
/// (`Some(false)`) or refused (`None`).
pub(crate) fn forwarded(name: &str) -> Option<bool> {
    if FORWARDED.contains(&name) {
        Some(true)
    } else if MODELED.contains(&name) {
        Some(false)
    } else {
        None
    }
}
