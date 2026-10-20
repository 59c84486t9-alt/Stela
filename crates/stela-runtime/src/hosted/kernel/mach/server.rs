//! The kernel-object MIG routines the hosted kernel answers itself: those
//! whose answer describes the arm64 machine rather than the x86 host. Each
//! returns its reply body after the header (`NDR_record`, `RetCode`, then
//! the out arguments), as the routine's MIG server stub lays it out, or a
//! failing `RetCode` for the short `mig_reply_error_t`.
use super::super::{Kernel, control};
use super::reclaim;
use crate::hosted::threads::lock;
use crate::hosted::{
    hardware,
    memory::{self, Protection},
};
use anyhow::{Result, bail};

/// A request's body after its header.
pub(super) struct Request<'a> {
    pub(super) body: &'a [u8],
}

impl Request<'_> {
    pub(super) fn word(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.body.get(at..at + 4)?.try_into().ok()?,
        ))
    }

    /// MIG packs 64-bit arguments at 4-byte alignment.
    pub(super) fn double(&self, at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            self.body.get(at..at + 8)?.try_into().ok()?,
        ))
    }
}

/// A routine's outcome.
pub(super) enum Reply {
    /// The body after `RetCode` (`KERN_SUCCESS`).
    Success(Vec<u8>),
    /// A failing `RetCode`.
    Failure(u32),
    /// The host kernel's answer is the arm64 kernel's: forward the request.
    Forward,
    /// A complex reply (`MACH_MSGH_BITS_COMPLEX`, no `RetCode`): its
    /// descriptors, then the body after the NDR record.
    Complex {
        descriptors: Vec<Descriptor>,
        body: Vec<u8>,
    },
    /// A complex reply of descriptors alone, without an NDR record.
    Descriptors(Vec<Descriptor>),
    /// The request could not be sent: the send's `mach_msg_return_t`,
    /// which the call returns without a reply.
    NotSent(u32),
}

/// One descriptor of a complex reply. Further forms join as routines
/// need them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Descriptor {
    /// One right of this space carried with `disposition`
    /// (`mach_msg_port_descriptor_t`).
    Port { name: u32, disposition: u8 },
    /// An out-of-line array of rights of this space, each carried with
    /// `disposition` (`mach_msg_ool_ports_descriptor64_t`,
    /// `MACH_MSG_VIRTUAL_COPY`).
    Ports { names: Vec<u32>, disposition: u8 },
    /// Out-of-line memory of this space (`mach_msg_ool_descriptor64_t`,
    /// `MACH_MSG_VIRTUAL_COPY`), released from it with the reply when
    /// `deallocate`.
    Memory {
        address: u64,
        size: u32,
        deallocate: bool,
    },
}

/// `MACH_MSG_TYPE_MOVE_SEND`, which is also a received send right's
/// disposition (`MACH_MSG_TYPE_PORT_SEND`).
pub(super) const MOVE_SEND: u8 = 17;
/// `MACH_MSG_TYPE_COPY_SEND`.
pub(super) const COPY_SEND: u8 = 19;
/// `MACH_PORT_DEAD`.
pub(super) const MACH_PORT_DEAD: u32 = !0;

impl Descriptor {
    /// The descriptor as an LP64 sender lays it out; a port array's
    /// address is its names', valid while the descriptor lives.
    pub(super) fn bytes(&self) -> Vec<u8> {
        const PORT: u8 = 0;
        const OOL: u8 = 1;
        const OOL_PORTS: u8 = 2;
        const VIRTUAL_COPY: u8 = 1;
        let mut out = Vec::with_capacity(16);
        match self {
            Self::Port { name, disposition } => {
                out.extend(name.to_le_bytes());
                out.extend([0; 6]);
                out.extend([*disposition, PORT]);
            }
            Self::Ports { names, disposition } => {
                out.extend((names.as_ptr() as u64).to_le_bytes());
                out.extend([0, VIRTUAL_COPY, *disposition, OOL_PORTS]);
                out.extend((names.len() as u32).to_le_bytes());
            }
            Self::Memory {
                address,
                size,
                deallocate,
            } => {
                out.extend(address.to_le_bytes());
                out.extend([u8::from(*deallocate), VIRTUAL_COPY, 0, OOL]);
                out.extend(size.to_le_bytes());
            }
        }
        out
    }

    /// Release the right a moved port carries, as the kernel destroys a
    /// reply it cannot send.
    pub(super) fn release(&self) {
        if let Self::Port {
            name,
            disposition: MOVE_SEND,
        } = self
        {
            release_send(*name);
        }
    }
}

/// Release one send right of this space to `name`, if it names a port.
pub(super) fn release_send(name: u32) {
    unsafe extern "C" {
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
    }
    if name != 0 && name != MACH_PORT_DEAD {
        // SAFETY: a right of this task's own space.
        unsafe { mach_port_deallocate(crate::hosted::host::task(), name) };
    }
}

pub(super) const KERN_INVALID_ARGUMENT: u32 = 4;
pub(super) const KERN_FAILURE: u32 = 5;
pub(super) const KERN_NOT_SUPPORTED: u32 = 46;
/// `MIG_BAD_ARGUMENTS`: the request is malformed.
pub(super) const MIG_BAD_ARGUMENTS: u32 = (-304i32) as u32;

/// `NDR_record` on both LP64 ABIs: little-endian, ASCII, IEEE floats.
pub(super) const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// Which kernel object a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Object {
    Task,
    Thread,
    Host,
    /// The default processor set's name port (`processor_set_default`).
    ProcessorSet,
}

/// The routines [`serve`] answers or forwards, by object, with the named
/// limit of a routine served only in part (other arguments stop the run
/// naming them).
pub(crate) const SERVED: &[(Object, &str, Option<&str>)] = &[
    (Object::Host, "host_info", None),
    (Object::Host, "host_kernel_version", None),
    (Object::Host, "_host_page_size", None),
    (
        Object::Host,
        "mach_memory_object_memory_entry",
        Some("an internal entry of a size in partial guest pages stops the run"),
    ),
    (
        Object::Host,
        "mach_memory_object_memory_entry_64",
        Some("an internal entry of a size in partial guest pages stops the run"),
    ),
    (Object::Host, "host_request_notification", None),
    (Object::Host, "_kernelrpc_host_create_mach_voucher", None),
    (Object::Host, "kmod_get_info", None),
    (Object::Host, "host_virtual_physical_table_info", None),
    (
        Object::Host,
        "host_lockgroup_info",
        Some("the lock groups are the x86 host kernel's"),
    ),
    (
        Object::Host,
        "mach_zone_info",
        Some("a caller shown zones receives the x86 host kernel's"),
    ),
    (
        Object::Host,
        "mach_zone_info_for_zone",
        Some("a caller shown zones receives the x86 host kernel's"),
    ),
    (
        Object::Host,
        "mach_memory_info",
        Some("a caller shown zones receives the x86 host kernel's zones and memory"),
    ),
    (
        Object::Host,
        "mach_memory_info_redacted",
        Some("a caller shown zones receives the x86 host kernel's zones and memory"),
    ),
    (
        Object::Host,
        "host_set_atm_diagnostic_flag",
        Some(
            "an entitled caller sets the host's flag, which this process's commpage does not show",
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
        Some("ranges in whole guest pages"),
    ),
    (
        Object::Host,
        "host_statistics_from_user",
        Some("the x86 host's load and VM statistics, its page counts in guest pages"),
    ),
    (
        Object::Host,
        "host_statistics64_from_user",
        Some(
            "the x86 host's load and VM statistics, its page counts in guest pages; on a profile \
             with memory tagging the tag storage statistics stop the run",
        ),
    ),
    (Object::Host, "host_get_special_port", None),
    (
        Object::Host,
        "host_processor_info",
        Some("PROCESSOR_BASIC_INFO; the load and exception counters stop the run"),
    ),
    (Object::Host, "processor_set_default", None),
    (Object::Host, "host_processor_sets", None),
    (Object::Host, "host_processor_set_priv", None),
    (Object::Host, "host_processors", None),
    (Object::ProcessorSet, "processor_set_info", None),
    (
        Object::ProcessorSet,
        "processor_set_statistics",
        Some("the load average and Mach factor are the x86 host scheduler's"),
    ),
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
        Some("the token's name also holds the hosted kernel's receive right of the resume port"),
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
    (
        Object::Task,
        "task_info_from_user",
        Some("the TASK_AUDIT_TOKEN flavor"),
    ),
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
    (
        Object::Task,
        "task_purgable_info",
        Some("the counts include the hosted runtime's own purgeable memory"),
    ),
    (
        Object::Task,
        "task_set_phys_footprint_limit",
        Some("the footprint includes the hosted runtime's own memory"),
    ),
    (Object::Task, "task_get_state", None),
    (
        Object::Task,
        "task_set_state",
        Some(
            "a debug state enabling a breakpoint, watchpoint or single step for new threads \
             stops the run",
        ),
    ),
    (
        Object::Task,
        "task_inspect",
        Some("TASK_INSPECT_BASIC_COUNTS would count the x86 host's instructions and cycles"),
    ),
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
    (
        Object::Thread,
        "thread_info",
        Some(
            "the times, CPU usage and priorities are the host thread's, whose user time counts \
             the hosted kernel's work",
        ),
    ),
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
    (Object::Thread, "thread_adopt_exception_handler", None),
    (Object::Thread, "_kernelrpc_thread_policy", None),
    (
        Object::Thread,
        "_kernelrpc_thread_policy_set",
        Some("a time constraint of over 4.29 seconds, past the host's nanoseconds"),
    ),
    (Object::Thread, "thread_policy_get", None),
    (Object::Thread, "_kernelrpc_thread_set_policy", None),
    (Object::Thread, "thread_get_mach_voucher", None),
    (Object::Thread, "thread_set_mach_voucher", None),
    (Object::Thread, "thread_swap_mach_voucher", None),
    (Object::Thread, "thread_convert_thread_state", None),
];

/// The extra reference a hosted thread's port name carries.
const THREAD_PORT_LIMIT: &str =
    "the new thread's port name also carries its host thread library's reference";

/// What setting the task's exception ports does not reach.
const EXCEPTION_PORT_LIMITS: &str = "a guest exception for which a port is set stops the run; \
     the host kernel's EXC_CRASH, EXC_RESOURCE and EXC_GUARD reports go to the ports the process \
     inherited; a fork, exec or spawn after a change stops the run; a platform-restricted task's \
     policy violation stops the run";

/// What setting a thread's exception ports does not reach.
const THREAD_EXCEPTION_PORT_LIMITS: &str = "a guest exception for which a port is set stops the \
     run; the host kernel's EXC_CRASH, EXC_RESOURCE and EXC_GUARD reports pass the thread's ports \
     for the task's; a platform-restricted task's policy violation stops the run";

/// Task routines whose answer is the arm64 kernel's: the request is
/// forwarded to the task port, which is the host task's. They suspend,
/// resume and terminate this task, act on its vouchers, dyld
/// notification ports and EXC_GUARD behavior (which the host kernel then
/// applies to the calls it serves), trace dyld's image registrations
/// (`kdebug` only) or answer as every release kernel does (the dyld
/// image list and state routines, the test upcalls, corpse forking). The
/// purgeable counts and the footprint limit cover the host task's memory,
/// which holds the hosted runtime's too.
const TASK_FORWARDED: &[&str] = &[
    "task_terminate",
    "task_set_info",
    "task_suspend",
    "task_resume",
    "task_suspend2_mig",
    "task_resume2_mig",
    "task_get_mach_voucher",
    "task_set_mach_voucher",
    "task_swap_mach_voucher",
    "task_register_dyld_image_infos",
    "task_unregister_dyld_image_infos",
    "task_get_dyld_image_infos",
    "task_register_dyld_shared_cache_image_info",
    "task_register_dyld_set_dyld_state",
    "task_register_dyld_get_process_state",
    "task_get_exc_guard_behavior",
    "task_set_exc_guard_behavior",
    "_kernelrpc_mach_task_is_self",
    "task_dyld_process_info_notify_register",
    "task_dyld_process_info_notify_deregister",
    "task_identity_token_get_task_port",
    "task_test_sync_upcall",
    "task_test_async_upcall_propagation",
    "task_set_corpse_forking_behavior",
    "task_purgable_info",
    "task_set_phys_footprint_limit",
];

/// Answer `routine` sent to `object`, or `None` when the hosted kernel
/// does not serve it. `complex` is the request's `MACH_MSGH_BITS_COMPLEX`.
pub(super) fn serve(
    kernel: &mut Kernel,
    object: Object,
    port: u32,
    routine: &str,
    complex: bool,
    request: &Request,
) -> Result<Option<Reply>> {
    Ok(Some(match (object, routine, complex) {
        (Object::Thread, "thread_suspend" | "thread_resume", false) => {
            let own = port == kernel.thread_port;
            match kernel.process.runtime.registry.control_by_port(port) {
                Some(thread) => status(if routine == "thread_suspend" {
                    thread.suspend(own)
                } else {
                    thread.resume()
                }),
                None => Reply::Failure(control::KERN_TERMINATED),
            }
        }
        (Object::Thread, "thread_get_state_to_user" | "act_get_state_to_user", false) => {
            get_state(kernel, port, routine, request)?
        }
        (Object::Thread, "thread_set_state_from_user" | "act_set_state_from_user", false) => {
            set_state(kernel, port, routine, request)?
        }
        (Object::Host, "host_info", false) => {
            // `flavor`, then `host_info_outCnt` after the NDR record.
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            host_info(&kernel.process.hardware, flavor, count.min(HOST_INFO_MAX))
        }
        (Object::Task, "_kernelrpc_mach_vm_map_external", true) => vm_map(request)?,
        // `which_port`. The bootstrap and access ports are the host's
        // launchd's and taskgated's, as for any process of this user; the
        // kernel and host ports are this task's own kernel objects, whose
        // names the reply repeats; the debug-control port is the one this
        // task set, if any; the resource-notify port is configured out of
        // both release kernels, which refuse it and every other number
        // alike. The name, inspect and read ports are other ports of the
        // host task, whose requests would answer for the x86 task.
        (Object::Task, "task_get_special_port_from_user", false) => match request.word(8) {
            Some(which @ (TASK_NAME_PORT | TASK_INSPECT_PORT | TASK_READ_PORT)) => bail!(
                "task_get_special_port({which}): the host task's name, inspect and read ports \
                 would answer for the x86 task, which is not implemented"
            ),
            Some(_) => Reply::Forward,
            None => Reply::Failure(MIG_BAD_ARGUMENTS),
        },
        // One port descriptor, then `which_port`. This task's own control
        // ports are immovable sends of a platform-restricted task, which
        // no special port may hold (`KERN_INVALID_RIGHT`); the kernel and
        // host ports are settable only with SIP's kernel-debugger
        // allowance, which a stock Mac does not grant (`KERN_NO_ACCESS`).
        // Replacing any other port changes only this task's own state, or
        // fails alike in both kernels.
        (Object::Task, "task_set_special_port_from_user", true) => {
            let (Some(name), Some(which)) = (request.word(4), request.word(24)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            let immovable = super::thread::immovable_send(kernel, name);
            if !immovable && !matches!(which, TASK_KERNEL_PORT | TASK_HOST_PORT) {
                return Ok(Some(Reply::Forward));
            }
            let name = match super::exception::carried_send(kernel, routine, request, 28)? {
                Ok(name) => name,
                Err(reply) => return Ok(Some(reply)),
            };
            release_send(name);
            Reply::Failure(if immovable {
                KERN_INVALID_RIGHT
            } else {
                KERN_NO_ACCESS
            })
        }
        // One port descriptor (the parent entry), then `size`, `offset`
        // and `permission`. A range already in whole guest pages names the
        // same memory under the host's 4 KiB rounding as under the arm64
        // kernel's 16 KiB rounding.
        (Object::Task, "_mach_make_memory_entry", true) => {
            let (Some(size), Some(offset)) = (request.double(24), request.double(32)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            if (size | offset) & memory::PAGE_MASK != 0 {
                bail!(
                    "mach_make_memory_entry of {size:#x} bytes at {offset:#x}: a range in \
                     partial guest pages is not implemented"
                );
            }
            Reply::Forward
        }
        // `node`, `which`. The host port is the host's, already this
        // process's host kernel object.
        // The IOKit main port. IOKit's own requests then go to the host's
        // registry, whose serialized properties have one layout in both
        // ABIs but describe the x86 machine.
        (Object::Host, "host_get_io_main", false) => Reply::Forward,
        (Object::Host, "host_kernel_version", false) => kernel_version(),
        // `flavor`.
        (Object::Host, "host_processor_info", false) => match request.word(8) {
            Some(flavor) => processor_info(&kernel.process.hardware, flavor)?,
            None => Reply::Failure(MIG_BAD_ARGUMENTS),
        },
        // `vm_size_t`: the arm64 kernel's 16 KiB page.
        (Object::Host, "_host_page_size", false) => {
            Reply::Success(memory::PAGE_BYTES.to_le_bytes().to_vec())
        }
        // The pager port, then `internal`, `size` and `permission`. An
        // internal entry's object is the size rounded to the kernel's page
        // (`vm_sanitize_object_size`): the host's 4 KiB rounding names the
        // same memory only for whole guest pages.
        (
            Object::Host,
            "mach_memory_object_memory_entry" | "mach_memory_object_memory_entry_64",
            true,
        ) => {
            let (Some(pager), Some(internal), Some(size)) =
                (request.word(4), request.word(24), request.double(28))
            else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            if pager == 0 && internal != 0 && size & memory::PAGE_MASK != 0 {
                bail!(
                    "{routine} of {size:#x} bytes: an internal entry in partial guest pages is \
                     not implemented"
                );
            }
            Reply::Forward
        }
        (Object::Host, routine, _) if HOST_FORWARDED.contains(&routine) => Reply::Forward,
        // The default processor set is the host's boot set, whose name
        // the host kernel gives, and requests to it come back to
        // [`processor_set_info`].
        (Object::Host, "processor_set_default", _) => Reply::Forward,
        // `flavor`, `info_outCnt`.
        (Object::ProcessorSet, "processor_set_info", false) => {
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            processor_set_info(
                &kernel.process.hardware,
                kernel.process.host_port(),
                flavor,
                count.min(PROCESSOR_SET_INFO_MAX),
            )
        }
        // The boot set's load (the Mach factor and load average are the
        // host scheduler's), and its tasks, which take the set's control
        // port: only the privileged host port gives it, so the host
        // kernel refuses the name port as the arm64 kernel does.
        (
            Object::ProcessorSet,
            "processor_set_statistics" | "processor_set_tasks" | "processor_set_tasks_with_flavor",
            _,
        ) => Reply::Forward,
        // `flavor`, `host_info_outCnt`.
        (
            Object::Host,
            routine @ ("host_statistics_from_user" | "host_statistics64_from_user"),
            false,
        ) => {
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            host_statistics(
                &kernel.process.hardware,
                routine == "host_statistics64_from_user",
                flavor,
                count.min(HOST_INFO_MAX),
            )?
        }
        // A host-privileged routine: the host kernel refuses the host
        // port for every special port, as the arm64 kernel refuses it
        // to an unprivileged process.
        (Object::Host, "host_get_special_port", false) => Reply::Forward,
        // `flavor`, `task_info_outCnt`. The audit token is this process's
        // identity, the same in either ABI.
        // The process's guest threads, each as a new send right, in
        // creation order; the host task's other threads are the hosted
        // runtime's own.
        (Object::Task, "task_threads_from_user", false) => {
            let names = kernel.process.runtime.registry.ports();
            let count = names.len() as u32;
            Reply::Complex {
                descriptors: vec![Descriptor::Ports {
                    names,
                    disposition: COPY_SEND,
                }],
                body: count.to_le_bytes().to_vec(),
            }
        }
        // This task's scheduling policies (role, QoS, latency and
        // throughput tiers): integer structures of one layout in both
        // ABIs, which the host scheduler applies to the host threads that
        // run the guest's.
        (Object::Task, "task_policy_set" | "task_policy_get", false) => Reply::Forward,
        // This task's three registered ports (`itk_registered`): IPC state
        // of its own, which the host task keeps and children inherit as
        // the arm64 kernel's do.
        (Object::Task, "_kernelrpc_mach_ports_register3", true)
        | (Object::Task, "_kernelrpc_mach_ports_lookup3", false) => Reply::Forward,
        // A send right naming this task's identity (pid, version and audit
        // token), the same in either ABI.
        (Object::Task, "task_create_identity_token", false) => Reply::Forward,
        (Object::Task, "task_info_from_user", false) => {
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            match flavor {
                TASK_AUDIT_TOKEN => Reply::Forward,
                _ => bail!("task_info flavor {flavor} (count {count}) is not implemented"),
            }
        }
        (Object::Task, "task_restartable_ranges_register", false) => {
            restartable_ranges_register(kernel, request)
        }
        // Every thread off the execution lock was reset out of its range
        // when it was preempted, and the caller is outside one: no PC is
        // left to reset.
        (Object::Task, "task_restartable_ranges_synchronize", false) => Reply::Success(Vec::new()),
        // `len`, `max_len`; out `address`, `next_deadline`.
        (Object::Task, "mach_vm_deferred_reclamation_buffer_allocate", false) => {
            let (Some(len), Some(max_len)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            pair(reclaim::allocate(
                &mut lock(&kernel.process.reclaim),
                len,
                max_len,
            ))
        }
        // `num_entries_to_reclaim`; out `bytes_reclaimed`, `next_deadline`.
        (Object::Task, "mach_vm_deferred_reclamation_buffer_flush", false) => {
            let Some(entries) = request.word(8) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            pair(reclaim::flush(&lock(&kernel.process.reclaim), entries))
        }
        // `new_len`; out `bytes_reclaimed`, `next_deadline`.
        (Object::Task, "mach_vm_deferred_reclamation_buffer_resize", false) => {
            let Some(len) = request.word(8) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            pair(reclaim::resize(&mut lock(&kernel.process.reclaim), len))
        }
        // Out `addr`, `size`: the ring's, zero without one.
        (Object::Task, "mach_vm_deferred_reclamation_buffer_query", false) => {
            if !request.body.is_empty() {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            }
            let (address, size) = reclaim::query(&lock(&kernel.process.reclaim));
            let mut body = address.to_le_bytes().to_vec();
            body.extend(size.to_le_bytes());
            Reply::Success(body)
        }
        (Object::Task, routine, _) if TASK_FORWARDED.contains(&routine) => Reply::Forward,
        (Object::Task, "task_get_state", false) => task_get_state(kernel, request),
        (Object::Task, "task_set_state", false) => task_set_state(kernel, request)?,
        // `flavor`, `info_outCnt`, which MIG bounds to 4.
        (Object::Task, "task_inspect", false) => {
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            if flavor != TASK_INSPECT_BASIC_COUNTS || count.min(4) < TASK_INSPECT_BASIC_COUNTS_COUNT
            {
                Reply::Failure(KERN_INVALID_ARGUMENT)
            } else {
                bail!(
                    "task_inspect(TASK_INSPECT_BASIC_COUNTS): the host would count the x86 \
                     host's instructions and cycles, not the profile's processors'"
                )
            }
        }
        (Object::Task, "thread_create_from_user", false) => {
            if !request.body.is_empty() {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            }
            thread_create(kernel, None)?
        }
        // `flavor`, `new_stateCnt`, then the state.
        (Object::Task, "thread_create_running_from_user", false) => {
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            let Some(words) = state_words(request, count) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            thread_create(kernel, Some((flavor, words)))?
        }
        (Object::Task, "task_set_exception_ports", true) => {
            super::exception::set(kernel, request, false, super::exception::Target::Task)?
        }
        (Object::Task, "task_swap_exception_ports", true) => {
            super::exception::set(kernel, request, true, super::exception::Target::Task)?
        }
        (Object::Task, "task_get_exception_ports_from_user", false) => {
            super::exception::get(kernel, request, super::exception::Target::Task)?
        }
        (Object::Task, "task_get_exception_ports_info", false) => {
            super::exception::info(kernel, request, super::exception::Target::Task)?
        }
        (Object::Task, _, _) => return super::vm::serve(kernel, routine, complex, request),
        (Object::Thread, _, _) => {
            return super::thread::serve(kernel, port, routine, complex, request);
        }
        _ => return Ok(None),
    }))
}

/// A routine whose only out argument is its `kern_return_t`.
fn status(code: u32) -> Reply {
    if code == control::KERN_SUCCESS {
        Reply::Success(Vec::new())
    } else {
        Reply::Failure(code)
    }
}

/// `thread_get_state_to_user(flavor, old_stateCnt)` and its `act_` form,
/// which refuses the caller's own thread: the state words after their
/// count.
fn get_state(kernel: &Kernel, port: u32, routine: &str, request: &Request) -> Result<Reply> {
    let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let own = port == kernel.thread_port;
    if own && routine.starts_with("act_") {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    let Some(thread) = kernel.process.runtime.registry.control_by_port(port) else {
        return Ok(Reply::Failure(control::KERN_TERMINATED));
    };
    let signer = kernel.process.signer.as_ref();
    let count = count.min(control::THREAD_STATE_MAX);
    match thread.with_state(own, |state| {
        (control::get_state(state, flavor, count, signer), None)
    }) {
        Ok(words) => Ok(match words? {
            Ok(words) => {
                let mut body = (words.len() as u32).to_le_bytes().to_vec();
                for word in words {
                    body.extend(word.to_le_bytes());
                }
                Reply::Success(body)
            }
            Err(code) => Reply::Failure(code),
        }),
        Err(code) => Ok(Reply::Failure(code)),
    }
}

/// `thread_set_state_from_user(flavor, new_stateCnt, new_state)` and its
/// `act_` form, which refuses the caller's own thread.
fn set_state(kernel: &Kernel, port: u32, routine: &str, request: &Request) -> Result<Reply> {
    let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let Some(bytes) = (count <= control::THREAD_STATE_MAX)
        .then(|| request.body.get(16..16 + count as usize * 4))
        .flatten()
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect();
    let own = port == kernel.thread_port;
    if own && routine.starts_with("act_") {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    let Some(thread) = kernel.process.runtime.registry.control_by_port(port) else {
        return Ok(Reply::Failure(control::KERN_TERMINATED));
    };
    let signer = kernel.process.signer.as_ref();
    match thread.with_state(own, |state| {
        match control::set_state(state, flavor, &words, signer) {
            Ok(Ok(set)) => (Ok(Ok(())), Some(set)),
            other => (other.map(|result| result.map(|_| ())), None),
        }
    }) {
        Ok(result) => Ok(match result? {
            Ok(()) => Reply::Success(Vec::new()),
            Err(code) => Reply::Failure(code),
        }),
        Err(code) => Ok(Reply::Failure(code)),
    }
}

/// The `new_stateCnt` words of a request's state after its flavor and
/// count, at most `THREAD_STATE_MAX`.
fn state_words(request: &Request, count: u32) -> Option<Vec<u32>> {
    let bytes = (count <= control::THREAD_STATE_MAX)
        .then(|| request.body.get(16..16 + count as usize * 4))
        .flatten()?;
    Some(
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect(),
    )
}

/// `thread_state_flavor_t` values the task routines take.
const THREAD_STATE_NONE: u32 = 5;
const ARM_DEBUG_STATE64: u32 = 15;
const DEBUG_STATE64_COUNT: u32 = 130;
/// `MACH_VM_MAX_ADDRESS` of a 64-bit macOS task.
const MACH_VM_MAX_ADDRESS: u64 = 0x0000_7fff_fe00_0000;
/// `task_inspect`'s one flavor and its count.
const TASK_INSPECT_BASIC_COUNTS: u32 = 1;
const TASK_INSPECT_BASIC_COUNTS_COUNT: u32 = 4;

/// The doubleword `index` of an `arm_debug_state64_t` (`bvr[16]`,
/// `bcr[16]`, `wvr[16]`, `wcr[16]`, `mdscr_el1`).
fn debug_double(words: &[u32], index: usize) -> u64 {
    u64::from(words[index * 2]) | u64::from(words[index * 2 + 1]) << 32
}

/// `task_get_state(flavor, old_stateCnt)` (`machine_task_get_state`): the
/// debug state new threads take, zero when none is set, after its count.
/// A 64-bit task has no legacy or 32-bit debug state.
fn task_get_state(kernel: &Kernel, request: &Request) -> Reply {
    let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    if flavor != ARM_DEBUG_STATE64 || count.min(control::THREAD_STATE_MAX) != DEBUG_STATE64_COUNT {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    }
    let words = lock(&kernel.process.task_debug)
        .clone()
        .unwrap_or_else(|| vec![0; DEBUG_STATE64_COUNT as usize]);
    let mut body = DEBUG_STATE64_COUNT.to_le_bytes().to_vec();
    for word in words {
        body.extend(word.to_le_bytes());
    }
    Reply::Success(body)
}

/// `task_set_state(flavor, new_stateCnt, new_state)`
/// (`machine_task_set_state`): the debug state new threads take
/// (`machine_thread_inherit_taskwide`), kept as given;
/// `THREAD_STATE_NONE` clears it.
fn task_set_state(kernel: &Kernel, request: &Request) -> Result<Reply> {
    let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let Some(words) = state_words(request, count) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let mut debug = lock(&kernel.process.task_debug);
    Ok(match flavor {
        ARM_DEBUG_STATE64 if count == DEBUG_STATE64_COUNT => {
            use super::super::bsd::sysctl::{BREAKPOINT_PAIRS, WATCHPOINT_PAIRS};
            // `debug_state_is_valid64`: a used pair's address is a user
            // address.
            let invalid = |control: usize, value: usize, pairs: i32| {
                (0..pairs as usize).any(|index| {
                    debug_double(&words, control + index) != 0
                        && debug_double(&words, value + index) >= MACH_VM_MAX_ADDRESS
                })
            };
            if invalid(16, 0, BREAKPOINT_PAIRS) || invalid(48, 32, WATCHPOINT_PAIRS) {
                return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
            }
            const ENABLE: u64 = 1;
            const MDSCR_SS: u64 = 1;
            if debug_double(&words, 64) & MDSCR_SS != 0
                || (16..32)
                    .chain(48..64)
                    .any(|index| debug_double(&words, index) & ENABLE != 0)
            {
                bail!(
                    "task_set_state(ARM_DEBUG_STATE64) enabling a hardware breakpoint, watchpoint \
                     or single step for new threads: guest debug exceptions are not implemented"
                );
            }
            *debug = Some(words);
            Reply::Success(Vec::new())
        }
        THREAD_STATE_NONE => match debug.take() {
            Some(_) => Reply::Success(Vec::new()),
            None => Reply::Failure(KERN_FAILURE),
        },
        _ => Reply::Failure(KERN_INVALID_ARGUMENT),
    })
}

/// `thread_create_from_user` and, with its state, `thread_create_running`:
/// a thread of this task with all-zero user state, held by one user stop
/// until `thread_resume`, or running from the state set as
/// `thread_set_state` sets it. The reply moves the reference the new
/// thread took to its port; the host thread library keeps another.
fn thread_create(kernel: &mut Kernel, state: Option<(u32, Vec<u32>)>) -> Result<Reply> {
    use std::sync::{Arc, atomic::AtomicU32};
    // The state's `kern_return_t`, which ends the new thread unstarted.
    let refused = Arc::new(AtomicU32::new(control::KERN_SUCCESS));
    let refusal = refused.clone();
    let created = crate::hosted::threads::spawn(
        &kernel.process,
        0,
        kernel.signals.creation_mask(),
        move |kernel, pe| {
            if let Some(control) = kernel.control() {
                control.set_kind(control::Kind::Mach);
            }
            match state {
                None => {
                    if let Some(control) = kernel.process.runtime.registry.control(kernel.thread) {
                        control.start_suspended();
                    }
                }
                Some((flavor, words)) => {
                    let current = control::UserState::capture(pe);
                    let signer = kernel.process.signer.as_ref();
                    match control::set_state(&current, flavor, &words, signer)? {
                        Ok(set) => set.apply(pe),
                        Err(code) => {
                            refusal.store(code, std::sync::atomic::Ordering::SeqCst);
                            return Ok(Err(super::super::bsd::EINVAL));
                        }
                    }
                }
            }
            Ok(Ok(()))
        },
    )?;
    Ok(match created {
        Ok(port) => Reply::Descriptors(vec![Descriptor::Port {
            name: port,
            disposition: MOVE_SEND,
        }]),
        Err(_) => match refused.load(std::sync::atomic::Ordering::SeqCst) {
            control::KERN_SUCCESS => Reply::Failure(KERN_RESOURCE_SHORTAGE),
            code => Reply::Failure(code),
        },
    })
}

/// `KERN_RESOURCE_SHORTAGE`: no thread could be made.
const KERN_RESOURCE_SHORTAGE: u32 = 6;

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
    (
        Object::Task,
        "task_register_hardened_exception_handler",
        "whether its port was made an exception port (MPO_EXCEPTION_PORT) is known only to the \
         host kernel, and hardened exception delivery is not implemented",
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

/// Host routines whose answer is the arm64 kernel's: the request is
/// forwarded to the host port. The host-privileged routines refuse the
/// host port as an unprivileged arm64 process's kernel refuses it (only
/// root obtains the privileged port); the others act on this machine's
/// calendar notifications, vouchers and flags, or answer as every
/// release kernel does (`kmod_get_info`, `host_virtual_physical_table_info`).
const HOST_FORWARDED: &[&str] = &[
    "host_request_notification",
    "_kernelrpc_host_create_mach_voucher",
    "kmod_get_info",
    "host_virtual_physical_table_info",
    "host_lockgroup_info",
    "mach_zone_info",
    "mach_zone_info_for_zone",
    "mach_memory_info",
    "mach_memory_info_redacted",
    "host_set_atm_diagnostic_flag",
    "host_set_multiuser_config_flags",
    "host_get_boot_info",
    "host_reboot",
    "host_processor_sets",
    "host_processor_set_priv",
    "host_processors",
    "host_priv_statistics",
    "host_default_memory_manager",
    "vm_wire",
    "thread_wire",
    "host_set_special_port",
    "host_set_exception_ports",
    "host_get_exception_ports",
    "host_swap_exception_ports",
    "mach_vm_wire_external",
    "host_set_UNDServer",
    "host_get_UNDServer",
    "kext_request",
];

/// `processor_set_info_t`'s bound.
const PROCESSOR_SET_INFO_MAX: u32 = 1024;
/// `PROCESSOR_SET_BASIC_INFO` and its count: `processor_count`,
/// `default_policy`.
const PROCESSOR_SET_BASIC_INFO: u32 = 5;
const PROCESSOR_SET_BASIC_INFO_COUNT: u32 = 2;
/// `POLICY_TIMESHARE`.
const POLICY_TIMESHARE: u32 = 1;

/// `processor_set_info` on the default processor set. Its basic
/// information counts the set's processors as the arm64 kernel counts
/// them, every available processor of the machine
/// (`processor_avail_count`, where the x86 kernel gives
/// `processor_avail_count_user`), with the timesharing policy, in a
/// complex reply carrying the host port (`host`). The other flavors are
/// the scheduler's priority constants, the same in both kernels:
/// forwarded.
fn processor_set_info(hardware: &hardware::Hardware, host: u32, flavor: u32, count: u32) -> Reply {
    if flavor != PROCESSOR_SET_BASIC_INFO {
        return Reply::Forward;
    }
    if count < PROCESSOR_SET_BASIC_INFO_COUNT {
        return Reply::Failure(KERN_FAILURE);
    }
    let cpus = u32::from(hardware.cpus());
    let mut body = PROCESSOR_SET_BASIC_INFO_COUNT.to_le_bytes().to_vec();
    body.extend(
        [cpus, POLICY_TIMESHARE]
            .iter()
            .flat_map(|word| word.to_le_bytes()),
    );
    Reply::Complex {
        descriptors: vec![Descriptor::Port {
            name: host,
            disposition: COPY_SEND,
        }],
        body,
    }
}

/// `processor_flavor_t`s (`mach/processor_info.h`): the arm64 kernel's
/// own two, its CPU counter statistics (`cpu_info_count`).
const PROCESSOR_BASIC_INFO: u32 = 1;
const PROCESSOR_CPU_LOAD_INFO: u32 = 2;
const PROCESSOR_CPU_STAT: u32 = 0x1000_0003;
const PROCESSOR_CPU_STAT64: u32 = 0x1000_0004;
/// `processor_basic_info`: `cpu_type`, `cpu_subtype`, `running`,
/// `slot_num`, `is_master`.
const PROCESSOR_BASIC_INFO_COUNT: u32 = 5;

/// `host_processor_info`: one record per processor of the profile's
/// machine, out of line. Every processor is running ARM64E
/// (`CPU_ARCH_ARMv8E`) in its logical slot, the boot processor (slot 0)
/// the master. The load ticks and exception counters would be the x86
/// host's processors', so they stop the run; other flavors fail in
/// `processor_info_count`.
fn processor_info(hardware: &hardware::Hardware, flavor: u32) -> Result<Reply> {
    match flavor {
        PROCESSOR_BASIC_INFO => {}
        PROCESSOR_CPU_LOAD_INFO | PROCESSOR_CPU_STAT | PROCESSOR_CPU_STAT64 => bail!(
            "host_processor_info flavor {flavor:#x}: the load ticks and exception counters of \
             the profile's {} processors are not modeled",
            hardware.cpus()
        ),
        _ => return Ok(Reply::Failure(KERN_FAILURE)),
    }
    let cpus = u32::from(hardware.cpus());
    let records: Vec<u8> = (0..cpus)
        .flat_map(|slot| {
            [
                hardware::CPU_TYPE_ARM64,
                hardware::CPU_SUBTYPE_ARM64E,
                1,
                slot,
                u32::from(slot == 0),
            ]
        })
        .flat_map(u32::to_le_bytes)
        .collect();
    unsafe extern "C" {
        fn mach_vm_allocate(task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    }
    const VM_FLAGS_ANYWHERE: i32 = 1;
    let mut address = 0u64;
    // SAFETY: new memory of this task, which the reply's send releases.
    let code = unsafe {
        mach_vm_allocate(
            crate::hosted::host::task(),
            &mut address,
            records.len() as u64,
            VM_FLAGS_ANYWHERE,
        )
    };
    if code != 0 {
        return Ok(Reply::Failure(KERN_RESOURCE_SHORTAGE));
    }
    // SAFETY: the allocation holds the records.
    unsafe { std::ptr::copy_nonoverlapping(records.as_ptr(), address as *mut u8, records.len()) };
    let mut body = cpus.to_le_bytes().to_vec();
    body.extend((cpus * PROCESSOR_BASIC_INFO_COUNT).to_le_bytes());
    Ok(Reply::Complex {
        descriptors: vec![Descriptor::Memory {
            address,
            size: records.len() as u32,
            deallocate: true,
        }],
        body,
    })
}

/// `kernel_version_t`'s bound.
const KERNEL_VERSION_MAX: usize = 512;

/// `host_kernel_version`: the 26A434 kernel's version string, as
/// `kern.version` gives it, as a MIG string (offset, count with the NUL,
/// the bytes padded to a word).
fn kernel_version() -> Reply {
    let mut string = super::super::bsd::sysctl::KERNEL_VERSION
        .as_bytes()
        .to_vec();
    string.truncate(KERNEL_VERSION_MAX - 1);
    string.push(0);
    let mut body = 0u32.to_le_bytes().to_vec();
    body.extend((string.len() as u32).to_le_bytes());
    body.extend(&string);
    body.resize(body.len().next_multiple_of(4), 0);
    Reply::Success(body)
}

/// `osfmk/mach/task_special_ports.h`.
const TASK_KERNEL_PORT: u32 = 1;
const TASK_HOST_PORT: u32 = 2;
const TASK_NAME_PORT: u32 = 3;
const TASK_INSPECT_PORT: u32 = 5;
const TASK_READ_PORT: u32 = 6;
/// `KERN_NO_ACCESS` and `KERN_INVALID_RIGHT`.
const KERN_NO_ACCESS: u32 = 8;
const KERN_INVALID_RIGHT: u32 = 17;
/// `osfmk/mach/task_info.h`.
const TASK_AUDIT_TOKEN: u32 = 15;

/// `task_restartable_range_t` and the kernel's bounds
/// (`osfmk/kern/restartable.c`).
const RESTARTABLE_RANGE_BYTES: usize = 16;
const RESTARTABLE_RANGES_MAX: u32 = 64;
const TASK_RESTARTABLE_OFFSET_MAX: u16 = 4096;

/// `task_restartable_ranges_register(ranges, count)`: validated and kept
/// once, as a release kernel allows. A thread preempted inside a range
/// resumes at its recovery address (`crate::hosted::threads`); signals,
/// which would also reset it, are not delivered.
fn restartable_ranges_register(kernel: &mut Kernel, request: &Request) -> Reply {
    let Some(count) = request
        .word(8)
        .filter(|&count| count <= RESTARTABLE_RANGES_MAX)
    else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let Some(bytes) = request
        .body
        .get(12..12 + count as usize * RESTARTABLE_RANGE_BYTES)
    else {
        return Reply::Failure(MIG_BAD_ARGUMENTS);
    };
    let mut ranges: Vec<(u64, u16, u16, u32)> = bytes
        .as_chunks::<RESTARTABLE_RANGE_BYTES>()
        .0
        .iter()
        .map(|range| {
            (
                u64::from_le_bytes(range[..8].try_into().unwrap()),
                u16::from_le_bytes(range[8..10].try_into().unwrap()),
                u16::from_le_bytes(range[10..12].try_into().unwrap()),
                u32::from_le_bytes(range[12..16].try_into().unwrap()),
            )
        })
        .collect();
    // `_ranges_validate`: sorted, bounded, unflagged and disjoint.
    ranges.sort_by_key(|&(location, length, ..)| (location, length));
    if ranges.is_empty() {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    }
    for (index, &(location, length, recovery, flags)) in ranges.iter().enumerate() {
        let end = location.checked_add(u64::from(length));
        let valid = length <= TASK_RESTARTABLE_OFFSET_MAX
            && recovery <= TASK_RESTARTABLE_OFFSET_MAX
            && flags == 0
            && end.is_some()
            && location.checked_add(u64::from(recovery)).is_some()
            && ranges
                .get(index + 1)
                .is_none_or(|next| end.is_some_and(|end| end <= next.0));
        if !valid {
            return Reply::Failure(KERN_INVALID_ARGUMENT);
        }
    }
    let mut registered = lock(&kernel.process.restartable_ranges);
    if registered.is_some() {
        return Reply::Failure(KERN_NOT_SUPPORTED);
    }
    *registered = Some(ranges);
    Reply::Success(Vec::new())
}

/// A reply of two 64-bit out arguments.
fn pair(result: Result<(u64, u64), u32>) -> Reply {
    match result {
        Ok((first, second)) => {
            let mut body = first.to_le_bytes().to_vec();
            body.extend(second.to_le_bytes());
            Reply::Success(body)
        }
        Err(status) => Reply::Failure(status),
    }
}

/// `mach_vm_map` on this task: one port descriptor (the memory object),
/// then `address`, `size`, `mask`, `flags`, `offset`, `copy`,
/// `cur_protection`, `max_protection` and `inheritance`. Anonymous memory
/// (a null object) is mapped in the guest's pages, a memory object as
/// [`memory::map_object`] places it.
fn vm_map(request: &Request) -> Result<Reply> {
    const DESCRIPTORS: usize = 0;
    const OBJECT: usize = 4;
    const ADDRESS: usize = 24;
    let field = |at: usize| request.word(at);
    let (Some(1), Some(object)) = (field(DESCRIPTORS), field(OBJECT)) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let (Some(address), Some(size), Some(mask), Some(flags), Some(offset)) = (
        request.double(ADDRESS),
        request.double(ADDRESS + 8),
        request.double(ADDRESS + 16),
        field(ADDRESS + 24),
        request.double(ADDRESS + 28),
    ) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let (Some(copy), Some(current), Some(maximum), Some(inheritance)) = (
        field(ADDRESS + 36),
        field(ADDRESS + 40),
        field(ADDRESS + 44),
        field(ADDRESS + 48),
    ) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let (status, placed) = if object == 0 {
        memory::map_anonymous(
            address,
            size,
            mask,
            flags as i32,
            copy != 0,
            Protection(current as i32),
            Protection(maximum as i32),
            inheritance,
        )
    } else {
        memory::map_object(
            address,
            size,
            mask,
            flags as i32,
            object,
            offset,
            copy != 0,
            Protection(current as i32),
            Protection(maximum as i32),
            inheritance,
        )
    };
    Ok(if status == 0 {
        Reply::Success(placed.to_le_bytes().to_vec())
    } else {
        Reply::Failure(status as u32)
    })
}

/// `osfmk/mach/host_info.h` statistics flavors.
const HOST_VM_INFO: u32 = 2;
const HOST_VM_INFO64: u32 = 4;
/// The words of `vm_statistics` and `vm_statistics64` that count resident
/// or compressed pages (free, active, inactive, wired, purgeable,
/// speculative; for the 64-bit form also the compressor's, throttled,
/// external and internal pages and, as 64-bit pairs, the uncompressed
/// pages in the compressor and the swapped pages of rev2). Event counters
/// stay as the host counts them.
const VM_INFO_PAGE_WORDS: [usize; 6] = [0, 1, 2, 3, 12, 14];
const VM_INFO64_PAGE_WORDS: [usize; 10] = [0, 1, 2, 3, 22, 23, 32, 33, 34, 35];
const VM_INFO64_PAGE_PAIRS: [usize; 2] = [36, 38];
/// Rev3's tag storage and tagged-page statistics, from this word on: zero
/// on a profile without memory tagging, which has no tag storage.
const VM_INFO64_TAGGING: usize = 40;
/// Host pages per guest page.
const HOST_PAGES_PER_PAGE: u32 = (memory::PAGE_BYTES / (memory::HOST_PAGE_MASK + 1)) as u32;

/// `host_statistics` and `host_statistics64` on the host port: the x86
/// host's own answer, the same layout in both ABIs, with its page counts
/// restated in the guest's 16 KiB pages, as an arm64 kernel counts them.
fn host_statistics(
    hardware: &hardware::Hardware,
    sixty_four: bool,
    flavor: u32,
    count: u32,
) -> Result<Reply> {
    let mut words = [0i32; HOST_INFO_MAX as usize];
    let mut filled = count;
    // SAFETY: `words` holds `count` integers, at most HOST_INFO_MAX; the
    // host port right is released after the call.
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_host_self() -> u32;
        fn host_statistics(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn host_statistics64(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
    }
    let status = unsafe {
        let host = mach_host_self();
        let status = if sixty_four {
            host_statistics64(host, flavor as i32, words.as_mut_ptr(), &mut filled)
        } else {
            host_statistics(host, flavor as i32, words.as_mut_ptr(), &mut filled)
        };
        mach_port_deallocate(mach_task_self_, host);
        status
    };
    if status != 0 {
        return Ok(Reply::Failure(status as u32));
    }
    let mut words: Vec<u32> = words[..filled.min(HOST_INFO_MAX) as usize]
        .iter()
        .map(|&word| word as u32)
        .collect();
    if flavor == HOST_VM_INFO64 && words.len() > VM_INFO64_TAGGING && hardware.memory_tagging {
        bail!(
            "host_statistics64(HOST_VM_INFO64) of {} words: the tag storage statistics of a \
             profile with memory tagging are not modeled",
            words.len()
        );
    }
    restate_pages(&mut words, flavor);
    let mut body = (words.len() as u32).to_le_bytes().to_vec();
    for word in words {
        body.extend(word.to_le_bytes());
    }
    Ok(Reply::Success(body))
}

/// Restate the page counts of a `flavor` statistics reply in guest pages,
/// for a profile without memory tagging.
fn restate_pages(words: &mut [u32], flavor: u32) {
    let pages: &[usize] = match flavor {
        HOST_VM_INFO => &VM_INFO_PAGE_WORDS,
        HOST_VM_INFO64 => &VM_INFO64_PAGE_WORDS,
        _ => return,
    };
    for &index in pages {
        if let Some(word) = words.get_mut(index) {
            *word /= HOST_PAGES_PER_PAGE;
        }
    }
    if flavor != HOST_VM_INFO64 {
        return;
    }
    for index in VM_INFO64_PAGE_PAIRS {
        if let Some(pair) = words.get_mut(index..index + 2) {
            let pages =
                (u64::from(pair[0]) | u64::from(pair[1]) << 32) / u64::from(HOST_PAGES_PER_PAGE);
            pair[0] = pages as u32;
            pair[1] = (pages >> 32) as u32;
        }
    }
    if let Some(tagging) = words.get_mut(VM_INFO64_TAGGING..) {
        tagging.fill(0);
    }
}

/// `host_info_t`'s MIG bound (`array[*:68] of integer_t`).
const HOST_INFO_MAX: u32 = 68;
const HOST_BASIC_INFO: u32 = 1;
const HOST_SCHED_INFO: u32 = 3;
const HOST_RESOURCE_SIZES: u32 = 4;
const HOST_PRIORITY_INFO: u32 = 5;
const HOST_SEMAPHORE_TRAPS: u32 = 7;
const HOST_MACH_MSG_TRAP: u32 = 8;
const HOST_VM_PURGABLE: u32 = 9;
const HOST_DEBUG_INFO_INTERNAL: u32 = 10;
const HOST_CAN_HAS_DEBUGGER: u32 = 11;
const HOST_PREFERRED_USER_ARCH: u32 = 12;
const HOST_BASIC_INFO_OLD_COUNT: u32 = 5;
const HOST_BASIC_INFO_COUNT: u32 = 12;
const HOST_SCHED_INFO_COUNT: u32 = 2;
const HOST_RESOURCE_SIZES_COUNT: u32 = 5;
const HOST_PRIORITY_INFO_COUNT: u32 = 8;
const HOST_CAN_HAS_DEBUGGER_COUNT: u32 = 1;
const HOST_PREFERRED_USER_ARCH_COUNT: u32 = 2;
/// `std_quantum`: `1 s / DEFAULT_PREEMPTION_RATE (100)`, in milliseconds.
const STANDARD_QUANTUM_MS: u32 = 10;
/// `osfmk/kern/sched.h`: `MINPRI_KERNEL`, `MINPRI_RESERVED`,
/// `BASEPRI_DEFAULT`, `DEPRESSPRI`, `IDLEPRI`, `MINPRI_USER`,
/// `MAXPRI_RESERVED`.
const PRIORITIES: [u32; 8] = [80, 80, 64, 31, 0, 0, 0, 79];
const CPU_THREADTYPE_NONE: u32 = 0;

/// `host_info` (`osfmk/kern/host.c`) on the hosted machine; `count` is the
/// caller's capacity in `integer_t`s.
fn host_info(hardware: &hardware::Hardware, flavor: u32, count: u32) -> Reply {
    let cpus = u32::from(hardware.cpus());
    let words: Vec<u32> = match flavor {
        HOST_BASIC_INFO => {
            if count < HOST_BASIC_INFO_OLD_COUNT {
                return Reply::Failure(KERN_FAILURE);
            }
            // `memory_size` is `machine_conf`'s 32-bit truncation of the
            // memory size; `max_mem` the whole.
            let mut words = vec![
                cpus,
                cpus,
                hardware.memory_bytes as u32,
                hardware::CPU_TYPE_ARM64,
                hardware::CPU_SUBTYPE_ARM64E,
            ];
            if count >= HOST_BASIC_INFO_COUNT {
                words.extend([CPU_THREADTYPE_NONE, cpus, cpus, cpus, cpus]);
                words.extend([
                    hardware.memory_bytes as u32,
                    (hardware.memory_bytes >> 32) as u32,
                ]);
            }
            words
        }
        HOST_SCHED_INFO => {
            if count < HOST_SCHED_INFO_COUNT {
                return Reply::Failure(KERN_FAILURE);
            }
            vec![STANDARD_QUANTUM_MS, STANDARD_QUANTUM_MS]
        }
        HOST_RESOURCE_SIZES => {
            return Reply::Failure(if count < HOST_RESOURCE_SIZES_COUNT {
                KERN_FAILURE
            } else {
                KERN_INVALID_ARGUMENT
            });
        }
        HOST_PRIORITY_INFO => {
            if count < HOST_PRIORITY_INFO_COUNT {
                return Reply::Failure(KERN_FAILURE);
            }
            PRIORITIES.to_vec()
        }
        HOST_MACH_MSG_TRAP | HOST_SEMAPHORE_TRAPS => Vec::new(),
        HOST_CAN_HAS_DEBUGGER => {
            if count < HOST_CAN_HAS_DEBUGGER_COUNT {
                return Reply::Failure(KERN_FAILURE);
            }
            // `PE_i_can_has_debugger` on a release kernel without debug
            // boot arguments.
            vec![0]
        }
        // The release kernel's answer.
        HOST_DEBUG_INFO_INTERNAL => return Reply::Failure(KERN_NOT_SUPPORTED),
        HOST_PREFERRED_USER_ARCH => {
            if count < HOST_PREFERRED_USER_ARCH_COUNT {
                return Reply::Failure(KERN_FAILURE);
            }
            vec![hardware::CPU_TYPE_ARM64, hardware::CPU_SUBTYPE_ARM64E]
        }
        HOST_VM_PURGABLE => {
            // Host-wide purgeable-memory statistics are not modeled.
            return Reply::Failure(KERN_NOT_SUPPORTED);
        }
        _ => return Reply::Failure(KERN_INVALID_ARGUMENT),
    };
    let mut body = (words.len() as u32).to_le_bytes().to_vec();
    for word in words {
        body.extend(word.to_le_bytes());
    }
    Reply::Success(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Chip;

    fn words(reply: Reply) -> Vec<u32> {
        let Reply::Success(body) = reply else {
            panic!("host_info failed");
        };
        body.as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect()
    }

    #[test]
    fn reply_descriptors_have_the_lp64_layout() {
        let ports = Descriptor::Ports {
            names: vec![0x1303, 0x1403],
            disposition: COPY_SEND,
        };
        let bytes = ports.bytes();
        let Descriptor::Ports { names, .. } = &ports else {
            unreachable!()
        };
        assert_eq!(bytes[..8], (names.as_ptr() as u64).to_le_bytes());
        assert_eq!(bytes[8..], [0, 1, COPY_SEND, 2, 2, 0, 0, 0]);
        let memory = Descriptor::Memory {
            address: 0x1_2345_6789,
            size: 0x10,
            deallocate: true,
        };
        assert_eq!(
            memory.bytes(),
            [
                0x89, 0x67, 0x45, 0x23, 1, 0, 0, 0, 1, 1, 0, 1, 0x10, 0, 0, 0
            ]
        );
    }

    #[test]
    fn vm_statistics_count_guest_pages() {
        let mut vm = vec![400u32; 15];
        restate_pages(&mut vm, HOST_VM_INFO);
        assert_eq!(&vm[..5], &[100, 100, 100, 100, 400]);
        assert_eq!((vm[12], vm[13], vm[14]), (100, 400, 100));
        let mut vm64 = vec![8u32; 62];
        vm64[36] = 0;
        vm64[37] = 4;
        restate_pages(&mut vm64, HOST_VM_INFO64);
        assert_eq!(&vm64[..5], &[2, 2, 2, 2, 8]);
        assert_eq!(&vm64[32..42], &[2, 2, 2, 2, 0, 1, 2, 2, 0, 0]);
        assert!(vm64[40..].iter().all(|&word| word == 0));
        let mut load = vec![400u32; 6];
        restate_pages(&mut load, 1);
        assert_eq!(load, [400; 6]);
        // The host answers the load and VM flavors.
        let hardware = hardware::Hardware::of(Chip::AppleM2, 0x4_0000_0000).unwrap();
        let Ok(Reply::Success(body)) = host_statistics(&hardware, true, HOST_VM_INFO64, 38) else {
            panic!("host_statistics64 failed");
        };
        assert_eq!(u32::from_le_bytes(body[..4].try_into().unwrap()), 38);
        // A profile with memory tagging has tag storage the host lacks.
        let tagging = hardware::Hardware {
            memory_tagging: true,
            ..hardware.clone()
        };
        assert!(host_statistics(&tagging, true, HOST_VM_INFO64, 38).is_ok());
        let full = host_statistics(&tagging, true, HOST_VM_INFO64, HOST_INFO_MAX);
        let host_rev3 = matches!(
            host_statistics(&hardware, true, HOST_VM_INFO64, HOST_INFO_MAX),
            Ok(Reply::Success(body)) if u32::from_le_bytes(body[..4].try_into().unwrap()) > 40
        );
        assert_eq!(full.is_err(), host_rev3);
    }

    #[test]
    fn the_default_processor_set_holds_every_processor() {
        let hardware = hardware::Hardware::of(Chip::AppleM2, 0x4_0000_0000).unwrap();
        let Reply::Complex { descriptors, body } =
            processor_set_info(&hardware, 0x103, PROCESSOR_SET_BASIC_INFO, 8)
        else {
            panic!("processor_set_info failed");
        };
        assert!(matches!(
            descriptors[..],
            [Descriptor::Port {
                name: 0x103,
                disposition: COPY_SEND
            }]
        ));
        assert_eq!(body, [2, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0]);
        assert!(matches!(
            processor_set_info(&hardware, 0x103, PROCESSOR_SET_BASIC_INFO, 1),
            Reply::Failure(KERN_FAILURE)
        ));
        // The policy constants are the host kernel's too.
        assert!(matches!(
            processor_set_info(&hardware, 0x103, 10, 8),
            Reply::Forward
        ));
    }

    #[test]
    fn processor_records_describe_the_m2_processors() {
        let hardware = hardware::Hardware::of(Chip::AppleM2, 0x4_0000_0000).unwrap();
        let Reply::Complex { descriptors, body } =
            processor_info(&hardware, PROCESSOR_BASIC_INFO).unwrap()
        else {
            panic!("host_processor_info failed");
        };
        assert_eq!(body, [8, 0, 0, 0, 40, 0, 0, 0]);
        let [Descriptor::Memory { address, size, .. }] = descriptors[..] else {
            panic!("no out-of-line records");
        };
        assert_eq!(size, 160);
        // SAFETY: the records the reply would carry.
        let records = unsafe { std::slice::from_raw_parts(address as *const u32, 40) };
        assert_eq!(&records[..5], &[hardware::CPU_TYPE_ARM64, 2, 1, 0, 1]);
        assert_eq!(&records[35..], &[hardware::CPU_TYPE_ARM64, 2, 1, 7, 0]);
        unsafe extern "C" {
            fn mach_vm_deallocate(task: u32, address: u64, size: u64) -> i32;
        }
        // SAFETY: the allocation the reply's send would release.
        unsafe { mach_vm_deallocate(crate::hosted::host::task(), address, u64::from(size)) };
        assert!(matches!(
            processor_info(&hardware, 99).unwrap(),
            Reply::Failure(KERN_FAILURE)
        ));
        assert!(processor_info(&hardware, PROCESSOR_CPU_LOAD_INFO).is_err());
    }

    #[test]
    fn host_info_describes_the_hosted_machine() {
        let hardware = hardware::Hardware::of(Chip::AppleM2, 0x4_0000_0000).unwrap();
        let basic = words(host_info(&hardware, HOST_BASIC_INFO, HOST_INFO_MAX));
        assert_eq!(basic[0], HOST_BASIC_INFO_COUNT);
        assert_eq!(&basic[1..6], &[8, 8, 0, hardware::CPU_TYPE_ARM64, 2]);
        assert_eq!(&basic[11..13], &[0, 4]);
        let old = words(host_info(&hardware, HOST_BASIC_INFO, 5));
        assert_eq!(old[0], HOST_BASIC_INFO_OLD_COUNT);
        assert!(matches!(
            host_info(&hardware, HOST_BASIC_INFO, 4),
            Reply::Failure(KERN_FAILURE)
        ));
        assert_eq!(
            words(host_info(&hardware, HOST_SCHED_INFO, HOST_INFO_MAX)),
            [2, 10, 10]
        );
        assert_eq!(
            words(host_info(&hardware, HOST_MACH_MSG_TRAP, HOST_INFO_MAX)),
            [0]
        );
    }
}
