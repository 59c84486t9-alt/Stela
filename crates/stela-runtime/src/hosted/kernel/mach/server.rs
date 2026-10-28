//! The kernel-object MIG routines the hosted kernel answers itself: those
//! whose answer describes the arm64 machine rather than the x86 host. Each
//! returns its reply body after the header (`NDR_record`, `RetCode`, then
//! the out arguments), as the routine's MIG server stub lays it out, or a
//! failing `RetCode` for the short `mig_reply_error_t`.
use super::super::{Kernel, control};
use super::{accounting, reclaim};
use crate::hosted::darwin::{
    self, ARM_DEBUG_STATE64, DEBUG_STATE64_COUNT, EINVAL, KERN_FAILURE, KERN_INVALID_ARGUMENT,
    KERN_NOT_SUPPORTED, mach_host_self,
};
use crate::hosted::threads::lock;
use crate::hosted::unsupported::{self, Failure};
use crate::hosted::{
    hardware,
    memory::{self, Protection},
};
pub(crate) use crate::hosted_registry::mach::server::{Object, refusal};
use anyhow::Result;

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
pub(crate) enum Reply {
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
pub(crate) enum Descriptor {
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
/// `MACH_MSG_TYPE_COPY_SEND`, as a descriptor's disposition byte.
pub(super) const COPY_SEND: u8 = darwin::MACH_MSG_TYPE_COPY_SEND as u8;
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

/// `MIG_BAD_ARGUMENTS`: the request is malformed.
pub(super) const MIG_BAD_ARGUMENTS: u32 = (-304i32) as u32;

/// `NDR_record` on both LP64 ABIs: little-endian, ASCII, IEEE floats.
pub(super) const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// Task routines whose answer is the arm64 kernel's: the request is
/// forwarded to the task port, which is the host task's. They suspend,
/// resume and terminate this task, act on its vouchers, dyld
/// notification ports and EXC_GUARD behavior (which the host kernel then
/// applies to the calls it serves), trace dyld's image registrations
/// (`kdebug` only) or answer as every release kernel does (the dyld
/// image list and state routines, the test upcalls, corpse forking). The
/// purgeable counts and the footprint limit are the host task's, which is
/// this process (process accounting).
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
            Some(which @ (TASK_NAME_PORT | TASK_INSPECT_PORT | TASK_READ_PORT)) => {
                unsupported::refuse!(
                    Failure::Kern(KERN_FAILURE),
                    "task_get_special_port({which}): the task's name, inspect and read ports, \
                     which as the host task's would answer for the x86 task"
                )
            }
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
            let (Some(parent), Some(size), Some(offset), Some(permission)) = (
                request.word(4),
                request.double(24),
                request.double(32),
                request.word(40),
            ) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            if (size | offset) & memory::PAGE_MASK == 0 || permission & MAP_MEM_ONLY != 0 {
                Reply::Forward
            } else {
                partial_memory_entry(port, parent, size, offset, permission)?
            }
        }
        // `node`, `which`. The host port is the host's, already this
        // process's host kernel object.
        // The IOKit main port. IOKit's own requests then go to the host's
        // registry, whose serialized properties have one layout in both
        // ABIs but describe the x86 machine.
        (Object::Host, "host_get_io_main", false) => Reply::Forward,
        (Object::Host, "host_kernel_version", false) => kernel_version(kernel),
        // `flavor`.
        (Object::Host, "host_processor_info", false) => match request.word(8) {
            Some(flavor) => processor_info(&kernel.process.hardware, port, flavor)?,
            None => Reply::Failure(MIG_BAD_ARGUMENTS),
        },
        // `vm_size_t`: the arm64 kernel's 16 KiB page.
        (Object::Host, "_host_page_size", false) => {
            Reply::Success(memory::PAGE_BYTES.to_le_bytes().to_vec())
        }
        // The pager port, then `internal`, `size` and `permission`.
        (
            Object::Host,
            "mach_memory_object_memory_entry" | "mach_memory_object_memory_entry_64",
            true,
        ) => {
            let (Some(pager), Some(internal), Some(size), Some(permission)) = (
                request.word(4),
                request.word(24),
                request.double(28),
                request.word(36),
            ) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            if pager == 0 && internal != 0 && size & memory::PAGE_MASK != 0 {
                internal_entry(port, size, permission)
            } else {
                Reply::Forward
            }
        }
        // `diagnostic_flag`. Without the private entitlement the host's
        // KERN_NO_ACCESS is the arm64 kernel's; with it the arm64 kernel
        // sets the machine-wide flag (`atm_set_diagnostic_config`), which
        // the host refuses the hosted runtime.
        (Object::Host, "host_set_atm_diagnostic_flag", false)
            if lock(&kernel.process.executable)
                .signature
                .as_ref()
                .is_some_and(|signature| signature.entitled(ATM_DIAGNOSTIC_ENTITLEMENT)) =>
        {
            unsupported::refuse!(
                Failure::Kern(KERN_NO_ACCESS),
                "host_set_atm_diagnostic_flag by a task entitled to it: setting the machine's \
                 diagnostic flag, which the host refuses the hosted runtime"
            )
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
        // `flavor`, `info_outCnt`: the boot set's load.
        (Object::ProcessorSet, "processor_set_statistics", false) => {
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            processor_set_statistics(
                &kernel.process.hardware,
                port,
                flavor,
                count.min(PROCESSOR_SET_INFO_MAX),
            )
        }
        // The boot set's tasks, which take the set's control port: only
        // the privileged host port gives it, so the host kernel refuses
        // the name port as the arm64 kernel does.
        (Object::ProcessorSet, "processor_set_tasks" | "processor_set_tasks_with_flavor", _) => {
            Reply::Forward
        }
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
        (Object::Task, "task_info_from_user", false) => super::task::info(kernel, port, request)?,
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
        // `flavor`, `info_outCnt`, which MIG bounds to 4. The process's
        // instructions and cycles are the host process's, as a Rosetta
        // process's are the real processor's (process accounting).
        (Object::Task, "task_inspect", false) => Reply::Forward,
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
        (Object::Task, "task_register_hardened_exception_handler", complex) => {
            if complex {
                super::exception::register(kernel, request)?
            } else {
                Reply::Failure(MIG_BAD_ARGUMENTS)
            }
        }
        (Object::Task, _, _) => return super::vm::serve(kernel, routine, complex, request),
        (Object::Thread, _, _) => {
            return super::thread::serve(kernel, port, routine, complex, request);
        }
        _ => return Ok(None),
    }))
}

/// A routine whose only out argument is its `kern_return_t`.
pub(super) fn status(code: u32) -> Reply {
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
/// `MACH_VM_MAX_ADDRESS` of a 64-bit macOS task.
const MACH_VM_MAX_ADDRESS: u64 = 0x0000_7fff_fe00_0000;

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
            // `debug_state_is_valid64`: a used pair's address is a user
            // address.
            let invalid = |control: usize, value: usize, pairs: u64| {
                (0..pairs as usize).any(|index| {
                    debug_double(&words, control + index) != 0
                        && debug_double(&words, value + index) >= MACH_VM_MAX_ADDRESS
                })
            };
            let hardware = &kernel.process.hardware;
            if invalid(16, 0, hardware.breakpoints) || invalid(48, 32, hardware.watchpoints) {
                return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
            }
            const ENABLE: u64 = 1;
            const MDSCR_SS: u64 = 1;
            if debug_double(&words, 64) & MDSCR_SS != 0
                || (16..32)
                    .chain(48..64)
                    .any(|index| debug_double(&words, index) & ENABLE != 0)
            {
                unsupported::refuse!(
                    Failure::Kern(KERN_FAILURE),
                    "task_set_state(ARM_DEBUG_STATE64) enabling a hardware breakpoint, watchpoint \
                     or single step for new threads, whose debug exceptions"
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
                            return Ok(Err(EINVAL));
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

/// Host routines whose answer is the arm64 kernel's: the request is
/// forwarded to the host port. The host-privileged routines refuse the
/// host port as an unprivileged arm64 process's kernel refuses it (only
/// root obtains the privileged port); the others act on this machine's
/// calendar notifications, vouchers and flags, answer as every release
/// kernel does (`kmod_get_info`, `host_virtual_physical_table_info`), or
/// describe the kernel beneath this process, the host's (its lock groups,
/// zones and memory: kernel-internal state).
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

/// The entitlement `host_set_atm_diagnostic_flag` requires.
const ATM_DIAGNOSTIC_ENTITLEMENT: &str = "com.apple.private.set-atm-diagnostic-flag";

/// `mach_make_memory_entry_64` flags (`mach/memory_object_types.h`).
const MAP_MEM_ONLY: u32 = 0x01_0000;
const MAP_MEM_USE_DATA_ADDR: u32 = 0x10_0000;
#[cfg(test)]
const MAP_MEM_VM_SHARE: u32 = 0x40_0000;
const MAP_MEM_4K_DATA_ADDR: u32 = 0x80_0000;

/// `mach_make_memory_entry_64(task, size, offset, permission, parent)` of
/// a range in partial guest pages. An entry made from this task's map (a
/// share, copy or new object) or of a parent entry's range
/// (`mach_make_memory_entry_from_parent_entry`) spans the range rounded
/// out to the kernel's 16 KiB pages (`vm_sanitize_addr_size`),
/// KERN_INVALID_ARGUMENT when that overflows or passes the parent's end,
/// and answers that span's size less the data's offset in it: the host
/// makes it from the rounded range, which its 4 KiB rounding keeps. A
/// data-address entry (`MAP_MEM_USE_DATA_ADDR`, `MAP_MEM_4K_DATA_ADDR`)
/// keeps its start, whose offset in its guest page the host's offset in
/// its own page then is only below 4 KiB.
fn partial_memory_entry(
    task: u32,
    parent: u32,
    size: u64,
    offset: u64,
    permission: u32,
) -> Result<Reply> {
    unsafe extern "C" {
        fn mach_make_memory_entry_64(
            task: u32,
            size: *mut u64,
            offset: u64,
            permission: i32,
            entry: *mut u32,
            parent: u32,
        ) -> i32;
    }
    let data = permission & (MAP_MEM_USE_DATA_ADDR | MAP_MEM_4K_DATA_ADDR) != 0;
    if size == 0 || (data && offset & memory::PAGE_MASK & !memory::HOST_PAGE_MASK != 0) {
        unsupported::refuse!(
            Failure::Kern(KERN_FAILURE),
            "mach_make_memory_entry of {size:#x} bytes at {offset:#x} (permission \
             {permission:#x}): a range in partial guest pages"
        );
    }
    let Some(end) = offset.checked_add(size).and_then(memory::round_page) else {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    };
    let start = if data {
        offset
    } else {
        offset & !memory::PAGE_MASK
    };
    let mut span = end - start;
    let mut entry = 0;
    // SAFETY: this task's port, the guest's parent entry name and out
    // arguments of this frame.
    let code = unsafe {
        mach_make_memory_entry_64(
            task,
            &raw mut span,
            start,
            permission as i32,
            &raw mut entry,
            parent,
        )
    } as u32;
    if code != darwin::KERN_SUCCESS {
        return Ok(Reply::Failure(code));
    }
    Ok(Reply::Complex {
        descriptors: vec![Descriptor::Port {
            name: entry,
            disposition: MOVE_SEND,
        }],
        body: span.to_le_bytes().to_vec(),
    })
}

/// `mach_memory_object_memory_entry_64(host, TRUE, size, permission,
/// MEMORY_OBJECT_NULL)` of a size in partial guest pages: the entry's
/// object is the size rounded to the kernel's 16 KiB page
/// (`vm_sanitize_object_size`, KERN_INVALID_ARGUMENT when that overflows),
/// which the host makes with that size since its own 4 KiB rounding keeps
/// it.
fn internal_entry(host: u32, size: u64, permission: u32) -> Reply {
    unsafe extern "C" {
        fn mach_memory_object_memory_entry_64(
            host: u32,
            internal: i32,
            size: u64,
            permission: i32,
            pager: u32,
            entry: *mut u32,
        ) -> i32;
    }
    let Some(size) = memory::round_page(size) else {
        return Reply::Failure(KERN_INVALID_ARGUMENT);
    };
    let mut entry = 0;
    // SAFETY: the host port this request was sent to and an out name.
    let code = unsafe {
        mach_memory_object_memory_entry_64(host, 1, size, permission as i32, 0, &raw mut entry)
    } as u32;
    if code != darwin::KERN_SUCCESS {
        return Reply::Failure(code);
    }
    Reply::Descriptors(vec![Descriptor::Port {
        name: entry,
        disposition: MOVE_SEND,
    }])
}

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
    let cpus = u32::from(hardware.active_cpus());
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

/// `PROCESSOR_SET_LOAD_INFO`: `task_count`, `thread_count`,
/// `load_average`, `mach_factor`.
const PROCESSOR_SET_LOAD_INFO: u32 = 4;
const PROCESSOR_SET_LOAD_AVERAGE: usize = 2;
const PROCESSOR_SET_MACH_FACTOR: usize = 3;

/// `processor_set_statistics` on the default processor set `set`: the host
/// machine's task and thread counts and load average, and the Mach factor
/// of that load over the profile's processors (machine accounting). The
/// kernels refuse every other flavor alike.
fn processor_set_statistics(
    hardware: &hardware::Hardware,
    set: u32,
    flavor: u32,
    count: u32,
) -> Reply {
    unsafe extern "C" {
        fn processor_set_statistics(set: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    }
    let mut words = [0i32; PROCESSOR_SET_INFO_MAX as usize];
    let mut filled = count;
    // SAFETY: `words` holds `count` integers, at most its length.
    let code =
        unsafe { processor_set_statistics(set, flavor as i32, words.as_mut_ptr(), &mut filled) };
    if code != 0 {
        return Reply::Failure(code as u32);
    }
    let mut words: Vec<u32> = words[..filled.min(count) as usize]
        .iter()
        .map(|&word| word as u32)
        .collect();
    if flavor == PROCESSOR_SET_LOAD_INFO && words.len() > PROCESSOR_SET_MACH_FACTOR {
        words[PROCESSOR_SET_MACH_FACTOR] = accounting::mach_factor(
            words[PROCESSOR_SET_LOAD_AVERAGE],
            hardware.active_cpus().into(),
        );
    }
    let mut body = (words.len() as u32).to_le_bytes().to_vec();
    for word in words {
        body.extend(word.to_le_bytes());
    }
    Reply::Success(body)
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
/// the master. The load ticks are the host processors' folded onto the
/// profile's (machine accounting). The arm64 exception counters
/// (`PROCESSOR_CPU_STAT`, `_STAT64`) count exceptions the arm64 kernel
/// takes, which the x86 host kernel does not: they stop the run. Other
/// flavors fail in `processor_info_count`.
fn processor_info(hardware: &hardware::Hardware, host: u32, flavor: u32) -> Result<Reply> {
    let cpus = u32::from(hardware.cpus());
    let (words, per_cpu) = match flavor {
        PROCESSOR_BASIC_INFO => (
            (0..cpus)
                .flat_map(|slot| {
                    [
                        hardware::CPU_TYPE_ARM64,
                        hardware::CPU_SUBTYPE_ARM64E,
                        u32::from(slot < u32::from(hardware.active_cpus())),
                        slot,
                        u32::from(slot == 0),
                    ]
                })
                .collect::<Vec<u32>>(),
            PROCESSOR_BASIC_INFO_COUNT,
        ),
        PROCESSOR_CPU_LOAD_INFO => {
            if hardware.native_availability().is_some() {
                unsupported::refuse!(
                    Failure::Kern(KERN_FAILURE),
                    "host_processor_info: native logical CPU ticks have no qualified \
                     physical-core attribution for the shared guest execution group"
                );
            }
            let ticks = match host_load_ticks(host) {
                Ok(ticks) => ticks,
                Err(code) => return Ok(Reply::Failure(code)),
            };
            (
                accounting::fold(&ticks, cpus as usize)
                    .into_iter()
                    .flatten()
                    .collect(),
                accounting::CPU_STATES as u32,
            )
        }
        PROCESSOR_CPU_STAT | PROCESSOR_CPU_STAT64 => unsupported::refuse!(
            Failure::Kern(KERN_FAILURE),
            "host_processor_info flavor {flavor:#x}: the arm64 kernel's exception counters of \
             the profile's {cpus} processors, which have no host counterpart"
        ),
        _ => return Ok(Reply::Failure(KERN_FAILURE)),
    };
    let Some(memory) = out_of_line(&words) else {
        return Ok(Reply::Failure(KERN_RESOURCE_SHORTAGE));
    };
    let mut body = cpus.to_le_bytes().to_vec();
    body.extend((cpus * per_cpu).to_le_bytes());
    Ok(Reply::Complex {
        descriptors: vec![memory],
        body,
    })
}

/// The host processors' load ticks (`PROCESSOR_CPU_LOAD_INFO`) through
/// the host port `host`, or the host kernel's failure.
fn host_load_ticks(host: u32) -> Result<Vec<[u32; accounting::CPU_STATES]>, u32> {
    unsafe extern "C" {
        fn host_processor_info(
            host: u32,
            flavor: i32,
            count: *mut u32,
            info: *mut *mut i32,
            info_count: *mut u32,
        ) -> i32;
        fn mach_vm_deallocate(task: u32, address: u64, size: u64) -> i32;
    }
    let (mut processors, mut info, mut words) = (0u32, std::ptr::null_mut::<i32>(), 0u32);
    // SAFETY: out arguments of this frame; the host's array is new memory
    // of this task, released below.
    let code = unsafe {
        host_processor_info(
            host,
            PROCESSOR_CPU_LOAD_INFO as i32,
            &raw mut processors,
            &raw mut info,
            &raw mut words,
        )
    };
    if code != 0 {
        return Err(code as u32);
    }
    let length = (processors as usize * accounting::CPU_STATES).min(words as usize);
    // SAFETY: the host's array of `words` integers.
    let ticks = unsafe { std::slice::from_raw_parts(info.cast::<u32>(), length) }
        .as_chunks::<{ accounting::CPU_STATES }>()
        .0
        .to_vec();
    // SAFETY: the array the host kernel moved into this task.
    unsafe {
        mach_vm_deallocate(
            crate::hosted::host::task(),
            info as u64,
            u64::from(words) * 4,
        )
    };
    Ok(ticks)
}

/// `words` in new memory of this task, as an out-of-line descriptor the
/// reply's send releases; `None` when no memory could be had.
fn out_of_line(words: &[u32]) -> Option<Descriptor> {
    unsafe extern "C" {
        fn mach_vm_allocate(task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
    }
    const VM_FLAGS_ANYWHERE: i32 = 1;
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut address = 0u64;
    // SAFETY: new memory of this task.
    let code = unsafe {
        mach_vm_allocate(
            crate::hosted::host::task(),
            &mut address,
            bytes.len() as u64,
            VM_FLAGS_ANYWHERE,
        )
    };
    if code != 0 {
        return None;
    }
    // SAFETY: the allocation holds the bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
    Some(Descriptor::Memory {
        address,
        size: bytes.len() as u32,
        deallocate: true,
    })
}

/// `kernel_version_t`'s bound.
const KERNEL_VERSION_MAX: usize = 512;

/// `host_kernel_version`: the board's kernel version string, as
/// `kern.version` gives it, as a MIG string (offset, count with the NUL,
/// the bytes padded to a word). It fails when the guest system's install
/// did not record the version, as `kern.version` is then absent.
fn kernel_version(kernel: &Kernel) -> Reply {
    let Some(version) = &kernel.process.hardware.kernel_version else {
        return Reply::Failure(KERN_FAILURE);
    };
    let mut string = version.as_bytes().to_vec();
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
const HOST_LOAD_INFO: u32 = 1;
const HOST_VM_INFO: u32 = 2;
const HOST_CPU_LOAD_INFO: u32 = 3;
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
/// Rev3's tag storage and tagged-page statistics, eleven 64-bit counts
/// from this word on: the total tag storage pages, those holding pageable
/// and wired non-tag data, the free ones and those storing tags, then the
/// tagged pages (virtual, resident, compressed), tagged compressions and
/// decompressions and the compressed tag bytes.
const VM_INFO64_TAGGING: usize = 40;
const VM_INFO64_TAG_STORAGE_FREE: usize = 46;
/// `HOST_VM_INFO64_COUNT` of rev3.
const VM_INFO64_REV3_COUNT: usize = 62;
/// Memory per byte of tag storage: a 4-bit allocation tag per 16-byte
/// granule (Arm ARM, FEAT_MTE2).
const TAG_STORAGE_RATIO: u64 = 32;
/// Host pages per guest page.
const HOST_PAGES_PER_PAGE: u32 = (memory::PAGE_BYTES / (memory::HOST_PAGE_MASK + 1)) as u32;

/// `host_load_info`: `avenrun[3]`, then `mach_factor[3]`.
const LOAD_AVERAGES: usize = 3;

/// The Mach factors of a `host_load_info` reply restated from its load
/// averages over the profile's `cpus` processors.
fn restate_load(words: &mut [u32], cpus: u32) {
    for index in 0..LOAD_AVERAGES {
        if let (Some(&load), true) = (words.get(index), words.len() > LOAD_AVERAGES + index) {
            words[LOAD_AVERAGES + index] = accounting::mach_factor(load, cpus);
        }
    }
}

/// `host_statistics` and `host_statistics64` on the host port: the host
/// machine's answer (machine accounting), the same layout in both ABIs,
/// with its page counts restated in the guest's 16 KiB pages, as an arm64
/// kernel counts them, and its Mach factors over the profile's
/// processors. Rev3's tag statistics are the profile's
/// ([`tag_storage_pages`]).
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
        fn host_statistics(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn host_statistics64(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    }
    let status = unsafe {
        let host = mach_host_self();
        let status = if sixty_four {
            host_statistics64(host, flavor as i32, words.as_mut_ptr(), &mut filled)
        } else {
            host_statistics(host, flavor as i32, words.as_mut_ptr(), &mut filled)
        };
        release_send(host);
        status
    };
    if status != 0 {
        return Ok(Reply::Failure(status as u32));
    }
    if flavor == HOST_CPU_LOAD_INFO && hardware.native_availability().is_some() {
        unsupported::refuse!(
            Failure::Kern(KERN_FAILURE),
            "host_statistics: native logical CPU ticks have no qualified physical-core \
             attribution for the shared guest execution group"
        );
    }
    let mut words: Vec<u32> = words[..filled.min(HOST_INFO_MAX) as usize]
        .iter()
        .map(|&word| word as u32)
        .collect();
    if flavor == HOST_VM_INFO64 && count as usize >= VM_INFO64_REV3_COUNT {
        // The arm64 kernel always keeps rev3's words, which the profile
        // answers whether or not the host kernel has them.
        words.resize(words.len().max(VM_INFO64_REV3_COUNT), 0);
    }
    let tagging = crate::hosted::pe::memory_tagging(hardware.memory_tagging);
    restate_pages(
        &mut words,
        flavor,
        tag_storage_pages(hardware.memory_bytes, tagging),
    );
    if flavor == HOST_LOAD_INFO {
        restate_load(&mut words, hardware.active_cpus().into());
    }
    let mut body = (words.len() as u32).to_le_bytes().to_vec();
    for word in words {
        body.extend(word.to_le_bytes());
    }
    Ok(Reply::Success(body))
}

/// The tag storage of the hosted machine's `memory_bytes`, in guest pages:
/// on a machine presenting memory tagging (`pe::memory_tagging`), the
/// memory's share holding its allocation tags, none of it storing tags or
/// reused for other data, since no page of the hosted machine is tagged;
/// without memory tagging, none.
fn tag_storage_pages(memory_bytes: u64, tagging: bool) -> u64 {
    if tagging {
        memory_bytes / TAG_STORAGE_RATIO / memory::PAGE_BYTES
    } else {
        0
    }
}

/// Restate the page counts of a `flavor` statistics reply in guest pages,
/// with `tag_storage` free tag storage pages.
fn restate_pages(words: &mut [u32], flavor: u32, tag_storage: u64) {
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
    for index in [VM_INFO64_TAGGING, VM_INFO64_TAG_STORAGE_FREE] {
        if let Some(pair) = words.get_mut(index..index + 2) {
            pair[0] = tag_storage as u32;
            pair[1] = (tag_storage >> 32) as u32;
        }
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
    let active = u32::from(hardware.active_cpus());
    let words: Vec<u32> = match flavor {
        HOST_BASIC_INFO => {
            if count < HOST_BASIC_INFO_OLD_COUNT {
                return Reply::Failure(KERN_FAILURE);
            }
            // `memory_size` is `machine_conf`'s 32-bit truncation of the
            // memory size; `max_mem` the whole.
            let mut words = vec![
                cpus,
                active,
                hardware.memory_bytes as u32,
                hardware::CPU_TYPE_ARM64,
                hardware::CPU_SUBTYPE_ARM64E,
            ];
            if count >= HOST_BASIC_INFO_COUNT {
                words.extend([CPU_THREADTYPE_NONE, active, cpus, active, cpus]);
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
    use stela_contracts::Chip;

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
        restate_pages(&mut vm, HOST_VM_INFO, 0);
        assert_eq!(&vm[..5], &[100, 100, 100, 100, 400]);
        assert_eq!((vm[12], vm[13], vm[14]), (100, 400, 100));
        let mut vm64 = vec![8u32; 62];
        vm64[36] = 0;
        vm64[37] = 4;
        restate_pages(&mut vm64, HOST_VM_INFO64, 0);
        assert_eq!(&vm64[..5], &[2, 2, 2, 2, 8]);
        assert_eq!(&vm64[32..42], &[2, 2, 2, 2, 0, 1, 2, 2, 0, 0]);
        assert!(vm64[40..].iter().all(|&word| word == 0));
        let mut load = vec![400u32; 6];
        restate_pages(&mut load, 1, 0);
        assert_eq!(load, [400; 6]);
        // The host answers the load and VM flavors, rev3's tag storage
        // zero on every profile: the hosted machine presents no memory
        // tagging, even on a chip with it.
        let hardware = hardware::Hardware::of(Chip::AppleM2, 0x4_0000_0000).unwrap();
        let mut tagging = hardware.clone();
        tagging.memory_tagging = true;
        for profile in [&hardware, &tagging] {
            let Ok(Reply::Success(body)) =
                host_statistics(profile, true, HOST_VM_INFO64, HOST_INFO_MAX)
            else {
                panic!("host_statistics64 failed");
            };
            let words: Vec<u32> = body
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_le_bytes(*word))
                .collect();
            assert_eq!(words[0], VM_INFO64_REV3_COUNT as u32);
            let tags = &words[1 + VM_INFO64_TAGGING..];
            assert!(tags.iter().all(|&word| word == 0));
        }
        assert_eq!(tag_storage_pages(hardware.memory_bytes, false), 0);
        // 16 GiB holds 512 MiB of tags: 32768 guest pages, the total and
        // the free tag storage of a machine presenting memory tagging.
        assert_eq!(tag_storage_pages(hardware.memory_bytes, true), 0x8000);
        let mut words = vec![0u32; VM_INFO64_REV3_COUNT];
        restate_pages(&mut words, HOST_VM_INFO64, 0x8000);
        let tags = &words[VM_INFO64_TAGGING..];
        for (index, pair) in tags.as_chunks::<2>().0.iter().enumerate() {
            let value = u64::from(pair[0]) | u64::from(pair[1]) << 32;
            let expected = if matches!(index, 0 | 3) { 0x8000 } else { 0 };
            assert_eq!(value, expected, "tag statistic {index}");
        }
    }

    #[test]
    fn mach_factors_count_the_profile_processors() {
        // Three load averages of 2.5, 9 and 0 runnable threads.
        let mut load = vec![2_500, 9_000, 0, 1, 1, 1];
        restate_load(&mut load, 8);
        assert_eq!(load, [2_500, 9_000, 0, 5_500, 800, 8_000]);
        let mut short = vec![2_500, 9_000];
        restate_load(&mut short, 8);
        assert_eq!(short, [2_500, 9_000]);
        let hardware = hardware::Hardware::of_soc(0x6001, 0x4_0000_0000).unwrap();
        let cpus = u32::from(hardware.cpus());
        let Ok(Reply::Success(body)) =
            host_statistics(&hardware, false, HOST_LOAD_INFO, HOST_INFO_MAX)
        else {
            panic!("host_statistics(HOST_LOAD_INFO) failed");
        };
        let words: Vec<u32> = body
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        assert_eq!(words[0], 6);
        for index in 0..LOAD_AVERAGES {
            assert_eq!(
                words[1 + LOAD_AVERAGES + index],
                accounting::mach_factor(words[1 + index], cpus)
            );
        }
    }

    #[test]
    fn the_default_set_load_counts_the_profile_processors() {
        unsafe extern "C" {
            fn processor_set_default(host: u32, set: *mut u32) -> i32;
        }
        let mut set = 0u32;
        // SAFETY: this task's host port and a local out argument.
        assert_eq!(
            unsafe { processor_set_default(mach_host_self(), &raw mut set) },
            0
        );
        let hardware = hardware::Hardware::of(Chip::AppleM2, 0x4_0000_0000).unwrap();
        let Reply::Success(body) =
            processor_set_statistics(&hardware, set, PROCESSOR_SET_LOAD_INFO, 4)
        else {
            panic!("processor_set_statistics failed");
        };
        let words: Vec<u32> = body
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        assert_eq!(words[0], 4);
        assert!(words[1] > 0 && words[2] > 0);
        assert_eq!(words[4], accounting::mach_factor(words[3], 8));
        assert!(matches!(
            processor_set_statistics(&hardware, set, PROCESSOR_SET_LOAD_INFO, 3),
            Reply::Failure(KERN_FAILURE)
        ));
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

    /// The words of an out-of-line reply's memory, released.
    fn records(descriptors: &[Descriptor]) -> Vec<u32> {
        let [Descriptor::Memory { address, size, .. }] = descriptors[..] else {
            panic!("no out-of-line records");
        };
        // SAFETY: the records the reply would carry.
        let words = unsafe { std::slice::from_raw_parts(address as *const u32, size as usize / 4) }
            .to_vec();
        unsafe extern "C" {
            fn mach_vm_deallocate(task: u32, address: u64, size: u64) -> i32;
        }
        // SAFETY: the allocation the reply's send would release.
        unsafe { mach_vm_deallocate(crate::hosted::host::task(), address, u64::from(size)) };
        words
    }

    #[test]
    fn an_entry_of_a_partial_range_spans_its_guest_pages() {
        const VM_PROT_READ_WRITE: u32 = 3;
        let task = crate::hosted::host::task();
        let page = memory::allocate(
            0,
            2 * memory::PAGE_BYTES,
            true,
            memory::Protection::READ_WRITE,
        )
        .unwrap();
        let span = |offset: u64, permission: u32| match partial_memory_entry(
            task,
            0,
            0x100,
            offset,
            VM_PROT_READ_WRITE | permission,
        )
        .unwrap()
        {
            Reply::Complex { descriptors, body } => {
                let [Descriptor::Port { name, .. }] = descriptors[..] else {
                    panic!("{descriptors:?}");
                };
                release_send(name);
                u64::from_le_bytes(body[..8].try_into().unwrap())
            }
            _ => panic!("no entry"),
        };
        // The guest page holding the range, less a data address's offset.
        assert_eq!(span(page + 0x10, 0), memory::PAGE_BYTES);
        assert_eq!(span(page + 0x10, MAP_MEM_VM_SHARE), memory::PAGE_BYTES);
        assert_eq!(
            span(page + 0x10, MAP_MEM_USE_DATA_ADDR),
            memory::PAGE_BYTES - 0x10
        );
        // Across a guest page boundary: both pages.
        assert_eq!(
            span(page + memory::PAGE_BYTES - 0x10, 0),
            2 * memory::PAGE_BYTES
        );
        // A data address 4 KiB into its guest page is not implemented.
        assert!(
            partial_memory_entry(task, 0, 0x100, page + 0x1010, 3 | MAP_MEM_USE_DATA_ADDR).is_err()
        );
        // An entry of a parent's range spans its guest pages of the parent,
        // within the parent.
        unsafe extern "C" {
            fn mach_make_memory_entry_64(
                task: u32,
                size: *mut u64,
                offset: u64,
                permission: i32,
                entry: *mut u32,
                parent: u32,
            ) -> i32;
        }
        let (mut size, mut parent) = (2 * memory::PAGE_BYTES, 0);
        // SAFETY: an entry of this test's pages, into locals.
        let code = unsafe { mach_make_memory_entry_64(task, &mut size, page, 3, &mut parent, 0) };
        assert_eq!(code, 0);
        let sub = |offset: u64, size: u64| match partial_memory_entry(task, parent, size, offset, 3)
            .unwrap()
        {
            Reply::Complex { descriptors, body } => {
                let [Descriptor::Port { name, .. }] = descriptors[..] else {
                    panic!("{descriptors:?}");
                };
                release_send(name);
                Ok(u64::from_le_bytes(body[..8].try_into().unwrap()))
            }
            Reply::Failure(code) => Err(code),
            _ => panic!("no entry"),
        };
        assert_eq!(sub(0x1000, 0x1100), Ok(memory::PAGE_BYTES));
        assert_eq!(
            sub(memory::PAGE_BYTES - 0x10, 0x20),
            Ok(2 * memory::PAGE_BYTES)
        );
        assert_eq!(
            sub(2 * memory::PAGE_BYTES - 0x10, 0x20),
            Err(KERN_INVALID_ARGUMENT)
        );
        release_send(parent);
        assert!(matches!(
            partial_memory_entry(task, 0, 0x100, u64::MAX - 0x10, 3).unwrap(),
            Reply::Failure(KERN_INVALID_ARGUMENT)
        ));
        memory::deallocate(page, 2 * memory::PAGE_BYTES).unwrap();
    }

    #[test]
    fn an_internal_entry_holds_its_size_in_whole_guest_pages() {
        unsafe extern "C" {
            fn mach_vm_map(
                task: u32,
                address: *mut u64,
                size: u64,
                mask: u64,
                flags: i32,
                object: u32,
                offset: u64,
                copy: i32,
                current: i32,
                maximum: i32,
                inheritance: u32,
            ) -> i32;
            fn mach_vm_deallocate(task: u32, address: u64, size: u64) -> i32;
        }
        const VM_PROT_READ_WRITE: u32 = 3;
        // SAFETY: this task's host port.
        let host = unsafe { mach_host_self() };
        assert!(matches!(
            internal_entry(host, u64::MAX - 0x1000, VM_PROT_READ_WRITE),
            Reply::Failure(KERN_INVALID_ARGUMENT)
        ));
        let Reply::Descriptors(descriptors) = internal_entry(host, 0x1001, VM_PROT_READ_WRITE)
        else {
            panic!("the entry was not made");
        };
        let [Descriptor::Port { name, .. }] = descriptors[..] else {
            panic!("{descriptors:?}");
        };
        let map = |size: u64| {
            let mut address = 0;
            // SAFETY: a new mapping of the entry anywhere in this task.
            let code = unsafe {
                mach_vm_map(
                    crate::hosted::host::task(),
                    &raw mut address,
                    size,
                    0,
                    1,
                    name,
                    0,
                    0,
                    3,
                    3,
                    1,
                )
            };
            if code == 0 {
                // SAFETY: the mapping just made.
                unsafe { mach_vm_deallocate(crate::hosted::host::task(), address, size) };
            }
            code
        };
        // The whole guest page, and nothing past it.
        assert_eq!(map(memory::PAGE_BYTES), 0);
        assert_ne!(map(memory::PAGE_BYTES + 0x1000), 0);
        release_send(name);
    }

    #[test]
    fn processor_records_describe_the_profile_processors() {
        // SAFETY: this task's host port.
        let host = unsafe { mach_host_self() };
        for chip_id in [0x8103, 0x8112, 0x6001, 0x6021] {
            let hardware = hardware::Hardware::of_soc(chip_id, 0x4_0000_0000).unwrap();
            let cpus = u32::from(hardware.cpus());
            let Reply::Complex { descriptors, body } =
                processor_info(&hardware, host, PROCESSOR_BASIC_INFO).unwrap()
            else {
                panic!("host_processor_info failed");
            };
            assert_eq!(u32::from_le_bytes(body[..4].try_into().unwrap()), cpus);
            assert_eq!(u32::from_le_bytes(body[4..].try_into().unwrap()), cpus * 5);
            let words = records(&descriptors);
            assert_eq!(words.len() as u32, cpus * 5);
            assert_eq!(&words[..5], &[hardware::CPU_TYPE_ARM64, 2, 1, 0, 1]);
            let last = (cpus - 1) as usize * 5;
            assert_eq!(
                &words[last..],
                &[hardware::CPU_TYPE_ARM64, 2, 1, cpus - 1, 0]
            );
            // The load ticks: one record of four states per processor.
            let Reply::Complex { descriptors, body } =
                processor_info(&hardware, host, PROCESSOR_CPU_LOAD_INFO).unwrap()
            else {
                panic!("host_processor_info(PROCESSOR_CPU_LOAD_INFO) failed");
            };
            assert_eq!(u32::from_le_bytes(body[..4].try_into().unwrap()), cpus);
            let ticks = records(&descriptors);
            assert_eq!(ticks.len() as u32, cpus * 4);
            assert!(ticks.iter().any(|&tick| tick != 0));
        }
        let hardware = hardware::Hardware::of(Chip::AppleM2, 0x4_0000_0000).unwrap();
        assert!(matches!(
            processor_info(&hardware, host, 99).unwrap(),
            Reply::Failure(KERN_FAILURE)
        ));
        assert!(processor_info(&hardware, host, PROCESSOR_CPU_STAT).is_err());
    }

    #[test]
    fn shared_host_services_use_one_physical_budget_and_keep_ticks_unqualified() {
        let observed = hardware::DarwinAvailability {
            maximum_slots: 16,
            available_slots: 12,
            physical_active: Some(6),
            physical_maximum: Some(8),
            logical_active: Some(12),
            logical_maximum: Some(16),
        };
        let hardware = hardware::Hardware::of_soc(0x6000, 16 << 30)
            .unwrap()
            .with_availability(observed)
            .unwrap();
        let basic = words(host_info(&hardware, HOST_BASIC_INFO, HOST_INFO_MAX));
        assert_eq!(&basic[1..3], &[8, 6]);
        assert_eq!(&basic[6..11], &[CPU_THREADTYPE_NONE, 6, 8, 6, 8]);
        let Reply::Complex { body, .. } =
            processor_set_info(&hardware, 0, PROCESSOR_SET_BASIC_INFO, 2)
        else {
            panic!("default set information failed");
        };
        assert_eq!(
            body,
            [2u32, 6, POLICY_TIMESHARE]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
        );
        // SAFETY: one owned host send right, released below.
        let host = unsafe { mach_host_self() };
        let Reply::Complex { descriptors, body } =
            processor_info(&hardware, host, PROCESSOR_BASIC_INFO).unwrap()
        else {
            panic!("uniform processor records failed");
        };
        assert_eq!(
            body,
            [8u32, 40]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
        );
        let records = records(&descriptors);
        assert_eq!(records.len(), 40);
        for (slot, record) in records.as_chunks::<5>().0.iter().enumerate() {
            assert_eq!(
                *record,
                [
                    hardware::CPU_TYPE_ARM64,
                    hardware::CPU_SUBTYPE_ARM64E,
                    u32::from(slot < 6),
                    slot as u32,
                    u32::from(slot == 0)
                ]
            );
        }
        assert!(processor_info(&hardware, host, PROCESSOR_CPU_LOAD_INFO).is_err());
        assert!(host_statistics(&hardware, false, HOST_CPU_LOAD_INFO, 4).is_err());
        let load = words(host_statistics(&hardware, false, HOST_LOAD_INFO, HOST_INFO_MAX).unwrap());
        for index in 0..LOAD_AVERAGES {
            assert_eq!(
                load[1 + LOAD_AVERAGES + index],
                accounting::mach_factor(load[1 + index], 6)
            );
        }
        release_send(host);
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
