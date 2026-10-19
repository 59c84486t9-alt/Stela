//! The kernel-object MIG routines the hosted kernel answers itself: those
//! whose answer describes the arm64 machine rather than the x86 host. Each
//! returns its reply body after the header (`NDR_record`, `RetCode`, then
//! the out arguments), as the routine's MIG server stub lays it out, or a
//! failing `RetCode` for the short `mig_reply_error_t`.
use super::super::Kernel;
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
}

/// One descriptor of a complex reply. Further forms join as routines
/// need them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Descriptor {
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

/// `MACH_MSG_TYPE_COPY_SEND`.
pub(super) const COPY_SEND: u8 = 19;

impl Descriptor {
    /// The descriptor as an LP64 sender lays it out; a port array's
    /// address is its names', valid while the descriptor lives.
    pub(super) fn bytes(&self) -> Vec<u8> {
        const OOL: u8 = 1;
        const OOL_PORTS: u8 = 2;
        const VIRTUAL_COPY: u8 = 1;
        let mut out = Vec::with_capacity(16);
        match self {
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
}

/// The routines [`serve`] answers or forwards, by object, with the named
/// limit of a routine served only in part (other arguments stop the run
/// naming them).
pub(crate) const SERVED: &[(Object, &str, Option<&str>)] = &[
    (Object::Host, "host_info", None),
    (
        Object::Task,
        "_kernelrpc_mach_vm_map_external",
        Some("a memory object is mapped in host pages over a reserved guest range"),
    ),
    (
        Object::Task,
        "task_get_special_port_from_user",
        Some("the kernel, host, bootstrap and debug-control ports"),
    ),
    (
        Object::Task,
        "task_set_special_port_from_user",
        Some("the bootstrap and debug-control ports"),
    ),
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
        Some("the x86 host's load and VM statistics, its page counts in guest pages"),
    ),
    (Object::Host, "host_get_special_port", Some("the host port")),
    (
        Object::Host,
        "processor_set_default",
        Some("the x86 host's processor sets"),
    ),
    (
        Object::Host,
        "host_processor_sets",
        Some("the x86 host's processor sets"),
    ),
    (
        Object::Host,
        "host_processor_set_priv",
        Some("the x86 host's processor sets"),
    ),
    (
        Object::Host,
        "host_get_io_main",
        Some("the IOKit main port is the host's: its registry describes the x86 host"),
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
];

/// Answer `routine` sent to `object`, or `None` when the hosted kernel
/// does not serve it. `complex` is the request's `MACH_MSGH_BITS_COMPLEX`.
pub(super) fn serve(
    kernel: &mut Kernel,
    object: Object,
    routine: &str,
    complex: bool,
    request: &Request,
) -> Result<Option<Reply>> {
    Ok(Some(match (object, routine, complex) {
        (Object::Host, "host_info", false) => {
            // `flavor`, then `host_info_outCnt` after the NDR record.
            let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            host_info(&kernel.process.hardware, flavor, count.min(HOST_INFO_MAX))
        }
        (Object::Task, "_kernelrpc_mach_vm_map_external", true) => vm_map(request)?,
        // `which_port`. The bootstrap port is the host's launchd, as for
        // any process of this user; the kernel and host ports are this
        // task's own kernel objects, whose names the reply repeats; the
        // debug-control port is the one this task set, if any.
        (Object::Task, "task_get_special_port_from_user", false) => match request.word(8) {
            Some(
                TASK_KERNEL_PORT | TASK_HOST_PORT | TASK_BOOTSTRAP_PORT | TASK_DEBUG_CONTROL_PORT,
            ) => Reply::Forward,
            Some(which) => bail!("task_get_special_port({which}) is not implemented"),
            None => Reply::Failure(MIG_BAD_ARGUMENTS),
        },
        // One port descriptor, then `which_port`: replacing the bootstrap
        // or debug-control port changes only this task's own state.
        (Object::Task, "task_set_special_port_from_user", true) => match request.word(24) {
            Some(TASK_BOOTSTRAP_PORT | TASK_DEBUG_CONTROL_PORT) => Reply::Forward,
            Some(which) => bail!("task_set_special_port({which}) is not implemented"),
            None => Reply::Failure(MIG_BAD_ARGUMENTS),
        },
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
        // The processor sets are the host's: their names, and the host
        // kernel's refusal of the privileged routines to an unprivileged
        // host port.
        (
            Object::Host,
            "processor_set_default" | "host_processor_sets" | "host_processor_set_priv",
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
                routine == "host_statistics64_from_user",
                flavor,
                count.min(HOST_INFO_MAX),
            )
        }
        (Object::Host, "host_get_special_port", false) => {
            let (Some(node), Some(which)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            match which {
                HOST_PORT => Reply::Forward,
                _ => bail!("host_get_special_port(node {node:#x}, {which}) is not implemented"),
            }
        }
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
        (Object::Task, _, _) => return super::vm::serve(kernel, routine, complex, request),
        _ => return Ok(None),
    }))
}

/// `osfmk/mach/host_special_ports.h`.
const HOST_PORT: u32 = 1;
/// `osfmk/mach/task_special_ports.h`.
const TASK_KERNEL_PORT: u32 = 1;
const TASK_HOST_PORT: u32 = 2;
const TASK_BOOTSTRAP_PORT: u32 = 4;
const TASK_DEBUG_CONTROL_PORT: u32 = 10;
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
/// Rev3's tag storage and tagged-page statistics, from this word on: the
/// M2 has no memory tagging, so they are zero.
const VM_INFO64_TAGGING: usize = 40;
/// Host pages per guest page.
const HOST_PAGES_PER_PAGE: u32 = (memory::PAGE_BYTES / (memory::HOST_PAGE_MASK + 1)) as u32;

/// `host_statistics` and `host_statistics64` on the host port: the x86
/// host's own answer, the same layout in both ABIs, with its page counts
/// restated in the guest's 16 KiB pages, as an arm64 kernel counts them.
fn host_statistics(sixty_four: bool, flavor: u32, count: u32) -> Reply {
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
        return Reply::Failure(status as u32);
    }
    let mut words: Vec<u32> = words[..filled.min(HOST_INFO_MAX) as usize]
        .iter()
        .map(|&word| word as u32)
        .collect();
    restate_pages(&mut words, flavor);
    let mut body = (words.len() as u32).to_le_bytes().to_vec();
    for word in words {
        body.extend(word.to_le_bytes());
    }
    Reply::Success(body)
}

/// Restate the page counts of a `flavor` statistics reply in guest pages.
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
        let Reply::Success(body) = host_statistics(true, HOST_VM_INFO64, HOST_INFO_MAX) else {
            panic!("host_statistics64 failed");
        };
        assert!(u32::from_le_bytes(body[..4].try_into().unwrap()) >= 38);
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
