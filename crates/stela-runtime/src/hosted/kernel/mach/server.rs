//! The kernel-object MIG routines the hosted kernel answers itself: those
//! whose answer describes the arm64 machine rather than the x86 host. Each
//! returns its reply body after the header (`NDR_record`, `RetCode`, then
//! the out arguments), as the routine's MIG server stub lays it out, or a
//! failing `RetCode` for the short `mig_reply_error_t`.
use super::super::Kernel;
use super::reclaim;
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
    fn word(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.body.get(at..at + 4)?.try_into().ok()?,
        ))
    }

    /// MIG packs 64-bit arguments at 4-byte alignment.
    fn double(&self, at: usize) -> Option<u64> {
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
}

const KERN_INVALID_ARGUMENT: u32 = 4;
const KERN_FAILURE: u32 = 5;
const KERN_NOT_SUPPORTED: u32 = 46;
/// `MIG_BAD_ARGUMENTS`: the request is malformed.
const MIG_BAD_ARGUMENTS: u32 = (-304i32) as u32;

/// `NDR_record` on both LP64 ABIs: little-endian, ASCII, IEEE floats.
pub(super) const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// Which kernel object a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Object {
    Task,
    Thread,
    Host,
}

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
            host_info(&kernel.hardware, flavor, count.min(HOST_INFO_MAX))
        }
        (Object::Task, "_kernelrpc_mach_vm_map_external", true) => vm_map(request)?,
        // `which_port`. The bootstrap port is the host's launchd, as for
        // any process of this user; the kernel and host ports are this
        // task's own kernel objects, whose names the reply repeats.
        (Object::Task, "task_get_special_port_from_user", false) => match request.word(8) {
            Some(TASK_KERNEL_PORT | TASK_HOST_PORT | TASK_BOOTSTRAP_PORT) => Reply::Forward,
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
        // The process runs one thread, which is making this call outside
        // any range: no thread has a PC to reset.
        (Object::Task, "task_restartable_ranges_synchronize", false) => Reply::Success(Vec::new()),
        // `len`, `max_len`; out `address`, `next_deadline`.
        (Object::Task, "mach_vm_deferred_reclamation_buffer_allocate", false) => {
            let (Some(len), Some(max_len)) = (request.word(8), request.word(12)) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            pair(reclaim::allocate(&mut kernel.reclaim, len, max_len))
        }
        // `num_entries_to_reclaim`; out `bytes_reclaimed`, `next_deadline`.
        (Object::Task, "mach_vm_deferred_reclamation_buffer_flush", false) => {
            let Some(entries) = request.word(8) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            pair(reclaim::flush(&kernel.reclaim, entries))
        }
        // `new_len`; out `bytes_reclaimed`, `next_deadline`.
        (Object::Task, "mach_vm_deferred_reclamation_buffer_resize", false) => {
            let Some(len) = request.word(8) else {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            };
            pair(reclaim::resize(&mut kernel.reclaim, len))
        }
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
/// once, as a release kernel allows. The hosted kernel interrupts a guest
/// thread only at its own exceptions, which a range never contains, and
/// delivers no signals, so no PC is ever reset into a recovery path yet.
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
    if kernel.restartable_ranges.is_some() {
        return Reply::Failure(KERN_NOT_SUPPORTED);
    }
    kernel.restartable_ranges = Some(ranges);
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
