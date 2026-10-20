//! Mach traps (`osfmk/kern/syscall_sw.c`, `osfmk/arm64/sleh.c`
//! `mach_syscall`), bound by name to the pinned trap catalog. A trap
//! returns its `kern_return_t` or port name in X0 alone.
//!
//! Port, semaphore, voucher and message traps act on this task's IPC space,
//! which is the host task's, and are forwarded. Virtual-memory traps on this
//! task are performed in the guest's 16 KiB pages. Absolute-time arguments
//! and results are converted between the guest's 24 MHz count and the
//! host's nanoseconds. A message to this task's, thread's or host's own
//! kernel object would be answered by the x86 host's MIG servers with x86
//! semantics (page size, thread states, CPU information), so such messages
//! are serviced here by routine, and a routine not serviced stops the
//! process naming it.
use super::{Kernel, Pe, Trap};
use crate::hosted::threads::lock;
use crate::hosted::{
    forward, host,
    memory::{PAGE_MASK, Protection},
};
use crate::mach::catalog::{self, Reserved};
use anyhow::{Result, bail};

mod message;
pub(super) mod reclaim;
mod server;
mod vm;

/// The fast traps `handle_svc` answers before the table.
const MACH_ABSOLUTE_TIME_FAST: u32 = 3;
const MACH_CONTINUOUS_TIME_FAST: u32 = 4;
const KERN_SUCCESS: u64 = 0;
const KERN_INVALID_ARGUMENT: u64 = 4;
/// `MACH_SEND_INVALID_DEST`-class failure for a bad user address.
const KERN_INVALID_ADDRESS: u64 = 1;
const MACH_SEND_INVALID_DEST: u64 = 0x1000_0003;
const VM_FLAGS_ANYWHERE: u64 = 1;
/// `VM_PROT_DEFAULT`.
const VM_PROT_DEFAULT: u64 = 3;
/// The ARM timebase over the 24 MHz counter: 125/3 ns per tick.
const TIMEBASE_NUMERATOR: u32 = 125;
const TIMEBASE_DENOMINATOR: u32 = 3;

/// Traps forwarded unchanged.
const FORWARDED: &[&str] = &[
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
];

/// Traps the hosted kernel models: virtual memory in guest pages, the
/// guest's timebase and its deadlines, and messages to kernel objects.
const MODELED: &[&str] = &[
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
];

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
pub(crate) const REFUSED: &[(&str, &str)] = &[
    (
        "iokit_user_client_trap",
        "IOKit user clients are not modeled",
    ),
    ("_exclaves_ctl_trap", "exclaves are not modeled"),
    ("macx_swapon", "a system administration call"),
    ("macx_swapoff", "a system administration call"),
    ("macx_triggers", "a system administration call"),
    ("macx_backing_store_suspend", "a system administration call"),
    (
        "macx_backing_store_recovery",
        "a system administration call",
    ),
];

/// The kernel object a subsystem's requests address in this task: the
/// task port carries task, VM, restartable-range and port-space requests,
/// a thread port thread requests, the host port host requests.
pub(crate) fn object_of(subsystem: &str) -> Option<server::Object> {
    Some(match subsystem {
        "task" | "mach_vm" | "task_restartable" | "mach_port" => server::Object::Task,
        "thread_act" => server::Object::Thread,
        "mach_host" | "host_priv" => server::Object::Host,
        _ => return None,
    })
}

pub(crate) fn object_name(object: server::Object) -> &'static str {
    match object {
        server::Object::Task => "task",
        server::Object::Thread => "thread",
        server::Object::Host => "host",
    }
}

/// Subsystems whose objects are not this process's and whose requests are
/// forwarded, with what of the arm64 kernel's answer the host's differs in.
const OTHER_OBJECT_LIMITS: &[(&str, &str)] = &[
    ("processor", "describes the x86 host's processors"),
    ("processor_set", "describes the x86 host's processors"),
];

/// How a MIG request is serviced: to this process's kernel objects as the
/// message dispatcher routes it, to any other object forwarded.
pub(crate) fn mig_service(
    subsystem: &str,
    routine: &str,
) -> (super::services::Service, Option<&'static str>) {
    use super::services::Service;
    let Some(object) = object_of(subsystem) else {
        let limit = OTHER_OBJECT_LIMITS
            .iter()
            .find(|(name, _)| *name == subsystem)
            .map(|&(_, limit)| limit);
        return (Service::Forwarded { overlay: None }, limit);
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
                reason: "this process's kernel object does not serve it",
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

fn forward_trap(kernel: &mut Kernel, index: u32, arguments: &[u64]) -> Result<u64> {
    kernel.page_in_arguments(arguments)?;
    Ok(forward::mach(index, arguments).rax)
}

pub(super) fn index_of(name: &str) -> u32 {
    (0..)
        .map_while(catalog::entry)
        .find(|entry| entry.name == name)
        .map(|entry| entry.index)
        .expect("the trap is in the pinned catalog")
}

pub(super) fn trap(kernel: &mut Kernel, pe: &mut Pe, index: u32) -> Result<()> {
    let result = match index {
        MACH_ABSOLUTE_TIME_FAST => {
            kernel.count("mach_absolute_time");
            host::counter_at(host::host_nanoseconds())
        }
        MACH_CONTINUOUS_TIME_FAST => {
            kernel.count("mach_continuous_time");
            host::counter_at(host::continuous_nanoseconds())
        }
        _ => {
            let Some(entry) = catalog::entry(index).filter(|entry| entry.reserved == Reserved::No)
            else {
                bail!(
                    "Mach trap -{index} is unassigned: the guest would take EXC_SYSCALL, whose \
                     delivery is not implemented"
                );
            };
            kernel.count(entry.name);
            let mut arguments = [0u64; forward::MAX_ARGUMENTS];
            arguments[..entry.argument_count]
                .copy_from_slice(&pe.cpu.state.x[..entry.argument_count]);
            let arguments = &arguments[..entry.argument_count];
            let result = dispatch(kernel, entry.name, index, arguments)?;
            if kernel.trace {
                eprintln!("stela: mach {}({arguments:x?}) = {result:#x}", entry.name);
            }
            result
        }
    };
    Trap { cpu: &mut pe.cpu }.set_x(0, result);
    Ok(())
}

fn dispatch(kernel: &mut Kernel, name: &'static str, index: u32, arguments: &[u64]) -> Result<u64> {
    if FORWARDED.contains(&name) {
        return forward_trap(kernel, index, arguments);
    }
    Ok(match name {
        "_kernelrpc_mach_vm_allocate_trap" => {
            let [target, pointer, size, flags] = arguments[..4] else {
                unreachable!("the catalog row has four arguments")
            };
            let Some(address) = crate::hosted::memory::read_u64(pointer) else {
                return Ok(KERN_INVALID_ADDRESS);
            };
            // `mach_vm_allocate` is `mach_vm_map` of anonymous memory with
            // the default protection: placed in guest pages.
            let (address, size, mask) = if flags & VM_FLAGS_ANYWHERE != 0 {
                (address, size, PAGE_MASK)
            } else {
                let start = address & !PAGE_MASK;
                let Some(end) = address
                    .checked_add(size)
                    .and_then(crate::hosted::memory::round_page)
                else {
                    return Ok(KERN_INVALID_ARGUMENT);
                };
                (start, end - start, 0)
            };
            let Some(size) = crate::hosted::memory::round_page(size) else {
                return Ok(KERN_INVALID_ARGUMENT);
            };
            let mut placed = address;
            let status = forward_trap(
                kernel,
                index_of("_kernelrpc_mach_vm_map_trap"),
                &[
                    target,
                    &raw mut placed as u64,
                    size,
                    mask,
                    flags,
                    VM_PROT_DEFAULT,
                ],
            )?;
            if status == KERN_SUCCESS && !crate::hosted::memory::write_u64(pointer, placed) {
                return Ok(KERN_INVALID_ADDRESS);
            }
            status
        }
        "_kernelrpc_mach_vm_map_trap" => {
            let mut rounded = arguments.to_vec();
            let Some(size) = crate::hosted::memory::round_page(arguments[2]) else {
                return Ok(KERN_INVALID_ARGUMENT);
            };
            rounded[2] = size;
            rounded[3] |= PAGE_MASK;
            forward_trap(kernel, index, &rounded)?
        }
        "_kernelrpc_mach_vm_deallocate_trap" | "_kernelrpc_mach_vm_protect_trap" => {
            let (address, size) = (arguments[1], arguments[2]);
            let start = address & !PAGE_MASK;
            let Some(end) = address
                .checked_add(size)
                .and_then(crate::hosted::memory::round_page)
            else {
                return Ok(KERN_INVALID_ARGUMENT);
            };
            let deallocate = name == "_kernelrpc_mach_vm_deallocate_trap";
            // `mach_vm_protect_trap(target, address, size, set_maximum,
            // new_protection)`.
            let (maximum, new) = match arguments {
                [_, _, _, maximum, new, ..] => (*maximum != 0, *new as i32 & Protection::ALL.0),
                _ => (false, 0),
            };
            let runs = kernel.unslid_change(start, end - start, |current| {
                if deallocate {
                    None
                } else if maximum {
                    Some(Protection(current.0 & new))
                } else {
                    Some(Protection(new))
                }
            });
            let runs = if deallocate {
                vec![(start, end - start)]
            } else {
                runs
            };
            let mut status = KERN_SUCCESS;
            for (run, size) in runs {
                let mut rounded = arguments.to_vec();
                rounded[1] = run;
                rounded[2] = size;
                status = forward_trap(kernel, index, &rounded)?;
                if status != KERN_SUCCESS {
                    break;
                }
            }
            status
        }
        "mach_vm_reclaim_update_kernel_accounting_trap" => {
            // `(target_task, bytes_reclaimed_out, next_deadline_out)`.
            let (bytes_out, deadline_out) = (arguments[1], arguments[2]);
            if arguments[0] != u64::from(kernel.process.task_port()) {
                return Ok(MACH_SEND_INVALID_DEST);
            }
            if bytes_out == 0 || deadline_out == 0 {
                return Ok(KERN_INVALID_ARGUMENT);
            }
            match reclaim::update_accounting(&mut lock(&kernel.process.reclaim)) {
                Ok((bytes, deadline)) => {
                    // The kernel ignores copy-out faults here.
                    crate::hosted::memory::write_u64(bytes_out, bytes);
                    crate::hosted::memory::write_u64(deadline_out, deadline);
                    KERN_SUCCESS
                }
                Err(status) => u64::from(status),
            }
        }
        "mach_timebase_info_trap" => {
            let mut info = TIMEBASE_NUMERATOR.to_le_bytes().to_vec();
            info.extend(TIMEBASE_DENOMINATOR.to_le_bytes());
            if crate::hosted::memory::write(arguments[0], &info) {
                KERN_SUCCESS
            } else {
                KERN_INVALID_ARGUMENT
            }
        }
        "mach_wait_until_trap" => {
            forward_trap(kernel, index, &[host::nanoseconds_at(arguments[0])])?
        }
        "mk_timer_arm_trap" => forward_trap(
            kernel,
            index,
            &[arguments[0], host::nanoseconds_at(arguments[1])],
        )?,
        "mk_timer_arm_leeway_trap" => forward_trap(
            kernel,
            index,
            &[
                arguments[0],
                arguments[1],
                host::nanoseconds_at(arguments[2]),
                host::nanoseconds_at(arguments[3]),
            ],
        )?,
        "mk_timer_cancel_trap" => {
            let pointer = arguments[1];
            let mut armed = 0u64;
            let target = if pointer == 0 {
                0
            } else {
                &raw mut armed as u64
            };
            let status = forward_trap(kernel, index, &[arguments[0], target])?;
            if pointer != 0
                && status == KERN_SUCCESS
                && !crate::hosted::memory::write_u64(pointer, host::counter_at(armed))
            {
                return Ok(KERN_INVALID_ADDRESS);
            }
            status
        }
        "mach_msg_trap" | "mach_msg_overwrite_trap" | "mach_msg2_trap" => {
            let status = message::send(kernel, name, index, arguments)?;
            if status == KERN_SUCCESS {
                message::received(name, arguments)?;
            }
            status
        }
        other => {
            let reason = REFUSED
                .iter()
                .find(|(refused, _)| *refused == other)
                .map_or("no family services it", |&(_, reason)| reason);
            bail!(
                "Mach trap {other} (-{index}) is not implemented by the hosted kernel: {reason} \
                 (arguments {arguments:x?})"
            )
        }
    })
}
