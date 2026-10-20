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
//! are serviced here by routine. An unassigned trap number takes
//! EXC_SYSCALL (`mach_syscall`), which becomes SIGSYS at the trap; a trap
//! or request the hosted kernel does not service fails with its own error,
//! or `kern_invalid`'s KERN_INVALID_ARGUMENT, and is reported
//! ([`unsupported`]).
use super::{Kernel, Pe, Trap};
use crate::hosted::darwin::{
    ENOTSUP, KERN_FAILURE, KERN_INVALID_ADDRESS, KERN_INVALID_ARGUMENT, KERN_NOT_SUPPORTED,
    KERN_SUCCESS, MACH_SEND_INVALID_DEST, VM_PROT_DEFAULT,
};
use crate::hosted::threads::lock;
use crate::hosted::unsupported::{self, Failure, Kind};
use crate::hosted::{
    forward, host,
    memory::{PAGE_MASK, Protection},
};
use crate::mach::catalog::{self, Reserved};
use crate::machine::system::Register;
use anyhow::Result;

mod accounting;
pub(super) mod exception;
mod message;
pub(crate) use message::received_event;
pub(super) mod raise;
pub(super) mod reclaim;
mod server;
pub(super) mod suspension;
pub(super) mod task;
pub(super) mod thread;
mod vm;

/// The fast traps `handle_svc` answers before the table.
const MACH_ABSOLUTE_TIME_FAST: u32 = 3;
const MACH_CONTINUOUS_TIME_FAST: u32 = 4;
/// The entitlements exec records as the task's x86-64 compatibility
/// permission in 26A434.
const CROSS_ARCHITECTURE_ENTITLEMENTS: [&str; 2] = [
    "com.apple.developer.cross-architecture-support",
    "com.apple.developer.cross-architecture-support-unmanaged",
];
const VM_FLAGS_ANYWHERE: u64 = 1;
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
    "macx_triggers",
    "iokit_user_client_trap",
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

/// The 26A434 trap at reserved index `index`, if any.
pub(crate) fn addition(index: u32) -> Option<&'static str> {
    ADDITIONS
        .iter()
        .find(|&&(entry, _)| entry == index)
        .map(|&(_, name)| name)
}

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

fn forward_trap(kernel: &mut Kernel, index: u32, arguments: &[u64]) -> Result<u64> {
    kernel.page_in_arguments(arguments)?;
    // A terminated thread never sees the result.
    Ok(kernel
        .forwarding(|| forward::mach(index, arguments).rax)
        .unwrap_or(u64::from(super::control::KERN_ABORTED)))
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
            if let Some(name) = catalog::entry(index)
                .filter(|entry| entry.reserved == Reserved::Yes)
                .and(addition(index))
            {
                kernel.count(name);
                let compat = pe.cpu.state.x[0] as u32;
                let result = thread_set_x86_64_compat(kernel, compat);
                if kernel.trace {
                    eprintln!("stela: mach {name}({compat:#x}) = {result:#x}");
                }
                Trap { cpu: &mut pe.cpu }.set_x(0, result);
                return Ok(());
            }
            let Some(entry) = catalog::entry(index).filter(|entry| entry.reserved == Reserved::No)
            else {
                return syscall_exception(kernel, pe, index);
            };
            kernel.count(entry.name);
            let mut arguments = [0u64; forward::MAX_ARGUMENTS];
            arguments[..entry.argument_count]
                .copy_from_slice(&pe.cpu.state.x[..entry.argument_count]);
            let arguments = &arguments[..entry.argument_count];
            let pc = pe.cpu.read(Register::ELR_EL1).wrapping_sub(4);
            let result = match dispatch(kernel, entry.name, index, arguments, pc) {
                Ok(result) => result,
                Err(error) => match unsupported::recover(error, Kind::MachTrap, pc, None)? {
                    Failure::Kern(code) => u64::from(code),
                    _ => u64::from(KERN_INVALID_ARGUMENT),
                },
            };
            if kernel.trace {
                eprintln!("stela: mach {}({arguments:x?}) = {result:#x}", entry.name);
            }
            result
        }
    };
    Trap { cpu: &mut pe.cpu }.set_x(0, result);
    Ok(())
}

/// `mach_syscall`'s unassigned number: EXC_SYSCALL with the number, which
/// becomes SIGSYS at the trap (`ux_exception`) unless a handler takes it;
/// X0 is left as it was.
fn syscall_exception(kernel: &mut Kernel, pe: &mut Pe, index: u32) -> Result<()> {
    if kernel.deliver_exception(pe, crate::hosted::darwin::EXC_SYSCALL, &[u64::from(index)])? {
        return Ok(());
    }
    let pc = pe.cpu.read(Register::ELR_EL1).wrapping_sub(4);
    kernel.exception_signal(super::bsd::signal::SIGSYS, 0, false, || {
        format!("unassigned Mach trap -{index} at pc {pc:#x}")
    });
    Ok(())
}

fn dispatch(
    kernel: &mut Kernel,
    name: &'static str,
    index: u32,
    arguments: &[u64],
    pc: u64,
) -> Result<u64> {
    if FORWARDED.contains(&name) {
        return forward_trap(kernel, index, arguments);
    }
    Ok(match name {
        "_kernelrpc_mach_vm_allocate_trap" => {
            let [target, pointer, size, flags] = arguments[..4] else {
                unreachable!("the catalog row has four arguments")
            };
            let Some(address) = crate::hosted::memory::read_u64(pointer) else {
                return Ok(u64::from(KERN_INVALID_ADDRESS));
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
                    return Ok(u64::from(KERN_INVALID_ARGUMENT));
                };
                (start, end - start, 0)
            };
            let Some(size) = crate::hosted::memory::round_page(size) else {
                return Ok(u64::from(KERN_INVALID_ARGUMENT));
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
                    u64::from(VM_PROT_DEFAULT),
                ],
            )?;
            if status == u64::from(KERN_SUCCESS)
                && !crate::hosted::memory::write_u64(pointer, placed)
            {
                return Ok(u64::from(KERN_INVALID_ADDRESS));
            }
            status
        }
        "_kernelrpc_mach_vm_map_trap" => {
            let mut rounded = arguments.to_vec();
            let Some(size) = crate::hosted::memory::round_page(arguments[2]) else {
                return Ok(u64::from(KERN_INVALID_ARGUMENT));
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
                return Ok(u64::from(KERN_INVALID_ARGUMENT));
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
            let process = kernel.process.clone();
            let mut jit = lock(&process.jit);
            let mut status = u64::from(KERN_SUCCESS);
            for (run, size) in runs {
                let mut rounded = arguments.to_vec();
                rounded[1] = run;
                rounded[2] = size;
                status = forward_trap(kernel, index, &rounded)?;
                if status != u64::from(KERN_SUCCESS) {
                    break;
                }
            }
            // The JIT pages leave the table, or take the protection the
            // running thread's view gives them.
            if status == u64::from(KERN_SUCCESS) {
                if deallocate {
                    jit.forget(start, end - start);
                } else {
                    let change = |current: Protection| {
                        if maximum {
                            Protection(current.0 & new)
                        } else {
                            Protection(new)
                        }
                    };
                    for (run, size, host) in jit.protect(start, end - start, change) {
                        crate::hosted::memory::protect(run, size, host)?;
                    }
                }
            }
            status
        }
        "mach_vm_reclaim_update_kernel_accounting_trap" => {
            // `(target_task, bytes_reclaimed_out, next_deadline_out)`.
            let (bytes_out, deadline_out) = (arguments[1], arguments[2]);
            if arguments[0] != u64::from(kernel.process.task_port()) {
                return Ok(u64::from(MACH_SEND_INVALID_DEST));
            }
            if bytes_out == 0 || deadline_out == 0 {
                return Ok(u64::from(KERN_INVALID_ARGUMENT));
            }
            match reclaim::update_accounting(&mut lock(&kernel.process.reclaim)) {
                Ok((bytes, deadline)) => {
                    // The kernel ignores copy-out faults here.
                    crate::hosted::memory::write_u64(bytes_out, bytes);
                    crate::hosted::memory::write_u64(deadline_out, deadline);
                    u64::from(KERN_SUCCESS)
                }
                Err(status) => u64::from(status),
            }
        }
        // The commpage's preemption-free-zone routines enter the kernel
        // here to take a preemption deferred in the zone; leaving the
        // kernel takes it (`syscall_subr.c`).
        "pfz_exit" => u64::from(KERN_SUCCESS),
        "mach_timebase_info_trap" => {
            let mut info = TIMEBASE_NUMERATOR.to_le_bytes().to_vec();
            info.extend(TIMEBASE_DENOMINATOR.to_le_bytes());
            if crate::hosted::memory::write(arguments[0], &info) {
                u64::from(KERN_SUCCESS)
            } else {
                u64::from(KERN_INVALID_ARGUMENT)
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
                && status == u64::from(KERN_SUCCESS)
                && !crate::hosted::memory::write_u64(pointer, host::counter_at(armed))
            {
                return Ok(u64::from(KERN_INVALID_ADDRESS));
            }
            status
        }
        // 26A434 keeps these stubs: no swap file is added or removed and
        // no backing store is suspended (`bsd/vm/dp_backing_file.c`).
        "macx_swapon"
        | "macx_swapoff"
        | "macx_backing_store_suspend"
        | "macx_backing_store_recovery" => ENOTSUP,
        // The M2's 26A434 kernel is built without exclaves.
        "_exclaves_ctl_trap" => u64::from(KERN_NOT_SUPPORTED),
        "mach_msg_trap" | "mach_msg_overwrite_trap" | "mach_msg2_trap" => {
            let status = message::send(kernel, name, index, arguments, pc)?;
            if status == u64::from(KERN_SUCCESS) {
                message::received(name, arguments)?;
            }
            status
        }
        other => {
            let reason = REFUSED
                .iter()
                .find(|(refused, _)| *refused == other)
                .map_or("no family services it", |&(_, reason)| reason);
            unsupported::refuse!(
                Failure::Kern(KERN_INVALID_ARGUMENT),
                "Mach trap {other} (-{index}) is not implemented by the hosted kernel: {reason} \
                 (arguments {arguments:x?})"
            )
        }
    })
}

/// `thread_set_x86_64_compat(compat)` (26A434): a task exec found holding
/// a cross-architecture entitlement may turn the calling thread's x86-64
/// compatibility mode off (0) or on (1), which runs its user code with
/// ACTLR_EL1's TSO ordering and saves the Apple FP-mode registers across
/// exceptions; any other value is KERN_INVALID_ARGUMENT, and every other
/// task gets KERN_FAILURE. Guest code here already runs under one total
/// order of memory effects, which TSO ordering permits, in either mode,
/// and the Apple FP-mode registers are each thread's own PE state, so
/// either mode leaves nothing more to change.
fn thread_set_x86_64_compat(kernel: &Kernel, compat: u32) -> u64 {
    let entitled = lock(&kernel.process.executable)
        .signature
        .as_ref()
        .is_some_and(|signature| {
            CROSS_ARCHITECTURE_ENTITLEMENTS
                .iter()
                .any(|name| signature.entitled(name))
        });
    if !entitled {
        return u64::from(KERN_FAILURE);
    }
    match compat {
        0 | 1 => u64::from(KERN_SUCCESS),
        _ => u64::from(KERN_INVALID_ARGUMENT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additions_lie_at_reserved_indices() {
        for &(index, name) in ADDITIONS {
            let entry = catalog::entry(index).expect("the index is in the trap table");
            assert_eq!(entry.reserved, Reserved::Yes, "{name}");
            assert_eq!(addition(index), Some(name));
        }
        assert!(REFUSED.is_empty());
    }
}
