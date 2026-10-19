//! Mach message sends. A message to a port in another task's or the host
//! kernel's IPC space is forwarded unchanged: its bytes have one layout on
//! both LP64 ABIs. A message to this task's, its thread's or the host's own
//! kernel object is a MIG request the host kernel would serve with x86
//! semantics; those requests are identified by subsystem and routine and
//! serviced here or refused by name.
use super::{Kernel, forward_trap};
use crate::hosted::memory;
use anyhow::{Result, bail};

/// `MACH_SEND_MSG` (and `MACH64_SEND_MSG`).
const SEND: u64 = 0x1;
/// `mach_msg_header_t` field offsets.
const HEADER_REMOTE_PORT: u64 = 8;
const HEADER_ID: u64 = 20;
const LOW_HALF: u64 = 0xffff_ffff;

/// Kernel MIG subsystems by base message id
/// (`osfmk/mach/*.defs` `subsystem` declarations).
const SUBSYSTEMS: &[(u32, u32, &str)] = &[
    (200, 300, "mach_host"),
    (400, 500, "host_priv"),
    (600, 700, "host_security"),
    (1000, 1100, "clock"),
    (1200, 1300, "clock_priv"),
    (2400, 2500, "exc"),
    (3000, 3100, "processor"),
    (3200, 3400, "mach_port"),
    (3400, 3600, "task"),
    (3600, 3800, "thread_act"),
    (3800, 4000, "vm_map"),
    (4000, 4100, "processor_set"),
    (4800, 4900, "mach_vm"),
    (4900, 5000, "memory_entry"),
    (5400, 5500, "mach_voucher"),
    (8000, 8100, "task_restartable"),
];

/// Subsystems whose requests act only on IPC state, which this task shares
/// with the host task, and are forwarded.
const IPC_ONLY: &[&str] = &["mach_port"];

fn subsystem(id: u32) -> Option<&'static str> {
    SUBSYSTEMS
        .iter()
        .find(|(start, end, _)| (*start..*end).contains(&id))
        .map(|(_, _, name)| *name)
}

pub(super) fn send(
    kernel: &mut Kernel,
    name: &'static str,
    index: u32,
    arguments: &[u64],
) -> Result<u64> {
    let destination = destination(name, arguments)?;
    if let Some((port, id)) = destination
        && kernel.kernel_objects.contains(&port)
    {
        match subsystem(id) {
            Some(subsystem) if IPC_ONLY.contains(&subsystem) => {}
            Some(subsystem) => bail!(
                "{name}: {subsystem} request {id} (routine {}) to this process's kernel object \
                 {port:#x} is not serviced by the hosted kernel",
                id - SUBSYSTEMS
                    .iter()
                    .find(|(_, _, candidate)| *candidate == subsystem)
                    .map_or(0, |(start, _, _)| *start)
            ),
            None => bail!(
                "{name}: request {id} to this process's kernel object {port:#x} belongs to no \
                 kernel MIG subsystem"
            ),
        }
    }
    forward_trap(kernel, index, arguments)
}

/// The destination port and message id of a send, if the call sends.
fn destination(name: &str, arguments: &[u64]) -> Result<Option<(u32, u32)>> {
    if arguments[1] & SEND == 0 {
        return Ok(None);
    }
    if name == "mach_msg2_trap" {
        // The header travels in registers: `msgh_remote_and_local_port`
        // and `msgh_voucher_and_id`.
        return Ok(Some((
            (arguments[3] & LOW_HALF) as u32,
            (arguments[4] >> 32) as u32,
        )));
    }
    let header = arguments[0];
    match (
        memory::read_u32(header + HEADER_REMOTE_PORT),
        memory::read_u32(header + HEADER_ID),
    ) {
        (Some(port), Some(id)) => Ok(Some((port, id))),
        // The host kernel reports the bad header itself.
        _ => Ok(None),
    }
}
