//! Mach message sends. A message to a port in another task's or the host
//! kernel's IPC space is forwarded unchanged: its bytes have one layout on
//! both LP64 ABIs. A message to this task's, its thread's or the host's own
//! kernel object is a MIG request the host kernel would serve with x86
//! semantics; those requests are identified by the pinned MIG catalog
//! ([`crate::mach::mig`]) and serviced here or refused by routine name.
use super::{Kernel, forward_trap};
use crate::hosted::memory;
use crate::mach::mig;
use anyhow::{Result, bail};

/// `MACH_SEND_MSG` (and `MACH64_SEND_MSG`).
const SEND: u64 = 0x1;
/// `mach_msg_header_t` field offsets.
const HEADER_REMOTE_PORT: u64 = 8;
const HEADER_ID: u64 = 20;
const LOW_HALF: u64 = 0xffff_ffff;

/// Subsystems whose requests act only on IPC state, which this task shares
/// with the host task, and are forwarded.
const IPC_ONLY: &[&str] = &["mach_port"];

pub(super) fn send(
    kernel: &mut Kernel,
    name: &'static str,
    index: u32,
    arguments: &[u64],
) -> Result<u64> {
    if let Some((port, id)) = destination(name, arguments)
        && kernel.kernel_objects.contains(&port)
    {
        match (mig::subsystem(id), mig::routine(id)) {
            (Some(subsystem), _) if IPC_ONLY.contains(&subsystem.name) => {}
            (Some(subsystem), Some(routine)) => bail!(
                "{name}: {}.{} (message {id}) to this process's kernel object {port:#x} is \
                 not serviced by the hosted kernel",
                subsystem.name,
                routine.name
            ),
            (Some(subsystem), None) => bail!(
                "{name}: message {id} to kernel object {port:#x} is a skipped number of \
                 {}: the kernel answers MIG_BAD_ID, which is not modeled",
                subsystem.name
            ),
            (None, _) => bail!(
                "{name}: message {id} to this process's kernel object {port:#x} belongs to \
                 no kernel-served MIG subsystem"
            ),
        }
    }
    forward_trap(kernel, index, arguments)
}

/// The destination port and message id of a send, if the call sends and
/// its header is readable (the host kernel reports a bad header itself).
fn destination(name: &str, arguments: &[u64]) -> Option<(u32, u32)> {
    if arguments[1] & SEND == 0 {
        return None;
    }
    if name == "mach_msg2_trap" {
        // The header travels in registers: `msgh_remote_and_local_port`
        // and `msgh_voucher_and_id`.
        return Some((
            (arguments[3] & LOW_HALF) as u32,
            (arguments[4] >> 32) as u32,
        ));
    }
    let header = arguments[0];
    Some((
        memory::read_u32(header + HEADER_REMOTE_PORT)?,
        memory::read_u32(header + HEADER_ID)?,
    ))
}
