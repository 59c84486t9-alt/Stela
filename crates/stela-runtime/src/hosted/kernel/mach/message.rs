//! Mach message sends. A message to a port in another task's or the host
//! kernel's IPC space is forwarded unchanged: its bytes have one layout on
//! both LP64 ABIs. A message to this task's, any of its threads' or the
//! host's own kernel object is a MIG request the host kernel would serve
//! with x86 semantics; those requests are identified by the pinned MIG
//! catalog ([`crate::mach::mig`]) and answered by [`server`] or refused
//! by routine name.
//!
//! An answered request's reply goes to its reply port as the kernel sends
//! it: the request's reply right is first carried, with the request's
//! disposition, to a relay port only the hosted kernel receives on, as
//! the kernel receives it with the request, and the reply then consumes
//! it. (A reply port's send-once right may only be made as a message's
//! reply port, so the kernel cannot address the reply port directly.) A
//! combined receive then proceeds on the host as for any reply. Known
//! limit: the host builds the received trailer, so its sender and audit
//! tokens are this process's rather than the kernel's.
use super::server::{self, NDR_RECORD, Object, Reply, Request};
use super::{Kernel, forward_trap, index_of};
use crate::hosted::{forward, memory};
use crate::mach::mig;
use anyhow::{Context as _, Result, bail};

/// `MACH_SEND_MSG` (and `MACH64_SEND_MSG`).
const SEND: u64 = 0x1;
/// `MACH_RCV_MSG`.
const RECEIVE: u64 = 0x2;
/// `mach_msg_header_t` field offsets.
const HEADER_REMOTE_PORT: u64 = 8;
const HEADER_ID: u64 = 20;
const HEADER_BYTES: u64 = 24;
const LOW_HALF: u64 = 0xffff_ffff;
/// `MACH64_MSG_VECTOR`: the message travels in data vectors.
const MESSAGE_VECTOR: u64 = 1 << 32;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
const MACH_MSG_TYPE_MOVE_SEND: u32 = 17;

/// Subsystems whose requests act only on IPC state, which this task shares
/// with the host task, and are forwarded.
pub(super) const IPC_ONLY: &[&str] = &["mach_port"];

/// Kernel-object routines whose answer is the same for an arm64 process:
/// forwarded unchanged. `host_get_clock_service` names a clock whose
/// `mach_timespec_t` time is the host's time base in either ABI, and
/// requests to the clock port it returns are the host kernel's.
/// `semaphore_create` and `semaphore_destroy` make and drop this task's own
/// semaphores, which the forwarded semaphore traps then use.
pub(super) const FORWARDED_ROUTINES: &[(&str, &str)] = &[
    ("mach_host", "host_get_clock_service"),
    ("task", "semaphore_create"),
    ("task", "semaphore_destroy"),
];

pub(super) fn send(
    kernel: &mut Kernel,
    name: &'static str,
    index: u32,
    arguments: &[u64],
) -> Result<u64> {
    if let Some((port, id)) = destination(name, arguments)
        && let Some(object) = kernel_object(kernel, port)
    {
        match (mig::subsystem(id), mig::routine(id)) {
            (Some(subsystem), _) if IPC_ONLY.contains(&subsystem.name) => {}
            (Some(_), Some(routine))
                if FORWARDED_ROUTINES.contains(&(routine.subsystem, routine.name)) => {}
            (Some(_), Some(routine))
                if let Some(request) = request(name, arguments).with_context(|| {
                    format!("{}.{} (message {id})", routine.subsystem, routine.name)
                })? =>
            {
                let body = Request {
                    body: &request.body,
                };
                let complex = request.bits & MACH_MSGH_BITS_COMPLEX != 0;
                let served = server::serve(kernel, object, routine.name, complex, &body)?;
                if matches!(served, Some(Reply::Forward)) {
                    return forward_trap(kernel, index, arguments);
                }
                if let Some(reply) = served {
                    if kernel.trace {
                        eprintln!("stela: mig {}.{} answered", routine.subsystem, routine.name);
                    }
                    return answer(kernel, name, index, arguments, &request, id, reply);
                }
                bail!(
                    "{name}: {}.{} (message {id}) to this process's kernel object {port:#x} is \
                     not serviced by the hosted kernel (arguments {arguments:x?})",
                    routine.subsystem,
                    routine.name
                )
            }
            (Some(subsystem), Some(routine)) => bail!(
                "{name}: {}.{} (message {id}) to this process's kernel object {port:#x} is \
                 not serviced by the hosted kernel (arguments {arguments:x?})",
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

/// The kernel object `port` names in this task: the task, the host, or
/// any of the task's threads.
fn kernel_object(kernel: &Kernel, port: u32) -> Option<Object> {
    let [task, thread, host] = kernel.kernel_objects();
    if port == task {
        Some(Object::Task)
    } else if port == host {
        Some(Object::Host)
    } else if port == thread || kernel.process.runtime.registry.contains_port(port) {
        Some(Object::Thread)
    } else {
        None
    }
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

/// A request to a kernel object, as sent.
struct Sent {
    bits: u32,
    reply_port: u32,
    body: Vec<u8>,
}

/// The request a send carries, or `None` when its header or body is
/// unreadable (the host kernel reports the fault itself).
fn request(name: &str, arguments: &[u64]) -> Result<Option<Sent>> {
    let (header, bits, size, reply_port, voucher) = if name == "mach_msg2_trap" {
        if arguments[1] & MESSAGE_VECTOR != 0 {
            bail!("{name}: a vector message to a kernel object is not implemented");
        }
        (
            arguments[0],
            (arguments[2] & LOW_HALF) as u32,
            arguments[2] >> 32,
            (arguments[3] >> 32) as u32,
            (arguments[4] & LOW_HALF) as u32,
        )
    } else {
        let header = arguments[0];
        let (Some(bits), Some(local), Some(voucher)) = (
            memory::read_u32(header),
            memory::read_u32(header + 12),
            memory::read_u32(header + 16),
        ) else {
            return Ok(None);
        };
        (header, bits, arguments[2] & LOW_HALF, local, voucher)
    };
    if bits & 0x1f == MACH_MSG_TYPE_MOVE_SEND || voucher != 0 {
        bail!(
            "{name}: a request that moves its kernel-object right or carries a voucher is not \
             implemented (bits {bits:#x}, voucher {voucher:#x})"
        );
    }
    let Some(body_bytes) = size.checked_sub(HEADER_BYTES) else {
        return Ok(None);
    };
    let Some(body) = memory::read(header + HEADER_BYTES, body_bytes as usize) else {
        return Ok(None);
    };
    Ok(Some(Sent {
        bits,
        reply_port,
        body,
    }))
}

/// Send `reply` to the request's reply port as the kernel would, then
/// perform the call's receive, if it has one.
fn answer(
    kernel: &mut Kernel,
    name: &str,
    index: u32,
    arguments: &[u64],
    request: &Sent,
    id: u32,
    reply: Reply,
) -> Result<u64> {
    let disposition = (request.bits >> 8) & 0x1f;
    if request.reply_port != 0 && disposition != 0 {
        let right = carry_reply_right(kernel, name, request.reply_port, disposition)?;
        let mut body = NDR_RECORD.to_vec();
        match reply {
            Reply::Success(out) => {
                body.extend(0u32.to_le_bytes());
                body.extend(out);
            }
            Reply::Failure(code) => body.extend(code.to_le_bytes()),
            Reply::Forward => unreachable!("forwarded requests are not answered"),
        }
        let size = HEADER_BYTES as u32 + body.len() as u32;
        let mut message = Vec::with_capacity(size as usize);
        for word in [right.1, size, right.0, 0, 0, id + mig::REPLY_OFFSET] {
            message.extend(word.to_le_bytes());
        }
        message.extend(body);
        let sent = host_message(&mut message, SEND, size, 0, 0);
        if sent != 0 {
            bail!("{name}: the reply to message {id} could not be sent: {sent:#x}");
        }
    }
    let mut receive = arguments.to_vec();
    receive[1] &= !SEND;
    if receive[1] & RECEIVE == 0 {
        return Ok(0);
    }
    forward_trap(kernel, index, &receive)
}

const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;
const MACH_PORT_RIGHT_RECEIVE: u64 = 1;
/// A received relay message: its header and the largest trailer.
const RELAY_BUFFER_BYTES: usize = 24 + 76;

/// Carry the request's reply right to the relay port and receive it there:
/// its name in this space and the disposition that sends the reply to it.
fn carry_reply_right(
    kernel: &mut Kernel,
    name: &str,
    reply_port: u32,
    disposition: u32,
) -> Result<(u32, u32)> {
    let relay = match kernel.mig_relay {
        Some(relay) => relay,
        None => {
            let mut relay = 0u32;
            let status = forward::mach(
                index_of("_kernelrpc_mach_port_allocate_trap"),
                &[
                    u64::from(kernel.process.task_port),
                    MACH_PORT_RIGHT_RECEIVE,
                    &raw mut relay as u64,
                ],
            )
            .rax;
            if status != 0 {
                bail!("{name}: the MIG reply relay port could not be allocated: {status:#x}");
            }
            kernel.mig_relay = Some(relay);
            relay
        }
    };
    let mut carrier = Vec::with_capacity(HEADER_BYTES as usize);
    for word in [
        MACH_MSG_TYPE_MAKE_SEND | disposition << 8,
        HEADER_BYTES as u32,
        relay,
        reply_port,
        0,
        0,
    ] {
        carrier.extend(word.to_le_bytes());
    }
    let status = host_message(&mut carrier, SEND, HEADER_BYTES as u32, 0, 0);
    if status != 0 {
        bail!("{name}: the reply right could not be carried to the relay port: {status:#x}");
    }
    let mut received = vec![0u8; RELAY_BUFFER_BYTES];
    let status = host_message(&mut received, RECEIVE, 0, RELAY_BUFFER_BYTES as u32, relay);
    if status != 0 {
        bail!("{name}: the reply right could not be received from the relay port: {status:#x}");
    }
    let word = |at: usize| u32::from_le_bytes(received[at..at + 4].try_into().unwrap());
    // The received header names the carried right as its remote port, its
    // bits' remote field the right's type, which is how a reply moves it.
    Ok((word(8), word(0) & 0x1f))
}

unsafe extern "C" {
    fn mach_msg(
        message: *mut u8,
        option: i32,
        send_size: u32,
        receive_size: u32,
        receive_name: u32,
        timeout: u32,
        notify: u32,
    ) -> i32;
}

/// The hosted kernel's own message operation, through the host library,
/// which selects the host kernel's current message trap and options.
fn host_message(
    buffer: &mut [u8],
    option: u64,
    send_size: u32,
    receive_size: u32,
    receive_name: u32,
) -> i32 {
    assert!(buffer.len() >= send_size.max(receive_size) as usize);
    // SAFETY: the buffer holds the message sent and the largest received.
    unsafe {
        mach_msg(
            buffer.as_mut_ptr(),
            option as i32,
            send_size,
            receive_size,
            receive_name,
            0,
            0,
        )
    }
}
