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
//!
//! A received message's out-of-line memory moves to guest pages of its own
//! ([`received`]), as the arm64 kernel places it.
use super::server::{self, NDR_RECORD, Object, Reply, Request};
use super::{Kernel, forward_trap, index_of};
use crate::hosted::darwin::{
    self, MACH_MSG_TYPE_MAKE_SEND, MACH_PORT_RIGHT_RECEIVE, MACH_SEND_INVALID_DEST, mach_msg,
};
use crate::hosted::threads::lock;
use crate::hosted::unsupported::{self, Failure, Kind};
use crate::hosted::{forward, memory};
use crate::mach::mig;
use anyhow::{Context as _, Result, bail};

/// `MACH_SEND_MSG` (and `MACH64_SEND_MSG`).
const SEND: u64 = darwin::MACH_SEND_MSG as u64;
/// `MACH_RCV_MSG`.
const RECEIVE: u64 = darwin::MACH_RCV_MSG as u64;
/// `mach_msg_header_t` field offsets.
const HEADER_REMOTE_PORT: u64 = 8;
const HEADER_ID: u64 = 20;
const HEADER_BYTES: u64 = 24;
const LOW_HALF: u64 = 0xffff_ffff;
/// `MIG_BAD_ID`: no routine of the destination has the message's ID.
const MIG_BAD_ID: u32 = (-303i32) as u32;
/// `MACH_SEND_INVALID_OPTIONS`.
const MACH_SEND_INVALID_OPTIONS: u32 = 0x1000_0013;
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
    pc: u64,
) -> Result<u64> {
    if let Some((port, id)) = destination(name, arguments)
        && let Some(object) = kernel_object(kernel, port, id)
    {
        // A guest thread's name with no reference of the guest's left is
        // the host thread library's alone: the guest holds no right.
        if object == Object::Thread && super::thread::guest_references(port) == 0 {
            return Ok(u64::from(MACH_SEND_INVALID_DEST));
        }
        let routine = match (mig::subsystem(id), mig::routine(id)) {
            (Some(subsystem), _) if IPC_ONLY.contains(&subsystem.name) => {
                return forward_trap(kernel, index, arguments);
            }
            // A routine of another object's subsystem: the kernel converts
            // the destination to that object, which fails for this one in
            // either kernel, and the routine answers the failure.
            (Some(subsystem), Some(_)) if super::object_of(subsystem.name) != Some(object) => {
                return forward_trap(kernel, index, arguments);
            }
            (Some(_), Some(routine))
                if FORWARDED_ROUTINES.contains(&(routine.subsystem, routine.name)) =>
            {
                return forward_trap(kernel, index, arguments);
            }
            (_, routine) => routine,
        };
        let Some(request) = request(name, arguments)
            .with_context(|| format!("message {id} to kernel object {port:#x}"))?
        else {
            return forward_trap(kernel, index, arguments);
        };
        let body = Request {
            body: &request.body,
        };
        let complex = request.bits & MACH_MSGH_BITS_COMPLEX != 0;
        let moves = request.bits & 0x1f == MACH_MSG_TYPE_MOVE_SEND;
        if moves && let Some(status) = moved_destination(kernel, name, object, port)? {
            return Ok(u64::from(status));
        }
        let reply = match routine {
            // A number no routine of the object's subsystem has, or of no
            // kernel-served subsystem: the kernel's MIG server answers
            // MIG_BAD_ID.
            None => Reply::Failure(MIG_BAD_ID),
            Some(routine) => {
                let subject = format!("{}.{}", routine.subsystem, routine.name);
                let served = match server::serve(kernel, object, port, routine.name, complex, &body)
                {
                    Ok(served) => served,
                    // An unsupported operation fails as the routine's error,
                    // its reply's RetCode.
                    Err(error) => Some(Reply::Failure(
                        match unsupported::recover(error, Kind::MigRoutine, pc, Some(&subject))? {
                            Failure::Kern(code) => code,
                            _ => darwin::KERN_FAILURE,
                        },
                    )),
                };
                match served {
                    // The host kernel consumes a moved destination itself.
                    Some(Reply::Forward) => return forward_trap(kernel, index, arguments),
                    Some(Reply::NotSent(status)) => return Ok(u64::from(status)),
                    Some(reply) => {
                        if kernel.trace {
                            eprintln!("stela: mig {}.{} answered", routine.subsystem, routine.name);
                        }
                        reply
                    }
                    // A routine the hosted kernel does not serve: MIG_BAD_ID,
                    // as for a routine the kernel lacks.
                    None => {
                        unsupported::report(
                            Kind::MigRoutine,
                            pc,
                            &format!(
                                "{subject} (message {id}) to this process's kernel object: {}",
                                server::refusal(object, routine.name)
                            ),
                            Failure::Kern(MIG_BAD_ID),
                            Some(&subject),
                        )?;
                        Reply::Failure(MIG_BAD_ID)
                    }
                }
            }
        };
        if moves {
            // The request consumed the moved reference.
            server::release_send(port);
        }
        // The kernel destroys the request with the voucher it carried.
        if (request.bits >> 16) & 0x1f == MACH_MSG_TYPE_MOVE_SEND {
            server::release_send(request.voucher);
        }
        return answer(kernel, name, index, arguments, &request, id, reply);
    }
    forward_trap(kernel, index, arguments)
}

/// `mach_msg_descriptor_type_t`: the out-of-line forms, whose received
/// memory the host kernel places in its own 4 KiB pages.
const OOL_DESCRIPTOR: u8 = 1;
const OOL_PORTS_DESCRIPTOR: u8 = 2;
const OOL_VOLATILE_DESCRIPTOR: u8 = 3;
const PORT_DESCRIPTOR: u8 = 0;
/// Received descriptor sizes on LP64: a port descriptor, and the others.
const PORT_DESCRIPTOR_BYTES: u64 = 12;
const DESCRIPTOR_BYTES: u64 = 16;
/// `mach_msg_body_t`'s `msgh_descriptor_count` follows the header.
const DESCRIPTOR_COUNT: u64 = HEADER_BYTES;
/// `mach_msg_vector_t`: `msgv_data`, `msgv_rcv_addr`, then the sizes.
const VECTOR_RECEIVE_ADDRESS: u64 = 8;

/// The buffer a successful receive of the call wrote its message to.
fn receive_buffer(name: &str, arguments: &[u64]) -> Option<u64> {
    match name {
        // `rcv_msg`, else the send buffer.
        "mach_msg_overwrite_trap" if arguments[7] != 0 => Some(arguments[7]),
        "mach_msg2_trap" if arguments[1] & MESSAGE_VECTOR != 0 => {
            // The first vector is the message's.
            let vector = arguments[0];
            match memory::read_u64(vector + VECTOR_RECEIVE_ADDRESS)? {
                0 => memory::read_u64(vector),
                address => Some(address),
            }
        }
        _ => Some(arguments[0]),
    }
}

/// After a successful receive, move each out-of-line region of the
/// received message into guest pages of its own and rewrite its
/// descriptor's address ([`memory::own_guest_pages`]): the guest releases
/// the region rounded to 16 KiB pages, as the arm64 kernel placed it.
pub(super) fn received(name: &str, arguments: &[u64]) -> Result<()> {
    if arguments[1] & RECEIVE == 0 {
        return Ok(());
    }
    let Some(message) = receive_buffer(name, arguments) else {
        return Ok(());
    };
    let Some(bits) = memory::read_u32(message) else {
        return Ok(());
    };
    if bits & MACH_MSGH_BITS_COMPLEX == 0 {
        return Ok(());
    }
    let Some(count) = memory::read_u32(message + DESCRIPTOR_COUNT) else {
        return Ok(());
    };
    let mut at = message + DESCRIPTOR_COUNT + 4;
    for _ in 0..count {
        let Some(kind) = memory::read_u32(at + 8).map(|word| (word >> 24) as u8) else {
            bail!("{name}: a received descriptor at {at:#x} is unreadable");
        };
        if kind == PORT_DESCRIPTOR {
            at += PORT_DESCRIPTOR_BYTES;
            continue;
        }
        let (Some(address), Some(length)) = (memory::read_u64(at), memory::read_u32(at + 12))
        else {
            bail!("{name}: a received descriptor at {at:#x} is unreadable");
        };
        let bytes = match kind {
            OOL_DESCRIPTOR | OOL_VOLATILE_DESCRIPTOR => u64::from(length),
            // Port names, one `mach_port_name_t` each.
            OOL_PORTS_DESCRIPTOR => u64::from(length) * 4,
            _ => 0,
        };
        if address != 0
            && let Some(moved) = memory::own_guest_pages(address, bytes)?
            && !memory::write_u64(at, moved)
        {
            bail!("{name}: a received descriptor at {at:#x} is not writable");
        }
        at += DESCRIPTOR_BYTES;
    }
    Ok(())
}

/// Copy in a request's moved destination right (`ipc_right_copyin`): a
/// guest thread's (`thread_act_consume_ref_t`), whose pinned last
/// reference cannot move (`KERN_INVALID_CAPABILITY`, so
/// `MACH_SEND_INVALID_DEST`). A third-party task's violation is a soft
/// EXC_GUARD (`ICP_OPTIONS_PINNED_3P_SOFT`), a crash report the process
/// does not see; a platform-restricted task's is fatal, which stops the
/// run. The failure, if the send fails.
fn moved_destination(
    kernel: &Kernel,
    name: &str,
    object: Object,
    port: u32,
) -> Result<Option<u32>> {
    if object != Object::Thread {
        unsupported::refuse!(
            Failure::Kern(MACH_SEND_INVALID_DEST),
            "{name}: a request that moves its {object:?} kernel-object right"
        );
    }
    if !super::thread::pinned(kernel, port) || super::thread::guest_references(port) > 1 {
        return Ok(None);
    }
    let restricted = lock(&kernel.process.executable)
        .signature
        .as_ref()
        .is_some_and(|signature| signature.platform_restricted());
    if restricted {
        unsupported::refuse!(
            Failure::Kern(MACH_SEND_INVALID_DEST),
            "{name}: moving the last reference of the pinned thread port {port:#x}, which \
             raises a platform-restricted task's fatal EXC_GUARD (kGUARD_EXC_MOD_REFS)"
        );
    }
    Ok(Some(MACH_SEND_INVALID_DEST))
}

/// The kernel object `port` names in this task: the task, the host, or
/// any of the task's threads.
fn kernel_object(kernel: &Kernel, port: u32, id: u32) -> Option<Object> {
    let [task, thread, host] = kernel.kernel_objects();
    if port == task {
        Some(Object::Task)
    } else if port == host {
        Some(Object::Host)
    } else if port == thread || kernel.process.runtime.registry.contains_port(port) {
        Some(Object::Thread)
    } else if mig::subsystem(id).is_some_and(|subsystem| subsystem.name == "processor_set")
        && default_processor_set(host) == Some(port)
    {
        Some(Object::ProcessorSet)
    } else {
        None
    }
}

/// This space's name for the default processor set's name port, which
/// `processor_set_default` on the host port gives (the extra reference it
/// makes is dropped again).
fn default_processor_set(host: u32) -> Option<u32> {
    unsafe extern "C" {
        fn processor_set_default(host: u32, set: *mut u32) -> i32;
    }
    let mut set = 0u32;
    // SAFETY: an out-parameter for one port name.
    if unsafe { processor_set_default(host, &mut set) } != 0 {
        return None;
    }
    server::release_send(set);
    Some(set)
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
    voucher: u32,
    body: Vec<u8>,
}

/// The request a send carries, or `None` when its header or body is
/// unreadable (the host kernel reports the fault itself).
fn request(name: &str, arguments: &[u64]) -> Result<Option<Sent>> {
    let (header, bits, size, reply_port, voucher) = if name == "mach_msg2_trap" {
        if arguments[1] & MESSAGE_VECTOR != 0 {
            unsupported::refuse!(
                Failure::Kern(MACH_SEND_INVALID_OPTIONS),
                "{name}: a vector message to a kernel object"
            );
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
    let Some(body_bytes) = size.checked_sub(HEADER_BYTES) else {
        return Ok(None);
    };
    let Some(body) = memory::read(header + HEADER_BYTES, body_bytes as usize) else {
        return Ok(None);
    };
    Ok(Some(Sent {
        bits,
        reply_port,
        voucher,
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
        let mut body = Vec::new();
        let mut bits = right.1;
        // A port array's names stay in place until the reply is sent.
        let mut _kept = Vec::new();
        match reply {
            Reply::Success(out) => {
                body.extend(NDR_RECORD);
                body.extend(0u32.to_le_bytes());
                body.extend(out);
            }
            Reply::Failure(code) => {
                body.extend(NDR_RECORD);
                body.extend(code.to_le_bytes());
            }
            Reply::Complex {
                descriptors,
                body: out,
            } => {
                bits |= MACH_MSGH_BITS_COMPLEX;
                body.extend((descriptors.len() as u32).to_le_bytes());
                for descriptor in &descriptors {
                    body.extend(descriptor.bytes());
                }
                body.extend(NDR_RECORD);
                body.extend(out);
                _kept = descriptors;
            }
            Reply::Descriptors(descriptors) => {
                bits |= MACH_MSGH_BITS_COMPLEX;
                body.extend((descriptors.len() as u32).to_le_bytes());
                for descriptor in &descriptors {
                    body.extend(descriptor.bytes());
                }
                _kept = descriptors;
            }
            Reply::Forward | Reply::NotSent(_) => {
                unreachable!("forwarded and unsent requests are not answered")
            }
        }
        let size = HEADER_BYTES as u32 + body.len() as u32;
        let mut message = Vec::with_capacity(size as usize);
        for word in [bits, size, right.0, 0, 0, id + mig::REPLY_OFFSET] {
            message.extend(word.to_le_bytes());
        }
        message.extend(body);
        let sent = host_message(&mut message, SEND, size, 0, 0);
        if sent != 0 {
            bail!("{name}: the reply to message {id} could not be sent: {sent:#x}");
        }
    } else if let Reply::Complex { descriptors, .. } | Reply::Descriptors(descriptors) = &reply {
        // No reply is sent: the kernel destroys it, and the rights it
        // carries with it.
        for descriptor in descriptors {
            descriptor.release();
        }
    }
    let mut receive = arguments.to_vec();
    receive[1] &= !SEND;
    if receive[1] & RECEIVE == 0 {
        return Ok(0);
    }
    forward_trap(kernel, index, &receive)
}

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
    let relay = relay(kernel, name)?;
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

/// The port only the hosted kernel receives on, which carries rights.
fn relay(kernel: &mut Kernel, name: &str) -> Result<u32> {
    if let Some(relay) = kernel.mig_relay {
        return Ok(relay);
    }
    let mut relay = 0u32;
    let status = forward::mach(
        index_of("_kernelrpc_mach_port_allocate_trap"),
        &[
            u64::from(kernel.process.task_port()),
            u64::from(MACH_PORT_RIGHT_RECEIVE),
            &raw mut relay as u64,
        ],
    )
    .rax;
    if status != 0 {
        bail!("{name}: the MIG reply relay port could not be allocated: {status:#x}");
    }
    kernel.mig_relay = Some(relay);
    Ok(relay)
}

/// A carrier of one port descriptor: header, descriptor count, descriptor.
const PORT_CARRIER_BYTES: usize = HEADER_BYTES as usize + 4 + PORT_DESCRIPTOR_BYTES as usize;

/// Carry a request's port descriptor, `name` with `disposition`, as the
/// kernel copies it in with the request: the right then received into
/// this space, as its name and received disposition (a send right's is
/// [`server::MOVE_SEND`]), or the send's failure, when the kernel would
/// not have taken the request.
pub(super) fn carry_port(
    kernel: &mut Kernel,
    routine: &str,
    name: u32,
    disposition: u8,
) -> Result<std::result::Result<(u32, u8), u32>> {
    let relay = relay(kernel, routine)?;
    let mut carrier = Vec::with_capacity(PORT_CARRIER_BYTES);
    for word in [
        MACH_MSGH_BITS_COMPLEX | MACH_MSG_TYPE_MAKE_SEND,
        PORT_CARRIER_BYTES as u32,
        relay,
        0,
        0,
        0,
        1,
    ] {
        carrier.extend(word.to_le_bytes());
    }
    carrier.extend(server::Descriptor::Port { name, disposition }.bytes());
    let status = host_message(&mut carrier, SEND, PORT_CARRIER_BYTES as u32, 0, 0);
    if status != 0 {
        return Ok(Err(status as u32));
    }
    let mut received = vec![0u8; PORT_CARRIER_BYTES + RELAY_BUFFER_BYTES];
    let size = received.len() as u32;
    let status = host_message(&mut received, RECEIVE, 0, size, relay);
    if status != 0 {
        bail!(
            "{routine}: a request's right could not be received from the relay port: {status:#x}"
        );
    }
    let at = HEADER_BYTES as usize + 4;
    let carried = u32::from_le_bytes(received[at..at + 4].try_into().unwrap());
    Ok(Ok((carried, received[at + 10])))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::memory::{PAGE_BYTES, PAGE_MASK, Protection};

    #[test]
    fn received_out_of_line_memory_moves_to_guest_pages() {
        let block = memory::allocate(0, 2 * PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        let region = block + 0x2000;
        assert!(memory::write(region, b"data"));
        // A complex message: a port descriptor, then an OOL descriptor.
        let mut message = Vec::new();
        for word in [MACH_MSGH_BITS_COMPLEX, 0, 0, 0, 0, 0, 2] {
            message.extend(u32::to_le_bytes(word));
        }
        message.extend([0u8; 11]);
        message.push(PORT_DESCRIPTOR);
        message.extend(region.to_le_bytes());
        message.extend([0, 0, 0, OOL_DESCRIPTOR]);
        message.extend(0x100u32.to_le_bytes());
        let buffer = message.as_mut_ptr() as u64;
        let mut arguments = [0u64; 8];
        arguments[0] = buffer;
        // A send alone leaves the buffer as it is.
        arguments[1] = SEND;
        received("mach_msg_trap", &arguments).unwrap();
        assert_eq!(memory::read_u64(buffer + 40), Some(region));
        arguments[1] = SEND | RECEIVE;
        received("mach_msg_trap", &arguments).unwrap();
        let moved = memory::read_u64(buffer + 40).unwrap();
        assert_ne!(moved, region);
        assert_eq!(moved & PAGE_MASK, 0);
        assert_eq!(memory::read(moved, 4).unwrap(), b"data");
        memory::deallocate(moved, PAGE_BYTES).unwrap();
        memory::deallocate(block, 0x2000).unwrap();
        memory::deallocate(block + 0x3000, 2 * PAGE_BYTES - 0x3000).unwrap();
    }
}
