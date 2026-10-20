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
//! Out-of-line memory stays in whole guest pages, so that a guest's 16 KiB
//! deallocation never reaches the host's own 4 KiB allocations: a received
//! message's regions, whether by `mach_msg` ([`received`]) or by a port
//! knote ([`received_event`]), move to guest pages of their own, as the
//! arm64 kernel places them, and a region a send deallocates goes with
//! the rest of its guest pages ([`forward_send`]).
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
                return forward_send(kernel, name, index, arguments);
            }
            // A routine of another object's subsystem: the kernel converts
            // the destination to that object, which fails for this one in
            // either kernel, and the routine answers the failure.
            (Some(subsystem), Some(_)) if super::object_of(subsystem.name) != Some(object) => {
                return forward_send(kernel, name, index, arguments);
            }
            (Some(_), Some(routine))
                if FORWARDED_ROUTINES.contains(&(routine.subsystem, routine.name)) =>
            {
                return forward_send(kernel, name, index, arguments);
            }
            (_, routine) => routine,
        };
        let Some(request) = request(name, arguments)
            .with_context(|| format!("message {id} to kernel object {port:#x}"))?
        else {
            return forward_send(kernel, name, index, arguments);
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
                    Some(Reply::Forward) => return forward_send(kernel, name, index, arguments),
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
    forward_send(kernel, name, index, arguments)
}

/// Send a message on the host, as the arm64 kernel would for the guest's
/// pages: an out-of-line region the send deallocates goes with its whole
/// guest pages, and the regions a failed send returns
/// (`mach_msg_receive_pseudo`) are placed in guest pages of their own.
fn forward_send(kernel: &mut Kernel, name: &str, index: u32, arguments: &[u64]) -> Result<u64> {
    if kernel.trace
        && let Some(description) = describe_send(name, arguments)
    {
        eprintln!("stela: {name} sends {description}");
    }
    let outgoing = Outgoing::read(name, arguments);
    let status = forward_trap(kernel, index, arguments)?;
    if let Some(outgoing) = outgoing {
        outgoing.sent(name, status, |start, size| {
            kernel.unslid_change(start, size, |_| None);
        })?;
    }
    Ok(status)
}

/// An outgoing complex message as the guest handed it to the send: where
/// its descriptors are, their bytes, and the out-of-line regions the
/// send deallocates whose guest pages the host's would not cover whole.
struct Outgoing {
    message: u64,
    descriptors: Vec<u8>,
    partial: Vec<Deallocated>,
}

/// An out-of-line region a send deallocates (`vm_map_copyin` with
/// `src_destroy`): the guest pages the arm64 kernel takes and the host
/// pages the host kernel takes of them, which were all mapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deallocated {
    guest: (u64, u64),
    host: (u64, u64),
}

impl Deallocated {
    /// The region of `bytes` at `address`, if it is not empty.
    fn new(address: u64, bytes: u64) -> Option<Self> {
        let end = address.checked_add(bytes)?;
        if bytes == 0 {
            return None;
        }
        Some(Self {
            guest: (memory::trunc_page(address), memory::round_page(end)?),
            host: (
                address & !memory::HOST_PAGE_MASK,
                memory::round_host_page(end)?,
            ),
        })
    }

    /// The parts of the guest pages the host pages leave.
    fn rest(&self) -> [(u64, u64); 2] {
        [(self.guest.0, self.host.0), (self.host.1, self.guest.1)]
    }

    /// Whether the guest pages are the guest's own: wholly mapped by host
    /// regions that begin and end on guest pages, as every mapping the
    /// hosted kernel makes for the guest does. A region beginning or ending
    /// inside them is one the host placed in its own 4 KiB pages, which
    /// may be the runtime's.
    fn guest_owned(&self) -> bool {
        let (start, end) = self.guest;
        let runs = memory::mapped_runs(start, end);
        let mapped: u64 = runs.iter().map(|(start, end)| end - start).sum();
        mapped == end - start
            && runs.iter().all(|&(run, run_end)| {
                (run == start || run & PAGE_MASK == 0)
                    && (run_end == end || run_end & PAGE_MASK == 0)
            })
    }
}

/// The guest's page mask.
const PAGE_MASK: u64 = memory::PAGE_MASK;

/// `mach_msg_return_t` send failures, `MACH_SEND_*`.
const SEND_FAILURE: u32 = 0x1000_0000;

impl Outgoing {
    fn read(name: &str, arguments: &[u64]) -> Option<Self> {
        if arguments[1] & SEND == 0 {
            return None;
        }
        let (message, bits) = if name == "mach_msg2_trap" {
            let message = if arguments[1] & MESSAGE_VECTOR != 0 {
                memory::read_u64(arguments[0])?
            } else {
                arguments[0]
            };
            (message, (arguments[2] & LOW_HALF) as u32)
        } else {
            (arguments[0], memory::read_u32(arguments[0])?)
        };
        if bits & MACH_MSGH_BITS_COMPLEX == 0 {
            return None;
        }
        let count = memory::read_u32(message + DESCRIPTOR_COUNT)?;
        let first = message + DESCRIPTOR_COUNT + 4;
        let descriptors = descriptor_bytes(first, count)?;
        let mut partial = Vec::new();
        let mut at = 0usize;
        for _ in 0..count {
            let Some(header) = descriptors.get(at..at + 12) else {
                break;
            };
            let kind = header[11];
            if kind == PORT_DESCRIPTOR {
                at += PORT_DESCRIPTOR_BYTES as usize;
                continue;
            }
            let Some(rest) = descriptors.get(at + 12..at + 16) else {
                break;
            };
            let address = u64::from_le_bytes(header[..8].try_into().unwrap());
            let length = u64::from(u32::from_le_bytes(rest.try_into().unwrap()));
            let bytes = match kind {
                OOL_DESCRIPTOR | OOL_VOLATILE_DESCRIPTOR => length,
                OOL_PORTS_DESCRIPTOR => length * 4,
                _ => 0,
            };
            if header[8] != 0
                && address != 0
                && let Some(region) = Deallocated::new(address, bytes)
                && region.guest != region.host
            {
                if region.guest_owned() {
                    partial.push(region);
                } else {
                    unsupported::note(
                        Kind::MachTrap,
                        "shared guest page",
                        &format!(
                            "an out-of-line region a send deallocates at {address:#x} lies in \
                             guest pages {:#x}..{:#x} the host maps in parts, which may be the \
                             runtime's own: only the host pages it covers are released",
                            region.guest.0, region.guest.1
                        ),
                    );
                }
            }
            at += DESCRIPTOR_BYTES as usize;
        }
        Some(Self {
            message,
            descriptors,
            partial,
        })
    }

    /// After the host's send returned `status`: a failed send whose copy in
    /// succeeded returns the message in place with copies of its regions
    /// (`mach_msg_receive_pseudo`), which move to guest pages of their
    /// own; once the copy in succeeded, each region it took has the rest
    /// of its guest pages released. `releasing` learns of each range
    /// released before it goes.
    fn sent(&self, name: &str, status: u64, mut releasing: impl FnMut(u64, u64)) -> Result<()> {
        let failed = status as u32 & !0xff == SEND_FAILURE;
        let returned = failed
            && memory::read(self.message + DESCRIPTOR_COUNT + 4, self.descriptors.len())
                .is_some_and(|now| now != self.descriptors);
        if returned {
            place_received(name, self.message)?;
        }
        if failed && !returned {
            // The copy in failed: the regions stay the sender's.
            return Ok(());
        }
        for region in &self.partial {
            for (start, end) in region.rest() {
                for (run, run_end) in memory::mapped_runs(start, end) {
                    releasing(run, run_end - run);
                    memory::deallocate(run, run_end - run)?;
                }
            }
        }
        Ok(())
    }
}

/// The bytes of the `count` descriptors at `first`, or `None` when they
/// are unreadable (the send then fails on its own).
fn descriptor_bytes(first: u64, count: u32) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut at = first;
    for _ in 0..count.min(MAX_DESCRIPTORS) {
        let kind = (memory::read_u32(at + 8)? >> 24) as u8;
        let size = if kind == PORT_DESCRIPTOR {
            PORT_DESCRIPTOR_BYTES
        } else {
            DESCRIPTOR_BYTES
        };
        bytes.extend(memory::read(at, size as usize)?);
        at += size;
    }
    Some(bytes)
}

/// A forwarded send as `--trace` shows it: the header's bits, size,
/// ports and ID, and each descriptor's kind, size or right, and flags.
fn describe_send(name: &str, arguments: &[u64]) -> Option<String> {
    if arguments[1] & SEND == 0 {
        return None;
    }
    let (message, words) = if name == "mach_msg2_trap" {
        let message = if arguments[1] & MESSAGE_VECTOR != 0 {
            memory::read_u64(arguments[0])?
        } else {
            arguments[0]
        };
        let [_, _, bits_size, ports, voucher_id, ..] = *arguments else {
            return None;
        };
        let low = |word: u64| (word & LOW_HALF) as u32;
        let high = |word: u64| (word >> 32) as u32;
        (
            message,
            [
                low(bits_size),
                high(bits_size),
                low(ports),
                high(ports),
                low(voucher_id),
                high(voucher_id),
            ],
        )
    } else {
        let header = memory::read(arguments[0], HEADER_BYTES as usize)?;
        let word = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
        (
            arguments[0],
            [word(0), word(4), word(8), word(12), word(16), word(20)],
        )
    };
    let [bits, size, remote, local, voucher, id] = words;
    let mut text = format!(
        "message {id} ({size} bytes, bits {bits:#x}) to {remote:#x}, reply {local:#x}, voucher \
         {voucher:#x}"
    );
    if bits & MACH_MSGH_BITS_COMPLEX != 0 {
        let count = memory::read_u32(message + DESCRIPTOR_COUNT)?;
        let descriptors = descriptor_bytes(message + DESCRIPTOR_COUNT + 4, count)?;
        text.push_str(": ");
        text.push_str(&describe_descriptors(&descriptors));
    }
    Some(text)
}

/// Each descriptor's kind and what it carries.
fn describe_descriptors(bytes: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut at = 0;
    while let Some(descriptor) = bytes.get(at..) {
        let Some(&kind) = descriptor.get(11) else {
            break;
        };
        let word = |at: usize| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
        let disposition = descriptor[10];
        if kind == PORT_DESCRIPTOR {
            parts.push(format!("port {:#x} ({disposition})", word(0)));
            at += PORT_DESCRIPTOR_BYTES as usize;
            continue;
        }
        let Some(descriptor) = descriptor.get(..DESCRIPTOR_BYTES as usize) else {
            break;
        };
        let address = u64::from_le_bytes(descriptor[..8].try_into().unwrap());
        let (deallocate, copy) = (descriptor[8], descriptor[9]);
        parts.push(match kind {
            OOL_DESCRIPTOR | OOL_VOLATILE_DESCRIPTOR => format!(
                "{} {:#x} bytes at {address:#x} (copy {copy}, deallocate {deallocate})",
                if kind == OOL_DESCRIPTOR {
                    "out-of-line"
                } else {
                    "volatile"
                },
                word(12)
            ),
            OOL_PORTS_DESCRIPTOR => format!(
                "{} ports at {address:#x} ({disposition}, copy {copy}, deallocate {deallocate})",
                word(12)
            ),
            GUARDED_PORT_DESCRIPTOR => format!(
                "guarded port {:#x} ({disposition}, flags {:#x}, context {address:#x})",
                word(12),
                u16::from_le_bytes([descriptor[8], descriptor[9]])
            ),
            kind => format!("descriptor of type {kind}"),
        });
        at += DESCRIPTOR_BYTES as usize;
    }
    parts.join(", ")
}

/// A bound on the descriptors read of a message, far above what a
/// message's body space holds.
const MAX_DESCRIPTORS: u32 = 1 << 16;

/// `mach_msg_descriptor_type_t`: the out-of-line forms, whose received
/// memory the host kernel places in its own 4 KiB pages.
const OOL_DESCRIPTOR: u8 = 1;
const OOL_PORTS_DESCRIPTOR: u8 = 2;
const OOL_VOLATILE_DESCRIPTOR: u8 = 3;
const GUARDED_PORT_DESCRIPTOR: u8 = 4;
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
    place_received(name, message)
}

/// `EVFILT_MACHPORT`.
const EVFILT_MACHPORT: i16 = -8;

/// The event the host delivered for a knote: one of a port knote that
/// received a message into the guest's memory (`filt_machportprocess`:
/// `fflags` the receive's MACH_MSG_SUCCESS, `ext[0]` the message and
/// `ext[1]` its size and trailer's) has its out-of-line regions moved
/// into guest pages, as a `mach_msg` receive's are.
pub(crate) fn received_event(filter: i16, fflags: u32, ext: [u64; 2]) -> Result<()> {
    let [message, received] = ext;
    if filter != EVFILT_MACHPORT || fflags != 0 || message == 0 {
        return Ok(());
    }
    // A knote that only reports its port leaves the registered `ext`,
    // which names no message of that size.
    let Some(size) = memory::read_u32(message + 4) else {
        return Ok(());
    };
    let Some(trailer) = memory::read_u32(message + u64::from(size) + 4) else {
        return Ok(());
    };
    if u64::from(size) + u64::from(trailer) != received {
        return Ok(());
    }
    place_received("kevent", message)
}

/// Move the out-of-line regions of the message received at `message`
/// into guest pages, rewriting their descriptors.
fn place_received(name: &str, message: u64) -> Result<()> {
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

    /// A receive right of this process with a send right under the same
    /// name, destroyed when dropped.
    struct Port(u32);

    impl Port {
        fn new() -> Self {
            let task = crate::hosted::host::task();
            let mut name = 0;
            // SAFETY: new rights of this task under a name it returns.
            unsafe {
                assert_eq!(
                    darwin::mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &mut name),
                    0
                );
                assert_eq!(
                    darwin::mach_port_insert_right(task, name, name, MACH_MSG_TYPE_MAKE_SEND),
                    0
                );
            }
            Self(name)
        }
    }

    impl Drop for Port {
        fn drop(&mut self) {
            // SAFETY: the rights this value made.
            unsafe { darwin::mach_port_destruct(crate::hosted::host::task(), self.0, -1, 0) };
        }
    }

    const MACH_MSG_TYPE_COPY_SEND: u32 = 19;
    const VIRTUAL_COPY: u8 = 1;
    const MESSAGE_BYTES: usize = 24 + 4 + 16;

    /// A complex message to `port` carrying one out-of-line region.
    fn ool_message(port: u32, region: u64, bytes: u32, deallocate: bool) -> Vec<u8> {
        let mut message = Vec::new();
        for word in [
            MACH_MSGH_BITS_COMPLEX | MACH_MSG_TYPE_COPY_SEND,
            MESSAGE_BYTES as u32,
            port,
            0,
            0,
            0x1234,
            1,
        ] {
            message.extend(word.to_le_bytes());
        }
        message.extend(region.to_le_bytes());
        message.extend([u8::from(deallocate), VIRTUAL_COPY, 0, OOL_DESCRIPTOR]);
        message.extend(bytes.to_le_bytes());
        // Room for the received trailer.
        message.resize(MESSAGE_BYTES + 64, 0);
        message
    }

    fn host_send(message: &mut [u8], options: i32) -> u64 {
        // SAFETY: a message buffer of this test.
        u64::from(unsafe {
            darwin::mach_msg(
                message.as_mut_ptr(),
                options,
                MESSAGE_BYTES as u32,
                0,
                0,
                0,
                0,
            )
        } as u32)
    }

    fn host_receive(port: u32, buffer: &mut [u8]) {
        // SAFETY: a receive into this test's buffer.
        let status = unsafe {
            darwin::mach_msg(
                buffer.as_mut_ptr(),
                darwin::MACH_RCV_MSG,
                0,
                buffer.len() as u32,
                port,
                0,
                0,
            )
        };
        assert_eq!(status, 0);
    }

    fn mapped_bytes(start: u64, end: u64) -> u64 {
        memory::mapped_runs(start, end)
            .iter()
            .map(|(start, end)| end - start)
            .sum()
    }

    #[test]
    fn a_sent_region_goes_with_its_whole_guest_pages() {
        let port = Port::new();
        let block = memory::allocate(0, 3 * PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        let page = block + PAGE_BYTES;
        let region = page + 0x1010;
        assert!(memory::write(region, b"sent"));
        let mut message = ool_message(port.0, region, 0x100, true);
        let buffer = message.as_mut_ptr() as u64;
        let mut arguments = [buffer, SEND, 0, 0, 0, 0, 0, 0];
        let outgoing = Outgoing::read("mach_msg_trap", &arguments).unwrap();
        assert_eq!(
            outgoing.partial,
            [Deallocated {
                guest: (page, page + PAGE_BYTES),
                host: (page + 0x1000, page + 0x2000),
            }]
        );
        let status = host_send(&mut message, darwin::MACH_SEND_MSG);
        assert_eq!(status, 0);
        // The host took one host page; the rest of the guest page goes too,
        // and nothing else. (Freed pages are not checked: another test may
        // map them at once.)
        let mut released = Vec::new();
        outgoing
            .sent("mach_msg_trap", status, |start, size| {
                released.push((start, size))
            })
            .unwrap();
        assert_eq!(released, [(page, 0x1000), (page + 0x2000, 0x2000)]);
        assert!(memory::mapped(block) && memory::mapped(block + 2 * PAGE_BYTES));
        // The receiver finds the region in guest pages of its own.
        let mut received_message = vec![0u8; MESSAGE_BYTES + 64];
        host_receive(port.0, &mut received_message);
        let address = received_message.as_mut_ptr() as u64;
        arguments = [address, RECEIVE, 0, 0, 0, 0, 0, 0];
        received("mach_msg_trap", &arguments).unwrap();
        // (The freed page may hold it again.)
        let moved = memory::read_u64(address + 28).unwrap();
        assert_eq!(memory::read(moved, 4).unwrap(), b"sent");
        assert_eq!(
            mapped_bytes(moved & !PAGE_MASK, (moved & !PAGE_MASK) + PAGE_BYTES),
            PAGE_BYTES
        );
        memory::deallocate(moved & !PAGE_MASK, PAGE_BYTES).unwrap();
        memory::deallocate(block, PAGE_BYTES).unwrap();
        memory::deallocate(block + 2 * PAGE_BYTES, PAGE_BYTES).unwrap();
    }

    #[test]
    fn a_guest_page_the_host_shares_keeps_the_hosts_pages() {
        unsafe extern "C" {
            fn mach_vm_allocate(task: u32, address: *mut u64, size: u64, flags: i32) -> i32;
        }
        /// `VM_FLAGS_FIXED` with a test-private tag, which no other
        /// mapping joins.
        const HOST_FLAGS: i32 = 254 << 24;
        let port = Port::new();
        let page = memory::allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        // The host's own allocation in the second half of the guest page.
        let mut host = page + 0x2000;
        memory::deallocate(host, 0x2000).unwrap();
        // SAFETY: the host pages this test just released.
        let status =
            unsafe { mach_vm_allocate(crate::hosted::host::task(), &mut host, 0x2000, HOST_FLAGS) };
        assert_eq!(status, 0);
        assert!(memory::write(host, b"host"));
        let region = page + 0x10;
        let mut message = ool_message(port.0, region, 0x20, true);
        let arguments = [message.as_mut_ptr() as u64, SEND, 0, 0, 0, 0, 0, 0];
        let outgoing = Outgoing::read("mach_msg_trap", &arguments).unwrap();
        assert!(outgoing.partial.is_empty());
        let status = host_send(&mut message, darwin::MACH_SEND_MSG);
        assert_eq!(status, 0);
        let mut released = Vec::new();
        outgoing
            .sent("mach_msg_trap", status, |start, size| {
                released.push((start, size))
            })
            .unwrap();
        assert!(released.is_empty());
        assert_eq!(memory::read(host, 4).unwrap(), b"host");
        memory::deallocate(page + 0x1000, 0x1000).unwrap();
        memory::deallocate(host, 0x2000).unwrap();
    }

    #[test]
    fn traced_sends_name_their_descriptors() {
        let mut message = ool_message(0x1303, 0x4000_0010, 0x20, true);
        let arguments = [message.as_mut_ptr() as u64, SEND, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            describe_send("mach_msg_trap", &arguments).unwrap(),
            "message 4660 (44 bytes, bits 0x80000013) to 0x1303, reply 0x0, voucher 0x0: \
             out-of-line 0x20 bytes at 0x40000010 (copy 1, deallocate 1)"
        );
        let mut descriptors = vec![0u8; 12];
        descriptors[..4].copy_from_slice(&0x707u32.to_le_bytes());
        descriptors[10] = 17;
        let mut guarded = vec![0u8; 16];
        guarded[8..10].copy_from_slice(&2u16.to_le_bytes());
        guarded[10] = 16;
        guarded[11] = GUARDED_PORT_DESCRIPTOR;
        guarded[12..].copy_from_slice(&0x903u32.to_le_bytes());
        descriptors.extend(guarded);
        assert_eq!(
            describe_descriptors(&descriptors),
            "port 0x707 (17), guarded port 0x903 (16, flags 0x2, context 0x0)"
        );
        // A receive alone sends nothing.
        let arguments = [message.as_mut_ptr() as u64, RECEIVE, 0, 0, 0, 0, 0, 0];
        assert!(describe_send("mach_msg_trap", &arguments).is_none());
    }

    #[test]
    fn a_region_kept_by_the_sender_or_in_whole_pages_is_the_hosts() {
        let port = Port::new();
        let block = memory::allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        // Not deallocated: the sender keeps it.
        let message = ool_message(port.0, block + 0x10, 8, false);
        let arguments = [message.as_ptr() as u64, SEND, 0, 0, 0, 0, 0, 0];
        assert!(
            Outgoing::read("mach_msg_trap", &arguments)
                .unwrap()
                .partial
                .is_empty()
        );
        // Whole guest pages: the host's copy in takes them all.
        let message = ool_message(port.0, block, PAGE_BYTES as u32, true);
        let arguments = [message.as_ptr() as u64, SEND, 0, 0, 0, 0, 0, 0];
        assert!(
            Outgoing::read("mach_msg_trap", &arguments)
                .unwrap()
                .partial
                .is_empty()
        );
        // A simple message, or no send, has nothing to release.
        let mut simple = ool_message(port.0, block, 8, true);
        simple[3] = 0;
        let arguments = [simple.as_ptr() as u64, SEND, 0, 0, 0, 0, 0, 0];
        assert!(Outgoing::read("mach_msg_trap", &arguments).is_none());
        let arguments = [message.as_ptr() as u64, RECEIVE, 0, 0, 0, 0, 0, 0];
        assert!(Outgoing::read("mach_msg_trap", &arguments).is_none());
        memory::deallocate(block, PAGE_BYTES).unwrap();
    }

    #[test]
    fn a_failed_send_returns_its_regions_in_guest_pages() {
        const MACH_SEND_TIMEOUT: i32 = 0x10;
        const MACH_SEND_TIMED_OUT: u64 = 0x1000_0004;
        let port = Port::new();
        // Fill the port's queue (MACH_PORT_QLIMIT_DEFAULT).
        for _ in 0..5 {
            let mut message = ool_message(port.0, 0, 0, false);
            message[3] = 0;
            message[4..8].copy_from_slice(&24u32.to_le_bytes());
            // SAFETY: a message buffer of this test.
            let status = unsafe {
                darwin::mach_msg(message.as_mut_ptr(), darwin::MACH_SEND_MSG, 24, 0, 0, 0, 0)
            };
            assert_eq!(status, 0);
        }
        let block = memory::allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        let region = block + 0x2010;
        assert!(memory::write(region, b"back"));
        let mut message = ool_message(port.0, region, 0x20, true);
        let buffer = message.as_mut_ptr() as u64;
        let arguments = [buffer, SEND, 0, 0, 0, 0, 0, 0];
        let outgoing = Outgoing::read("mach_msg_trap", &arguments).unwrap();
        let status = host_send(&mut message, darwin::MACH_SEND_MSG | MACH_SEND_TIMEOUT);
        assert_eq!(status, MACH_SEND_TIMED_OUT);
        let mut released = Vec::new();
        outgoing
            .sent("mach_msg_trap", status, |start, size| {
                released.push((start, size))
            })
            .unwrap();
        // The copy in took the sender's guest page; the pseudo-receive's copy
        // is in a guest page of its own.
        assert_eq!(released, [(block, 0x2000), (block + 0x3000, 0x1000)]);
        let returned = memory::read_u64(buffer + 28).unwrap();
        assert_eq!(memory::read(returned, 4).unwrap(), b"back");
        assert_eq!(
            mapped_bytes(returned & !PAGE_MASK, (returned & !PAGE_MASK) + PAGE_BYTES),
            PAGE_BYTES
        );
        memory::deallocate(returned & !PAGE_MASK, PAGE_BYTES).unwrap();
    }

    #[test]
    fn a_port_knotes_received_message_has_its_regions_in_guest_pages() {
        const EVFILT_MACHPORT: i16 = -8;
        let port = Port::new();
        let block = memory::allocate(0, PAGE_BYTES, true, Protection::READ_WRITE).unwrap();
        assert!(memory::write(block + 0x10, b"kevent"));
        let mut message = ool_message(port.0, block + 0x10, 6, false);
        assert_eq!(host_send(&mut message, darwin::MACH_SEND_MSG), 0);
        let mut buffer = vec![0u8; MESSAGE_BYTES + 64];
        let event = |ext: [u64; 2], fflags: u32| libc::kevent64_s {
            ident: u64::from(port.0),
            filter: EVFILT_MACHPORT,
            flags: libc::EV_ADD | libc::EV_ENABLE,
            fflags,
            data: 0,
            udata: 0,
            ext,
        };
        // A knote that only reports its port names no message.
        assert_eq!(received_event(EVFILT_MACHPORT, 0, [0, 0]).ok(), Some(()));
        // SAFETY: a private kqueue and this test's buffers.
        let (queue, out) = unsafe {
            let queue = libc::kqueue();
            assert!(queue >= 0);
            let change = event(
                [buffer.as_mut_ptr() as u64, buffer.len() as u64],
                darwin::MACH_RCV_MSG as u32,
            );
            let mut out = event([0, 0], 0);
            let timeout = libc::timespec {
                tv_sec: 5,
                tv_nsec: 0,
            };
            assert_eq!(
                libc::kevent64(queue, &change, 1, &mut out, 1, 0, &timeout),
                1
            );
            (queue, out)
        };
        assert_eq!(out.fflags, 0, "MACH_MSG_SUCCESS");
        received_event(out.filter, out.fflags, out.ext).unwrap();
        let moved = u64::from_le_bytes(buffer[28..36].try_into().unwrap());
        assert_ne!(moved & !PAGE_MASK, block);
        assert_eq!(memory::read(moved, 6).unwrap(), b"kevent");
        assert_eq!(
            mapped_bytes(moved & !PAGE_MASK, (moved & !PAGE_MASK) + PAGE_BYTES),
            PAGE_BYTES
        );
        // SAFETY: the kqueue this test opened.
        unsafe { libc::close(queue) };
        memory::deallocate(moved & !PAGE_MASK, PAGE_BYTES).unwrap();
        memory::deallocate(block, PAGE_BYTES).unwrap();
    }
}
