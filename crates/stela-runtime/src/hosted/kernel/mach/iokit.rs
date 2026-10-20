//! The IOKit seam (`iokit`, `osfmk/device/device.defs`): requests to IOKit
//! objects a device family of the hosted kernel provides, in place of the
//! host's. The family registers one [`IokitService`] for the process.
//! Without one, or for an object it neither owns nor claims, the request
//! is forwarded to the host's IOKit unchanged.
//!
//! The message dispatcher ([`super::message`]) routes to the service:
//! - every message to a port the service owns (an object, iterator,
//!   connection or notification port it made), which the service must
//!   answer, as IOKit answers a number it does not serve (`MIG_BAD_ID`);
//! - an `iokit` request to the IOKit main port (`host_get_io_main`) that
//!   the service claims from the request as sent.
//!
//! A routed request is then copied in as the kernel's MIG server receives
//! it ([`copy_in`]), served, and answered to its reply port as the
//! kernel-object routines are; its moved destination and voucher are
//! consumed, and the out-of-line regions it deallocates leave the sender.
use super::server::{Reply, release_send};
use crate::hosted::darwin::MACH_PORT_RIGHT_RECEIVE;
use crate::hosted::host;
use crate::hosted::unsupported::{self, Failure};
use crate::mach::mig;
use anyhow::Result;

/// `mach_msg_descriptor_type_t` values, and the user descriptor sizes.
const PORT_DESCRIPTOR: u8 = 0;
const OOL_DESCRIPTOR: u8 = 1;
const OOL_VOLATILE_DESCRIPTOR: u8 = 3;
const PORT_DESCRIPTOR_BYTES: usize = 12;
const DESCRIPTOR_BYTES: usize = 16;
/// The received disposition of a carried receive right.
const PORT_RECEIVE: u8 = 16;
/// `MACH_SEND_INVALID_TYPE`.
const MACH_SEND_INVALID_TYPE: u32 = 0x1000_000f;

/// A request routed to the service.
#[expect(
    dead_code,
    reason = "the device family that registers a service reads it"
)]
pub(crate) struct IokitRequest<'a> {
    /// Its destination's name in this space.
    pub(crate) port: u32,
    /// Whether the destination is the IOKit main port.
    pub(crate) main: bool,
    pub(crate) id: u32,
    /// Its `device.defs` routine, `None` for a number with no routine.
    pub(crate) routine: Option<&'static mig::Routine>,
    /// Whether it is complex (`MACH_MSGH_BITS_COMPLEX`).
    pub(crate) complex: bool,
    /// The bytes after its header: when complex, the descriptor count and
    /// descriptors, then the NDR record and arguments.
    pub(crate) body: &'a [u8],
    /// The guest's trap PC, for reports.
    pub(crate) pc: u64,
}

/// A device family's IOKit objects.
pub(crate) trait IokitService: Send + Sync {
    /// Whether `port` is one of the service's own ports.
    fn owns(&self, port: u32) -> bool;

    /// Whether the service answers this request to the main port (an
    /// accelerator-family matching, say), judged on the request as sent:
    /// its port descriptors are still the sender's names and dispositions,
    /// and declining leaves the request to the host.
    fn claims(&self, request: &IokitRequest) -> bool;

    /// Answer a request the service owns or claimed, copied in: each port
    /// descriptor holds a right of this space the service now owns, with
    /// the received disposition (`MACH_MSG_TYPE_PORT_SEND` 17,
    /// `_SEND_ONCE` 18 or `_RECEIVE` 16), whatever the outcome;
    /// out-of-line memory is still at the sender's guest address. An
    /// error is reported as an unsupported routine and answered with its
    /// failure. [`Reply::Forward`] is not an answer.
    fn serve(&self, request: &IokitRequest) -> Result<Reply>;
}

/// Whether `port` names this space's IOKit main port, which
/// `host_get_io_main` gives on the host port `host` (its extra reference
/// is dropped again).
pub(super) fn main_port(host: u32, port: u32) -> bool {
    unsafe extern "C" {
        fn host_get_io_main(host: u32, main: *mut u32) -> i32;
    }
    let mut main = 0u32;
    // SAFETY: an out-parameter for one port name.
    if unsafe { host_get_io_main(host, &mut main) } != 0 {
        return false;
    }
    release_send(main);
    main == port
}

/// A request body as copied in.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CopiedIn {
    pub(super) body: Vec<u8>,
    /// The out-of-line regions the kernel takes from the sender
    /// (`deallocate`): address and size.
    pub(super) taken: Vec<(u64, u64)>,
}

/// `ipc_kmsg_copyin_body` of a complex request body: each port descriptor's
/// right carried into this space by `carry` (its name and disposition
/// become the received right's), each out-of-line region left in place
/// and, when the sender deallocates it, listed as taken. The failure of a
/// send whose copy in fails, with the rights carried so far released.
/// Out-of-line port arrays and guarded port descriptors are refused.
pub(super) fn copy_in(
    routine: &str,
    body: &[u8],
    mut carry: impl FnMut(u32, u8) -> Result<std::result::Result<(u32, u8), u32>>,
) -> Result<std::result::Result<CopiedIn, u32>> {
    let mut copied = CopiedIn {
        body: body.to_vec(),
        taken: Vec::new(),
    };
    let mut carried: Vec<(u32, u8)> = Vec::new();
    let release_all = |carried: &[(u32, u8)]| {
        for &(name, received) in carried {
            release(name, received);
        }
    };
    let count = word(body, 0).unwrap_or(0);
    let mut at = 4;
    for _ in 0..count {
        let Some(&kind) = body.get(at + 11) else {
            break;
        };
        match kind {
            PORT_DESCRIPTOR => {
                let (Some(name), Some(&disposition)) = (word(body, at), body.get(at + 10)) else {
                    break;
                };
                match carry(name, disposition) {
                    Ok(Ok((name, received))) => {
                        carried.push((name, received));
                        copied.body[at..at + 4].copy_from_slice(&name.to_le_bytes());
                        copied.body[at + 10] = received;
                    }
                    Ok(Err(status)) => {
                        release_all(&carried);
                        return Ok(Err(status));
                    }
                    Err(error) => {
                        release_all(&carried);
                        return Err(error);
                    }
                }
                at += PORT_DESCRIPTOR_BYTES;
            }
            OOL_DESCRIPTOR | OOL_VOLATILE_DESCRIPTOR => {
                let (Some(address), Some(&deallocate), Some(size)) = (
                    body.get(at..at + 8)
                        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap())),
                    body.get(at + 8),
                    word(body, at + 12),
                ) else {
                    break;
                };
                if deallocate != 0 && address != 0 && size != 0 {
                    copied.taken.push((address, u64::from(size)));
                }
                at += DESCRIPTOR_BYTES;
            }
            _ => {
                release_all(&carried);
                unsupported::refuse!(
                    Failure::Kern(MACH_SEND_INVALID_TYPE),
                    "{routine}: an IOKit request carrying descriptor type {kind}"
                );
            }
        }
    }
    Ok(Ok(copied))
}

/// Release a carried right, as the kernel destroys a request it took.
fn release(name: u32, received: u8) {
    if received == PORT_RECEIVE {
        unsafe extern "C" {
            fn mach_port_mod_refs(task: u32, name: u32, right: u32, delta: i32) -> i32;
        }
        // SAFETY: the receive right this space was given.
        unsafe { mach_port_mod_refs(host::task(), name, MACH_PORT_RIGHT_RECEIVE, -1) };
    } else {
        release_send(name);
    }
}

fn word(body: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(body.get(at..at + 4)?.try_into().ok()?))
}

/// Whether `id`'s subsystem is `iokit`.
pub(super) fn iokit_message(id: u32) -> bool {
    mig::subsystem(id).is_some_and(|subsystem| subsystem.name == "iokit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::darwin::mach_port_allocate;

    unsafe extern "C" {
        fn mach_host_self() -> u32;
        fn host_get_io_main(host: u32, main: *mut u32) -> i32;
        fn mach_port_type(task: u32, name: u32, kind: *mut u32) -> i32;
    }

    /// A complex body: the descriptor count, the descriptors, then `tail`.
    fn body(descriptors: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
        let mut bytes = (descriptors.len() as u32).to_le_bytes().to_vec();
        for descriptor in descriptors {
            bytes.extend(descriptor);
        }
        bytes.extend(tail);
        bytes
    }

    fn port(name: u32, disposition: u8) -> Vec<u8> {
        let mut bytes = name.to_le_bytes().to_vec();
        bytes.extend([0; 6]);
        bytes.extend([disposition, PORT_DESCRIPTOR]);
        bytes
    }

    fn memory(address: u64, size: u32, deallocate: bool) -> Vec<u8> {
        let mut bytes = address.to_le_bytes().to_vec();
        bytes.extend([u8::from(deallocate), 1, 0, OOL_DESCRIPTOR]);
        bytes.extend(size.to_le_bytes());
        bytes
    }

    fn receive_right() -> u32 {
        let mut name = 0;
        // SAFETY: an out-parameter for one port name.
        let status =
            unsafe { mach_port_allocate(host::task(), MACH_PORT_RIGHT_RECEIVE, &mut name) };
        assert_eq!(status, 0);
        name
    }

    #[test]
    fn requests_are_copied_in_as_the_kernels_mig_server_receives_them() {
        let sent = body(
            &[
                port(0x1103, 20),
                memory(0x4000_0010, 0x20, true),
                memory(0x5000_0000, 8, false),
            ],
            &[1, 2, 3, 4],
        );
        let mut carried = Vec::new();
        let copied = copy_in(
            "io_service_add_notification_bin_64",
            &sent,
            |name, disposition| {
                carried.push((name, disposition));
                Ok(Ok((0x2203, 17)))
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(carried, [(0x1103, 20)]);
        assert_eq!(
            copied,
            CopiedIn {
                body: body(
                    &[
                        port(0x2203, 17),
                        memory(0x4000_0010, 0x20, true),
                        memory(0x5000_0000, 8, false),
                    ],
                    &[1, 2, 3, 4],
                ),
                taken: vec![(0x4000_0010, 0x20)],
            }
        );
    }

    #[test]
    fn a_failed_copy_in_releases_the_rights_it_carried() {
        let first = receive_right();
        let sent = body(&[port(0x1103, 20), port(0x1203, 20)], &[]);
        let mut calls = 0;
        let outcome = copy_in("io_service_open_extended", &sent, |_, _| {
            calls += 1;
            Ok(if calls == 1 {
                Ok((first, PORT_RECEIVE))
            } else {
                Err(0x1000_0010)
            })
        })
        .unwrap();
        assert_eq!(outcome, Err(0x1000_0010));
        // The carried receive right was destroyed with the request.
        let mut kind = 0u32;
        // SAFETY: an out-parameter for the name's type.
        assert_ne!(unsafe { mach_port_type(host::task(), first, &mut kind) }, 0);
    }

    #[test]
    fn port_arrays_in_iokit_requests_are_refused() {
        let mut array = memory(0x4000_0000, 1, false);
        array[11] = 2;
        let sent = body(&[array], &[]);
        assert!(copy_in("io_connect_method", &sent, |_, _| unreachable!()).is_err());
    }

    #[test]
    fn the_main_port_is_host_get_io_mains_name() {
        // SAFETY: this task's host port name.
        let host = unsafe { mach_host_self() };
        let other = receive_right();
        assert!(!main_port(host, other));
        let mut main = 0;
        // SAFETY: an out-parameter for one port name.
        assert_eq!(unsafe { host_get_io_main(host, &mut main) }, 0);
        assert!(main_port(host, main));
        release_send(main);
        release(other, PORT_RECEIVE);
    }
}
