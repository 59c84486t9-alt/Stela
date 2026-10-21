//! KernelUser exception RPC lifetime (`kern/ipc_mig.c`). Ordinary aborts
//! retry, but inactive threads retire their reply receive right. The host
//! libsyscall wrapper must expose interruptions rather than retry them
//! internally, or task exit cannot finish interrupting this host thread.
use super::*;
use crate::hosted::darwin::{mach_msg, mach_port_allocate};
use crate::hosted::host;

/// Library-only restart controls (`mach/message.h`): stripped by the
/// wrapper before the trap. These do not change the kernel message ABI.
const MACH_SEND_INTERRUPT: i32 = 0x40;
const MACH_RCV_INTERRUPT: i32 = 0x400;
const MACH_SEND_INTERRUPTED: u32 = 0x1000_0007;
const MACH_SEND_TIMED_OUT: u32 = 0x1000_0004;
const MACH_RCV_INTERRUPTED: u32 = 0x1000_4005;
const MACH_RCV_BODY_ERROR: u32 = 0x1000_400c;
const MACH_MSG_MASK: u32 = 0x3e00;
const RECEIVE_ERROR: u32 = 0x1000_4000;
const ERROR_SUBSYSTEM_MASK: u32 = 0xffff_c000;
const MAKE_SEND_ONCE: u32 = 21;
const MOVE_SEND_RIGHT: u32 = 17;
const MOVE_SEND_ONCE: u32 = 18;
const MACH_PORT_RIGHT_RECEIVE: u32 = 1;

unsafe extern "C" {
    fn mach_port_mod_refs(task: u32, name: u32, right: u32, delta: i32) -> i32;
    fn mach_msg_destroy(message: *mut u32);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// The original request, or native pseudo-copyout after interruption,
    /// still owns its moved body/header references.
    Send,
    /// Send committed. Only the reply receive right is ours.
    Receive,
    /// Native copyout published the reply, including any unwanted rights.
    Reply,
    /// An unexpected partially consumed send has no qualified cleanup.
    Unqualified,
}

struct Exchange {
    message: Vec<u8>,
    size: u32,
    reply: u32,
    phase: Phase,
}

impl Exchange {
    /// Take ownership of the moved rights in a runtime-generated body,
    /// before allocating its reply resource. No guest bytes are parsed.
    fn new(destination: u32, id: i32, complex: bool, body: &[u8]) -> Result<Self> {
        let size = 24 + body.len();
        let mut exchange = Self {
            message: vec![0; size.max(REPLY_BYTES)],
            size: size.try_into()?,
            reply: 0,
            phase: Phase::Send,
        };
        let bits =
            COPY_SEND | MAKE_SEND_ONCE << 8 | if complex { MACH_MSGH_BITS_COMPLEX } else { 0 };
        for (at, word) in [
            (0, bits),
            (4, exchange.size),
            (8, destination),
            (20, id as u32),
        ] {
            exchange.message[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        exchange.message[24..size].copy_from_slice(body);
        // SAFETY: a new receive right in this actual space into an out name.
        let code = unsafe {
            mach_port_allocate(
                host::task(),
                MACH_PORT_RIGHT_RECEIVE,
                &raw mut exchange.reply,
            )
        };
        if code != 0 {
            bail!("an exception reply port could not be made: {code:#x}");
        }
        exchange.message[12..16].copy_from_slice(&exchange.reply.to_le_bytes());
        Ok(exchange)
    }

    fn step(&mut self) -> u32 {
        let sending = self.phase == Phase::Send;
        let options = darwin::MACH_RCV_MSG
            | MACH_SEND_INTERRUPT
            | MACH_RCV_INTERRUPT
            | if sending { darwin::MACH_SEND_MSG } else { 0 };
        // SAFETY: the owned buffer holds both the outgoing message and
        // largest reply; the reply receive right belongs to this frame.
        unsafe {
            mach_msg(
                self.message.as_mut_ptr(),
                options,
                if sending { self.size } else { 0 },
                self.message.len() as u32,
                self.reply,
                0,
                0,
            ) as u32
        }
    }

    /// Whether the interrupted operation needs a retry. Receive errors
    /// establish that send committed, so they must never resend a request.
    fn returned(&mut self, status: u32) -> Result<bool> {
        if status == darwin::KERN_SUCCESS {
            self.phase = Phase::Reply;
        } else if status & ERROR_SUBSYSTEM_MASK == RECEIVE_ERROR {
            self.phase = if status & !MACH_MSG_MASK == MACH_RCV_BODY_ERROR {
                // Partial native body copyout is destructible; unreceived
                // descriptors were nulled by ipc_kmsg_copyout_descriptors.
                Phase::Reply
            } else {
                Phase::Receive
            };
        } else if !matches!(
            status,
            MACH_SEND_INTERRUPTED | MACH_SEND_TIMED_OUT | darwin::MACH_SEND_INVALID_DEST
        ) {
            // libsyscall's mach_msg_server_is_recoverable_send_error
            // explicitly excludes other failures: the kernel may already
            // have destroyed a descriptor prefix. Never destroy it twice.
            self.phase = Phase::Unqualified;
            bail!(
                "exception RPC send {status:#x} has unqualified partial right consumption; \
                 refusing to destroy potentially retired references"
            );
        }
        Ok(matches!(
            status,
            MACH_SEND_INTERRUPTED | MACH_RCV_INTERRUPTED
        ))
    }

    fn run(
        mut self,
        control: Option<&control::Control>,
        id: i32,
        state: bool,
    ) -> Result<(u32, NewState)> {
        loop {
            let status = match control {
                Some(control) => control.forwarding(|| self.step()),
                None => Some(self.step()),
            };
            let Some(status) = status else {
                return Ok((darwin::KERN_SUCCESS, None));
            };
            if !self.returned(status)? {
                return Ok(if status == darwin::KERN_SUCCESS {
                    parse_reply(id, &self.message, state)
                } else {
                    (status, None)
                });
            }
            // A new forwarding admission checks liveness atomically
            // against close/terminate and publishes each retry.
        }
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if matches!(self.phase, Phase::Send | Phase::Reply) {
            if self.phase == Phase::Send {
                // Pseudo-copyout may turn MAKE_SEND_ONCE into an owned
                // MOVE_SEND_ONCE. mach_msg_destroy ignores the local field
                // (libsyscall's mach_msg_server_consume_unsent_message).
                let bits = u32::from_le_bytes(self.message[..4].try_into().unwrap());
                if matches!((bits >> 8) & 0xff, MOVE_SEND_RIGHT | MOVE_SEND_ONCE) {
                    let local = u32::from_le_bytes(self.message[12..16].try_into().unwrap());
                    super::super::server::release_send(local);
                }
            }
            // SAFETY: only our generated, wholly unsent message (including
            // recoverable pseudo-copyout), or a native copied-out reply.
            unsafe { mach_msg_destroy(self.message.as_mut_ptr().cast()) };
        }
        if self.reply != 0 {
            // SAFETY: this exact receive right was allocated above and is
            // never transferred. Destroying it retires queued replies too.
            unsafe { mach_port_mod_refs(host::task(), self.reply, MACH_PORT_RIGHT_RECEIVE, -1) };
        }
    }
}

/// As kernel_mach_msg_rpc_common: interruptions of an active thread
/// retry, but task/thread termination discards the private reply port and
/// returns no state to apply. This never reports a guest-visible success
/// for an active thread's interrupted RPC.
pub(super) fn call(
    control: Option<&control::Control>,
    destination: u32,
    id: i32,
    complex: bool,
    body: &[u8],
    state: bool,
) -> Result<(u32, NewState)> {
    Exchange::new(destination, id, complex, body)?.run(control, id, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    const MACH_RCV_TIMEOUT: i32 = 0x100;
    const MACH_RCV_TIMED_OUT: u32 = 0x1000_4003;
    const MACH_PORT_TYPE_DEAD_NAME: u32 = 0x10_0000;
    const ID: i32 = 2405;

    unsafe extern "C" {
        fn mach_port_get_refs(task: u32, name: u32, right: u32, refs: *mut u32) -> i32;
        fn mach_port_type(task: u32, name: u32, kind: *mut u32) -> i32;
    }

    struct Port(u32);

    impl Port {
        fn new() -> Self {
            let mut name = 0;
            // SAFETY: actual receive right and one send uref in our space.
            unsafe {
                assert_eq!(
                    mach_port_allocate(host::task(), MACH_PORT_RIGHT_RECEIVE, &raw mut name),
                    0
                );
                assert_eq!(
                    darwin::mach_port_insert_right(
                        host::task(),
                        name,
                        name,
                        darwin::MACH_MSG_TYPE_MAKE_SEND
                    ),
                    0
                );
            }
            Self(name)
        }

        fn refs(&self) -> u32 {
            let mut refs = 0;
            // SAFETY: actual owned receive name, send right selector zero.
            unsafe {
                assert_eq!(
                    mach_port_get_refs(host::task(), self.0, 0, &raw mut refs),
                    0
                );
            }
            refs
        }

        fn receive(&self, timeout: u32) -> (u32, Vec<u8>) {
            let mut message = vec![0; REPLY_BYTES];
            // SAFETY: owned buffer and receive right.
            let code = unsafe {
                mach_msg(
                    message.as_mut_ptr(),
                    darwin::MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                    0,
                    message.len() as u32,
                    self.0,
                    timeout,
                    0,
                ) as u32
            };
            (code, message)
        }
    }

    impl Drop for Port {
        fn drop(&mut self) {
            super::super::super::server::release_send(self.0);
            // SAFETY: the receive right this helper allocated.
            unsafe { mach_port_mod_refs(host::task(), self.0, MACH_PORT_RIGHT_RECEIVE, -1) };
        }
    }

    fn body(moved: &Port, copied: &Port) -> Vec<u8> {
        request_body(
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
            &[(moved.0, MOVE_SEND), (copied.0, COPY_SEND as u8)],
            None,
            Exception {
                kind: 1,
                codes: [0, 0],
                count: 2,
            },
            None,
        )
    }

    fn reply(request: &mut [u8], complex: Option<&Port>) {
        let destination = u32::from_le_bytes(request[8..12].try_into().unwrap());
        let mut message = if let Some(port) = complex {
            let mut message = vec![0; 40];
            message[24..28].copy_from_slice(&1u32.to_le_bytes());
            message[28..32].copy_from_slice(&port.0.to_le_bytes());
            message[38] = MOVE_SEND;
            message
        } else {
            let mut message = vec![0; 36];
            message[24..32].copy_from_slice(&NDR_RECORD);
            message
        };
        let bits = MOVE_SEND_ONCE
            | if complex.is_some() {
                MACH_MSGH_BITS_COMPLEX
            } else {
                0
            };
        let size = message.len() as u32;
        for (at, value) in [
            (0, bits),
            (4, size),
            (8, destination),
            (20, (ID + 100) as u32),
        ] {
            message[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        // SAFETY: initialized native message consumes the received reply
        // right and, for a malformed complex reply, the moved descriptor.
        unsafe {
            assert_eq!(
                mach_msg(
                    message.as_mut_ptr(),
                    darwin::MACH_SEND_MSG,
                    size,
                    0,
                    0,
                    0,
                    0
                ),
                0
            );
        }
        request[8..12].fill(0);
        // SAFETY: all remaining rights belong to this received request.
        unsafe { mach_msg_destroy(request.as_mut_ptr().cast()) };
    }

    #[test]
    fn interrupted_receives_commit_send_and_never_resend() {
        let port = Port::new();
        let mut exchange = Exchange::new(port.0, ID, false, &[]).unwrap();
        assert!(exchange.returned(MACH_SEND_INTERRUPTED).unwrap());
        assert_eq!(exchange.phase, Phase::Send);
        assert!(exchange.returned(MACH_RCV_INTERRUPTED).unwrap());
        assert_eq!(exchange.phase, Phase::Receive);
        assert!(exchange.returned(MACH_RCV_INTERRUPTED).unwrap());
        assert_eq!(exchange.phase, Phase::Receive);
        assert!(!exchange.returned(MACH_RCV_TIMED_OUT).unwrap());
        assert_eq!(exchange.phase, Phase::Receive);
        // Pure transition test did not perform a send; no moved body.
    }

    #[test]
    fn cancellation_before_send_retires_owned_moves_and_keeps_copies() {
        let control = control::Control::default();
        control.close();
        let destination = Port::new();
        let moved = Port::new();
        let copied = Port::new();
        assert_eq!(
            call(
                Some(&control),
                destination.0,
                ID,
                true,
                &body(&moved, &copied),
                false
            )
            .unwrap(),
            (0, None)
        );
        assert_eq!(moved.refs(), 0);
        assert_eq!(copied.refs(), 1);
        assert_eq!(destination.refs(), 1);
        assert_eq!(destination.receive(0).0, MACH_RCV_TIMED_OUT);
    }

    #[test]
    fn failed_send_retires_only_the_unsent_owned_references() {
        let moved = Port::new();
        let copied = Port::new();
        assert_eq!(
            call(None, 0, ID, true, &body(&moved, &copied), false).unwrap(),
            (darwin::MACH_SEND_INVALID_DEST, None)
        );
        assert_eq!(moved.refs(), 0);
        assert_eq!(copied.refs(), 1);
    }

    #[test]
    fn a_partially_consumed_native_send_is_not_destroyed_twice() {
        let destination = Port::new();
        let moved = Port::new();
        let body = request_body(
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
            &[(moved.0, MOVE_SEND), (0xdead_beef, MOVE_SEND)],
            None,
            Exception {
                kind: 1,
                codes: [0, 0],
                count: 2,
            },
            None,
        );
        let error = call(None, destination.0, ID, true, &body, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unqualified partial right consumption")
        );
        // The native copyin consumed the MOVE prefix before the invalid
        // second descriptor; retirement never restores or repeats it.
        assert_eq!(moved.refs(), 0);
        assert_eq!(destination.refs(), 1);
        assert_eq!(destination.receive(0).0, MACH_RCV_TIMED_OUT);
    }

    type Running = (
        u32,
        mpsc::Receiver<Result<(u32, NewState)>>,
        std::thread::JoinHandle<()>,
    );

    fn start(
        control: Arc<control::Control>,
        destination: u32,
        body: Vec<u8>,
        complex: bool,
    ) -> Running {
        let (prepared, ready) = mpsc::channel();
        let (sender, receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let exchange = Exchange::new(destination, ID, complex, &body).unwrap();
            let port = crate::hosted::forward::mach(darwin::THREAD_SELF_TRAP, &[]).rax as u32;
            prepared.send(port).unwrap();
            let result = exchange.run(Some(&control), ID, false);
            super::super::super::server::release_send(port);
            sender.send(result).unwrap();
        });
        (
            ready.recv_timeout(Duration::from_secs(5)).unwrap(),
            receiver,
            thread,
        )
    }

    #[test]
    fn ordinary_abort_keeps_the_same_rpc_and_complex_replies_retire_rights() {
        let destination = Port::new();
        let moved = Port::new();
        let copied = Port::new();
        let unexpected = Port::new();
        let control = Arc::new(control::Control::default());
        let (port, done, thread) =
            start(control.clone(), destination.0, body(&moved, &copied), true);
        let (status, mut request) = destination.receive(5000);
        assert_eq!(status, 0);
        assert_eq!(control.abort(port, false), 0);
        assert!(done.recv_timeout(Duration::from_millis(20)).is_err());
        assert_eq!(destination.receive(0).0, MACH_RCV_TIMED_OUT);
        reply(&mut request, Some(&unexpected));
        assert_eq!(
            done.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
            (MIG_TYPE_ERROR, None)
        );
        thread.join().unwrap();
        assert_eq!(moved.refs(), 0);
        assert_eq!(copied.refs(), 1);
        assert_eq!(unexpected.refs(), 0);
        assert_eq!(destination.refs(), 1);
    }

    #[test]
    fn task_close_and_thread_termination_retire_the_actual_reply_port() {
        for terminate in [false, true] {
            let destination = Port::new();
            let control = Arc::new(control::Control::default());
            let (port, done, thread) = start(control.clone(), destination.0, Vec::new(), false);
            let (status, mut request) = destination.receive(5000);
            assert_eq!(status, 0);
            let reply = u32::from_le_bytes(request[8..12].try_into().unwrap());
            let closer = std::thread::spawn(move || {
                if terminate {
                    assert_eq!(control.terminate(port), 0);
                } else {
                    control.close();
                    control.interrupt(port);
                }
            });
            assert_eq!(
                done.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
                (0, None)
            );
            closer.join().unwrap();
            thread.join().unwrap();
            let mut kind = 0;
            // SAFETY: the received send-once name is still ours; cancellation
            // destroyed its receive object, so it is now an actual dead name.
            unsafe {
                assert_eq!(mach_port_type(host::task(), reply, &raw mut kind), 0);
            }
            assert_eq!(kind, MACH_PORT_TYPE_DEAD_NAME);
            // SAFETY: destroys our received dead-name/send-once reference.
            unsafe { mach_msg_destroy(request.as_mut_ptr().cast()) };
            assert_eq!(destination.refs(), 1);
        }
    }

    #[test]
    fn process_close_retires_a_full_queue_send_and_pseudo_copyout_rights() {
        let destination = Port::new();
        // Fill the actual native queue without changing its limits.
        let mut filled = false;
        for _ in 0..32 {
            let mut message = [0u8; 24];
            for (at, value) in [(0, COPY_SEND), (4, 24), (8, destination.0)] {
                message[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            // SAFETY: complete simple message, immediate bounded send.
            let status = unsafe {
                mach_msg(
                    message.as_mut_ptr(),
                    darwin::MACH_SEND_MSG | darwin::MACH_SEND_TIMEOUT,
                    24,
                    0,
                    0,
                    0,
                    0,
                ) as u32
            };
            if status == MACH_SEND_TIMED_OUT {
                // SAFETY: the native recoverable pseudo-copyout owns its
                // rewritten destination reference; retire that copy.
                unsafe { mach_msg_destroy(message.as_mut_ptr().cast()) };
                filled = true;
                break;
            }
            assert_eq!(status, 0);
        }
        assert!(filled);
        let moved = Port::new();
        let copied = Port::new();
        let control = Arc::new(control::Control::default());
        let (port, done, thread) =
            start(control.clone(), destination.0, body(&moved, &copied), true);
        assert!(done.recv_timeout(Duration::from_millis(20)).is_err());
        // Exercise an ordinary interrupted send before permanent close;
        // pseudo-copyout may change names/dispositions, never identity.
        assert_eq!(control.abort(port, false), 0);
        assert!(done.recv_timeout(Duration::from_millis(20)).is_err());
        let closer = std::thread::spawn(move || {
            control.close();
            control.interrupt(port);
        });
        assert_eq!(
            done.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
            (0, None)
        );
        closer.join().unwrap();
        thread.join().unwrap();
        assert_eq!(moved.refs(), 0);
        assert_eq!(copied.refs(), 1);
        assert_eq!(destination.refs(), 1);
    }
}
