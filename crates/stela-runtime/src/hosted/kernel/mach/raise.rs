//! Delivery of a guest thread's exception to the exception ports set for
//! it (`osfmk/kern/exception.c`): `exception_triage_thread` tries the
//! thread's action, then the task's, then the host's; the host level is
//! the BSD exception-to-signal handler, which the caller's signal is.
//!
//! Each action is an RPC from the faulting thread (`exception_deliver`):
//! the `mach_exc` routine of its behavior (`mach_exc.defs`, 64-bit codes)
//! or the `exc` one (32-bit codes), sent to the action's port with a reply
//! port of this space and awaited as a host call this thread performs, so
//! that the handler's `thread_get_state` and `thread_set_state` of the
//! thread see its trap frame. A successful reply (or a dead reply port)
//! handles the exception: the thread returns to user space at its state,
//! with the reply's new state for the state behaviors. Otherwise the next
//! level is tried.
//!
//! The thread and task ports `EXCEPTION_DEFAULT` and
//! `EXCEPTION_STATE_IDENTITY` carry are the control ports with developer
//! mode on and the read ports otherwise, which the hosted kernel does not
//! yet serve; the identity-protected behaviors carry the thread's ID and a
//! task identity token. The kernel's RPC carries the thread's voucher,
//! which this one does not.
use super::super::control::{self, UserState};
use super::super::{Kernel, Pe};
use super::server::NDR_RECORD;
use crate::hosted::darwin::{self, mach_msg, mach_port_allocate};
use crate::hosted::host;
use crate::hosted::unsupported::{self, Failure, Kind};
use crate::mach::mig;
use anyhow::{Result, bail};

/// The exception routines' message IDs: `exc` (32-bit codes) and
/// `mach_exc` (64-bit codes), by behavior.
const EXC_BASE: i32 = 2401;
const MACH_EXC_BASE: i32 = 2405;
/// `exception_behavior_t` values and flags.
const EXCEPTION_DEFAULT: u32 = 1;
const EXCEPTION_STATE: u32 = 2;
const EXCEPTION_STATE_IDENTITY: u32 = 3;
const EXCEPTION_IDENTITY_PROTECTED: u32 = 4;
const EXCEPTION_STATE_IDENTITY_PROTECTED: u32 = 5;
const MACH_EXCEPTION_CODES: u32 = 0x8000_0000;
const MACH_EXCEPTION_BACKTRACE_PREFERRED: u32 = 0x2000_0000;
const MACH_EXCEPTION_MASK: u32 = 0xe000_0000;
/// `mach_msg` values.
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
const COPY_SEND: u32 = 19;
const MOVE_SEND: u8 = 17;
const MAKE_SEND_ONCE: u32 = 21;
const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
const PORT_DESCRIPTOR: u8 = 0;
const MACH_NOTIFY_SEND_ONCE: i32 = 0o107;
/// MIG's reply checks (`mig_errors.h`).
const MIG_TYPE_ERROR: u32 = (-300i32) as u32;
const MIG_REPLY_MISMATCH: u32 = (-301i32) as u32;
const MIG_SERVER_DIED: u32 = (-308i32) as u32;
/// `MACH_RCV_PORT_DIED`, which handles the exception as a success does.
const MACH_RCV_PORT_DIED: u32 = 0x1000_4009;
/// A reply's largest size: the state routines' with a full state, and the
/// receive trailer.
const REPLY_BYTES: usize = 24 + 8 + 12 + 4 * control::THREAD_STATE_MAX as usize + 256;

unsafe extern "C" {
    fn task_create_identity_token(task: u32, token: *mut u32) -> i32;
    fn mach_port_mod_refs(task: u32, name: u32, right: u32, delta: i32) -> i32;
}

/// One level's action for an exception: a send right of this space to its
/// port, and its behavior and flavor (or the x86 flavor of an inherited
/// port, which has no arm64 counterpart).
#[derive(Debug, Clone, Copy)]
pub(super) struct Action {
    pub(super) name: u32,
    pub(super) behavior: u32,
    pub(super) flavor: Result<u32, u32>,
}

/// A guest exception: its type and the codes the kernel raises it with
/// (`sleh.c` gives two, `mach_syscall` one).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Exception {
    pub(crate) kind: usize,
    pub(crate) codes: [u64; 2],
    pub(crate) count: usize,
}

/// Whether this process's address space is debugged
/// (`is_address_space_debugged`).
pub(crate) fn address_space_debugged(kernel: &Kernel) -> bool {
    super::vm::address_space_debugged(kernel)
}

/// Deliver `exception` of this thread, whose trap frame `pe` holds, to the
/// thread's and then the task's action for it: whether one handled it.
pub(crate) fn deliver(kernel: &Kernel, pe: &mut Pe, exception: Exception) -> Result<bool> {
    let actions = kernel
        .process
        .exception_ports
        .actions(kernel.thread_port, exception.kind)?;
    if actions.is_empty() {
        return Ok(false);
    }
    // An exception the thread raised in user code (an instruction the
    // runtime does not implement) enters the kernel here, so that the
    // handler sees its state, and leaves it with the state the handling
    // gave it.
    let control = kernel.control().filter(|_| pe.cpu.pstate.el == 0);
    if let Some(control) = control {
        control.enter_kernel(pe);
    }
    let mut handled = false;
    let mut outcome = Ok(());
    for action in &actions {
        if !handled && outcome.is_ok() {
            match raise(kernel, pe, exception, *action) {
                Ok(code) => handled = code == darwin::KERN_SUCCESS || code == MACH_RCV_PORT_DIED,
                // An unsupported delivery fails at this level, which goes
                // on to the next.
                Err(error) => {
                    let pc = UserState::capture(pe).pc;
                    if let Err(error) = unsupported::recover(error, Kind::Exception, pc) {
                        outcome = Err(error);
                    }
                }
            }
        }
        super::server::release_send(action.name);
    }
    if let Some(control) = control {
        control.leave(pe);
    }
    outcome.map(|()| handled)
}

/// The routine of `behavior`'s ID.
fn message_id(behavior: u32) -> i32 {
    let base = if behavior & MACH_EXCEPTION_CODES != 0 {
        MACH_EXC_BASE
    } else {
        EXC_BASE
    };
    base + match behavior & !MACH_EXCEPTION_MASK {
        EXCEPTION_DEFAULT => 0,
        EXCEPTION_STATE => 1,
        EXCEPTION_STATE_IDENTITY => 2,
        EXCEPTION_IDENTITY_PROTECTED => 3,
        _ => 5,
    }
}

/// A port descriptor carrying `name` with `disposition`.
fn port(body: &mut Vec<u8>, name: u32, disposition: u8) {
    body.extend(name.to_le_bytes());
    body.extend([0; 6]);
    body.extend([disposition, PORT_DESCRIPTOR]);
}

/// The request after its header for `behavior`: its descriptors and their
/// count (complex requests), then the NDR record and the arguments in
/// order, each variable array followed directly by the next argument as
/// MIG packs them.
pub(super) fn request_body(
    behavior: u32,
    ports: &[(u32, u8)],
    thread_id: Option<u64>,
    exception: Exception,
    state: Option<(u32, &[u32])>,
) -> Vec<u8> {
    let mut body = Vec::new();
    if !ports.is_empty() {
        body.extend((ports.len() as u32).to_le_bytes());
        for &(name, disposition) in ports {
            port(&mut body, name, disposition);
        }
    }
    body.extend(NDR_RECORD);
    if let Some(id) = thread_id {
        body.extend(id.to_le_bytes());
    }
    body.extend((exception.kind as u32).to_le_bytes());
    body.extend((exception.count as u32).to_le_bytes());
    for &code in &exception.codes[..exception.count] {
        if behavior & MACH_EXCEPTION_CODES != 0 {
            body.extend(code.to_le_bytes());
        } else {
            body.extend((code as u32).to_le_bytes());
        }
    }
    if let Some((flavor, words)) = state {
        body.extend(flavor.to_le_bytes());
        body.extend((words.len() as u32).to_le_bytes());
        body.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    }
    body
}

/// A state routine reply's new state: its flavor and words.
type NewState = Option<(u32, Vec<u32>)>;

/// A reply as MIG's user stub checks it: the routine's `kern_return_t`,
/// and for the state routines the new state's flavor and words.
pub(super) fn parse_reply(id: i32, reply: &[u8], state: bool) -> (u32, NewState) {
    let word = |at: usize| {
        reply
            .get(at..at + 4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
    };
    let (Some(bits), Some(size), Some(reply_id)) = (word(0), word(4), word(20)) else {
        return (MIG_TYPE_ERROR, None);
    };
    let reply_id = reply_id as i32;
    if reply_id == MACH_NOTIFY_SEND_ONCE {
        return (MIG_SERVER_DIED, None);
    }
    if reply_id != id + mig::REPLY_OFFSET as i32 {
        return (MIG_REPLY_MISMATCH, None);
    }
    let size = size as usize;
    if bits & MACH_MSGH_BITS_COMPLEX != 0 || size < 36 || size > reply.len() {
        return (MIG_TYPE_ERROR, None);
    }
    let code = word(32).expect("the size was checked");
    if code != darwin::KERN_SUCCESS || !state {
        return (if size == 36 { code } else { MIG_TYPE_ERROR }, None);
    }
    let (Some(flavor), Some(count)) = (word(36), word(40)) else {
        return (MIG_TYPE_ERROR, None);
    };
    if count > control::THREAD_STATE_MAX || size != 44 + 4 * count as usize {
        return (MIG_TYPE_ERROR, None);
    }
    let words = (0..count as usize)
        .map(|index| word(44 + 4 * index).expect("the size was checked"))
        .collect();
    (code, Some((flavor, words)))
}

/// The thread's user state as its kernel entry saved it.
fn user_state(kernel: &Kernel, pe: &Pe) -> UserState {
    kernel
        .control()
        .and_then(|control| control.with_state(true, |state| (*state, None)).ok())
        .unwrap_or_else(|| UserState::capture(pe))
}

/// Give the thread `state` at its return to user space.
fn set_user_state(kernel: &Kernel, pe: &mut Pe, state: UserState) {
    match kernel.control() {
        Some(control) => {
            let _ = control.with_state(true, |_| ((), Some(state)));
        }
        None => state.apply(pe),
    }
}

/// `exception_deliver` of `exception` to `action`: its `kern_return_t`.
fn raise(kernel: &Kernel, pe: &mut Pe, exception: Exception, action: Action) -> Result<u32> {
    let Action {
        name,
        behavior,
        flavor,
    } = action;
    if behavior & MACH_EXCEPTION_BACKTRACE_PREFERRED != 0 {
        unsupported::refuse!(
            Failure::Kern(darwin::KERN_FAILURE),
            "an exception port with MACH_EXCEPTION_BACKTRACE_PREFERRED (behavior \
             {behavior:#x}): a backtrace kcdata object"
        );
    }
    let kind = behavior & !MACH_EXCEPTION_MASK;
    let code64 = behavior & MACH_EXCEPTION_CODES != 0;
    if matches!(
        kind,
        EXCEPTION_IDENTITY_PROTECTED | EXCEPTION_STATE_IDENTITY_PROTECTED
    ) && !code64
    {
        // The kernel's stub exists only for 64-bit codes.
        unsupported::refuse!(
            Failure::Kern(darwin::KERN_FAILURE),
            "an identity-protected exception behavior without MACH_EXCEPTION_CODES"
        );
    }
    let with_state = matches!(
        kind,
        EXCEPTION_STATE | EXCEPTION_STATE_IDENTITY | EXCEPTION_STATE_IDENTITY_PROTECTED
    );
    let signer = kernel.process.signer.as_ref();
    let state = user_state(kernel, pe);
    let flavor = match flavor {
        Ok(flavor) => flavor,
        Err(x86) if with_state => unsupported::refuse!(
            Failure::Kern(darwin::KERN_FAILURE),
            "{} to an inherited exception port with x86 state flavor {x86}, which has no arm64 \
             counterpart",
            super::exception::NAMES
                .get(exception.kind)
                .unwrap_or(&"an exception")
        ),
        Err(_) => 0,
    };
    let old = if with_state {
        match control::get_state(&state, flavor, control::THREAD_STATE_MAX, signer)? {
            Ok(words) => Some(words),
            Err(code) => return Ok(code),
        }
    } else {
        None
    };
    let mut token = 0;
    let (ports, thread_id): (Vec<(u32, u8)>, Option<u64>) = match kind {
        EXCEPTION_DEFAULT | EXCEPTION_STATE_IDENTITY => {
            if !super::vm::developer_mode() {
                unsupported::refuse!(
                    Failure::Kern(darwin::KERN_FAILURE),
                    "an exception port with behavior {behavior:#x} without developer mode: the \
                     task and thread read ports it carries"
                );
            }
            (
                vec![
                    (kernel.thread_port, COPY_SEND as u8),
                    (kernel.process.task_port(), COPY_SEND as u8),
                ],
                None,
            )
        }
        EXCEPTION_IDENTITY_PROTECTED | EXCEPTION_STATE_IDENTITY_PROTECTED => {
            // SAFETY: this task's port and an out name.
            let code =
                unsafe { task_create_identity_token(kernel.process.task_port(), &raw mut token) };
            if code != 0 {
                bail!("this task's identity token could not be made: {code:#x}");
            }
            let mut id = 0u64;
            // SAFETY: the calling thread's ID into this frame.
            unsafe { libc::pthread_threadid_np(0, &raw mut id) };
            (vec![(token, MOVE_SEND)], Some(id))
        }
        EXCEPTION_STATE => (Vec::new(), None),
        _ => unsupported::refuse!(
            Failure::Kern(darwin::KERN_FAILURE),
            "an exception port with behavior {behavior:#x}"
        ),
    };
    let id = message_id(behavior);
    let body = request_body(
        behavior,
        &ports,
        thread_id,
        exception,
        old.as_deref().map(|words| (flavor, words)),
    );
    let (code, new) = rpc(kernel, name, id, !ports.is_empty(), &body, with_state)?;
    let Some((flavor, words)) = new else {
        return Ok(code);
    };
    // `thread_setstatus_from_user` of the reply's state, over a state the
    // handler set meanwhile.
    let state = user_state(kernel, pe);
    Ok(match control::set_state(&state, flavor, &words, signer)? {
        Ok(state) => {
            set_user_state(kernel, pe, state);
            darwin::KERN_SUCCESS
        }
        Err(code) => code,
    })
}

/// Send the request `id` with `body` to `destination` with a reply port of
/// this space and await its reply, as a host call of this thread: the
/// routine's `kern_return_t` (or the send's or receive's failure), and the
/// state routines' new state.
fn rpc(
    kernel: &Kernel,
    destination: u32,
    id: i32,
    complex: bool,
    body: &[u8],
    state: bool,
) -> Result<(u32, NewState)> {
    let mut reply_port = 0;
    // SAFETY: a new receive right of this space into an out name.
    let code =
        unsafe { mach_port_allocate(host::task(), MACH_PORT_RIGHT_RECEIVE, &raw mut reply_port) };
    if code != 0 {
        bail!("an exception reply port could not be made: {code:#x}");
    }
    let size = 24 + body.len();
    let mut message = vec![0u8; size.max(REPLY_BYTES)];
    let bits = COPY_SEND | MAKE_SEND_ONCE << 8 | if complex { MACH_MSGH_BITS_COMPLEX } else { 0 };
    for (at, word) in [
        (0, bits),
        (4, size as u32),
        (8, destination),
        (12, reply_port),
        (16, 0),
        (20, id as u32),
    ] {
        message[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    message[24..size].copy_from_slice(body);
    let receive = message.len() as u32;
    // SAFETY: a message buffer of `receive` bytes this frame owns; the
    // reply port is this space's.
    let sent = kernel.forwarding(|| unsafe {
        mach_msg(
            message.as_mut_ptr(),
            darwin::MACH_SEND_MSG | darwin::MACH_RCV_MSG,
            size as u32,
            receive,
            reply_port,
            0,
            0,
        )
    });
    // SAFETY: the receive right made above.
    unsafe { mach_port_mod_refs(host::task(), reply_port, MACH_PORT_RIGHT_RECEIVE, -1) };
    Ok(match sent {
        Some(0) => parse_reply(id, &message, state),
        Some(failure) => (failure as u32, None),
        // The thread was terminated: it does not return to user space.
        None => (darwin::KERN_SUCCESS, None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_pack_each_routine_as_mig_does() {
        let exception = Exception {
            kind: 1,
            codes: [2, 0x1234_5678_9abc],
            count: 2,
        };
        // mach_exception_raise: two port descriptors, then 64-bit codes.
        let body = request_body(
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
            &[(0x103, 19), (0x203, 19)],
            None,
            exception,
            None,
        );
        assert_eq!(body.len(), 4 + 24 + 8 + 8 + 16);
        assert_eq!(&body[..4], &2u32.to_le_bytes());
        assert_eq!(&body[4..8], &0x103u32.to_le_bytes());
        assert_eq!(body[14..16], [19, 0]);
        assert_eq!(&body[28..36], &NDR_RECORD);
        assert_eq!(&body[44..52], &2u64.to_le_bytes());
        assert_eq!(message_id(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), 2405);
        // exception_raise_state: 32-bit codes, then the flavor and state.
        let body = request_body(EXCEPTION_STATE, &[], None, exception, Some((6, &[7; 68])));
        assert_eq!(body.len(), 8 + 8 + 8 + 8 + 68 * 4);
        assert_eq!(&body[16..20], &2u32.to_le_bytes());
        assert_eq!(&body[20..24], &0x5678_9abcu32.to_le_bytes());
        assert_eq!(&body[24..28], &6u32.to_le_bytes());
        assert_eq!(&body[28..32], &68u32.to_le_bytes());
        assert_eq!(message_id(EXCEPTION_STATE), 2402);
        // The identity-protected routines put the thread ID before the
        // exception.
        let body = request_body(
            EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES,
            &[(0x303, MOVE_SEND)],
            Some(0x42),
            exception,
            Some((6, &[0; 68])),
        );
        assert_eq!(&body[24..32], &0x42u64.to_le_bytes());
        assert_eq!(
            message_id(EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
            2408
        );
        assert_eq!(
            message_id(EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
            2410
        );
        // EXC_SYSCALL's one code.
        let one = Exception {
            count: 1,
            ..exception
        };
        let body = request_body(EXCEPTION_STATE | MACH_EXCEPTION_CODES, &[], None, one, None);
        assert_eq!(body.len(), 8 + 8 + 8);
        assert_eq!(&body[12..16], &1u32.to_le_bytes());
    }

    #[test]
    fn replies_are_checked_as_the_user_stub_checks_them() {
        let reply = |id: i32, words: &[u32]| {
            let size = 24 + 4 * words.len();
            let mut bytes = Vec::new();
            for word in [0, size as u32, 0, 0, 0, id as u32] {
                bytes.extend(word.to_le_bytes());
            }
            bytes.extend(words.iter().flat_map(|word| word.to_le_bytes()));
            bytes
        };
        // NDR, then RetCode.
        assert_eq!(
            parse_reply(2405, &reply(2505, &[0, 1, 0]), false),
            (0, None)
        );
        assert_eq!(
            parse_reply(2405, &reply(2505, &[0, 1, 5]), false),
            (5, None)
        );
        assert_eq!(
            parse_reply(2405, &reply(2506, &[0, 1, 0]), false),
            (MIG_REPLY_MISMATCH, None)
        );
        assert_eq!(
            parse_reply(2405, &reply(MACH_NOTIFY_SEND_ONCE, &[0, 1, 0]), false),
            (MIG_SERVER_DIED, None)
        );
        // A state reply: RetCode, flavor, count and the words.
        assert_eq!(
            parse_reply(2406, &reply(2506, &[0, 1, 0, 6, 2, 9, 8]), true),
            (0, Some((6, vec![9, 8])))
        );
        assert_eq!(
            parse_reply(2406, &reply(2506, &[0, 1, 0, 6, 3, 9, 8]), true),
            (MIG_TYPE_ERROR, None)
        );
        // A failing state routine replies with its code alone.
        assert_eq!(parse_reply(2406, &reply(2506, &[0, 1, 5]), true), (5, None));
    }
}
