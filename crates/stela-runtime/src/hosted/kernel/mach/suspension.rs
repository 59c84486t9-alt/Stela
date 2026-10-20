//! Thread suspension tokens (`thread_suspend2`, `thread_resume2`;
//! `osfmk/kern/thread_act.c`). Each `thread_suspend2` adds a user stop and
//! gives the caller a send right to the thread's resume port, an
//! `IKOT_THREAD_RESUME` kernel object: `thread_resume2` on a token resumes
//! one stop, and when no token is left (its no-senders notification, with
//! no token made since) every stop a token made is resumed.
//!
//! The resume port is a port of this space whose receive right the hosted
//! kernel holds, its context the guest thread's port name; a service
//! thread receives its `thread_resume2` requests and no-senders
//! notifications and answers as the kernel object does. The port ends
//! with the thread, so its tokens become dead names. Known limit: the
//! token's name also holds the hosted kernel's receive right, which
//! `mach_port_type` and the space's listings show.
use super::super::control::{self, Token};
use super::super::{Kernel, Process};
use super::server::{Descriptor, MIG_BAD_ARGUMENTS, MOVE_SEND, Reply};
use crate::hosted::darwin::{
    MACH_MSG_TYPE_MAKE_SEND, MACH_PORT_RIGHT_RECEIVE, MACH_RCV_MSG, MACH_SEND_MSG,
    MACH_SEND_TIMEOUT, mach_msg, mach_port_allocate, mach_port_insert_right,
};
use crate::hosted::host;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// `mach_port_right_t`s, dispositions and notifications.
const MACH_PORT_RIGHT_PORT_SET: u32 = 3;
const MACH_PORT_TYPE_RECEIVE: u32 = 1 << 17;
const MACH_MSG_TYPE_MAKE_SEND_ONCE: u32 = 21;
const MACH_NOTIFY_NO_SENDERS: i32 = 0o106;
/// `MACH_PORT_RECEIVE_STATUS` and the offset of `mps_mscount` in
/// `mach_port_status_t` (after `mps_pset` and `mps_seqno`).
const MACH_PORT_RECEIVE_STATUS: i32 = 2;
const STATUS_WORDS: usize = 10;
const STATUS_MSCOUNT: usize = 2;
/// `mach_msg` results.
const MACH_RCV_INTERRUPTED: i32 = 0x1000_4005;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
/// `thread_resume2`'s message ID, and its reply's.
const THREAD_RESUME2: u32 = 3633;
const MIG_REPLY_OFFSET: u32 = 100;
/// `KERN_RESOURCE_SHORTAGE`.
const KERN_RESOURCE_SHORTAGE: u32 = 6;
/// The largest message the service receives: a notification or a
/// `thread_resume2` request, with room for a trailer.
const RECEIVE_BYTES: usize = 1024;

unsafe extern "C" {
    fn mach_port_mod_refs(task: u32, name: u32, right: u32, delta: i32) -> i32;
    fn mach_port_insert_member(task: u32, name: u32, set: u32) -> i32;
    fn mach_port_set_context(task: u32, name: u32, context: u64) -> i32;
    fn mach_port_get_context(task: u32, name: u32, context: *mut u64) -> i32;
    fn mach_port_type(task: u32, name: u32, kind: *mut u32) -> i32;
    fn mach_port_get_attributes(
        task: u32,
        name: u32,
        flavor: i32,
        info: *mut u32,
        count: *mut u32,
    ) -> i32;
    fn mach_port_request_notification(
        task: u32,
        name: u32,
        id: i32,
        sync: u32,
        notify: u32,
        disposition: u32,
        previous: *mut u32,
    ) -> i32;
}

/// The service's port set, tagged with the process that made it: a fork
/// child, which has neither the set nor the service thread, makes its own.
static SERVICE: AtomicU64 = AtomicU64::new(0);

/// `thread_suspend2` on the guest thread `port`: a stop and a token, in a
/// reply carrying only the token.
pub(super) fn suspend(kernel: &Kernel, port: u32) -> Result<Reply> {
    let Some(control) = kernel.process.runtime.registry.control_by_port(port) else {
        return Ok(Reply::Failure(control::KERN_TERMINATED));
    };
    let set = service(&kernel.process)?;
    let own = port == kernel.thread_port;
    Ok(
        match control.suspend_with_token(own, |token| mint(token, port, set)) {
            Ok(name) => Reply::Descriptors(vec![Descriptor::Port {
                name,
                disposition: MOVE_SEND,
            }]),
            Err(code) => Reply::Failure(code),
        },
    )
}

/// Make one token: a send right to the thread's resume port, made first,
/// with its no-senders notification requested.
fn mint(token: &mut Token, thread: u32, set: u32) -> std::result::Result<u32, u32> {
    let task = host::task();
    let mut kind = 0u32;
    // SAFETY: names of this space and a local out argument.
    let held = token.port != 0
        && unsafe { mach_port_type(task, token.port, &mut kind) } == 0
        && kind & MACH_PORT_TYPE_RECEIVE != 0;
    if !held {
        *token = Token::default();
        let mut name = 0u32;
        // SAFETY: a new receive right of this space, its context the
        // thread's name, in the service's set.
        let made = unsafe {
            mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &mut name) == 0
                && mach_port_set_context(task, name, u64::from(thread)) == 0
                && mach_port_insert_member(task, name, set) == 0
        };
        if !made {
            return Err(KERN_RESOURCE_SHORTAGE);
        }
        token.port = name;
    }
    // SAFETY: a send right made from the receive right this space holds.
    if unsafe { mach_port_insert_right(task, token.port, token.port, MACH_MSG_TYPE_MAKE_SEND) } != 0
    {
        return Err(KERN_RESOURCE_SHORTAGE);
    }
    if !token.armed {
        token.armed = arm(token.port);
    }
    Ok(token.port)
}

/// Request the resume port's next no-senders notification, to itself.
fn arm(port: u32) -> bool {
    let mut previous = 0u32;
    // SAFETY: the receive right this space holds and a local out argument.
    unsafe {
        mach_port_request_notification(
            host::task(),
            port,
            MACH_NOTIFY_NO_SENDERS,
            0,
            port,
            MACH_MSG_TYPE_MAKE_SEND_ONCE,
            &mut previous,
        ) == 0
    }
}

/// The resume port's make-send count.
fn make_send_count(port: u32) -> Option<u32> {
    let mut status = [0u32; STATUS_WORDS];
    let mut count = STATUS_WORDS as u32;
    // SAFETY: an out array of `count` words.
    let code = unsafe {
        mach_port_get_attributes(
            host::task(),
            port,
            MACH_PORT_RECEIVE_STATUS,
            status.as_mut_ptr(),
            &mut count,
        )
    };
    (code == 0).then_some(status[STATUS_MSCOUNT])
}

/// The thread ended: its resume port goes, and its tokens with it.
pub(crate) fn destroy(token: Token) {
    if token.port != 0 {
        // SAFETY: the receive right this space holds for the thread.
        unsafe { mach_port_mod_refs(host::task(), token.port, MACH_PORT_RIGHT_RECEIVE, -1) };
    }
}

/// This process's service port set, starting its service thread first.
fn service(process: &Arc<Process>) -> Result<u32> {
    let pid = u64::from(std::process::id());
    loop {
        let current = SERVICE.load(Ordering::SeqCst);
        if current >> 32 == pid {
            match current as u32 {
                0 => std::thread::yield_now(),
                set => return Ok(set),
            }
            continue;
        }
        if SERVICE
            .compare_exchange(current, pid << 32, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            continue;
        }
        let mut set = 0u32;
        // SAFETY: a new port set of this space.
        if unsafe { mach_port_allocate(host::task(), MACH_PORT_RIGHT_PORT_SET, &mut set) } != 0 {
            SERVICE.store(0, Ordering::SeqCst);
            return Err(anyhow!("thread_suspend2: no port set for the resume ports"));
        }
        let process = process.clone();
        let builder = std::thread::Builder::new().name("stela-suspension".into());
        super::super::bsd::signal::host::without_signals(|| {
            builder.spawn(move || serve(&process, set))
        })?;
        SERVICE.store(pid << 32 | u64::from(set), Ordering::SeqCst);
        return Ok(set);
    }
}

/// Receive on the resume ports and answer as their kernel objects do.
fn serve(process: &Process, set: u32) {
    let mut buffer = [0u64; RECEIVE_BYTES / 8];
    loop {
        let message = buffer.as_mut_ptr().cast::<u8>();
        // SAFETY: a receive into the local buffer of its size.
        let code = unsafe { mach_msg(message, MACH_RCV_MSG, 0, RECEIVE_BYTES as u32, set, 0, 0) };
        if code == MACH_RCV_INTERRUPTED {
            continue;
        }
        if code != 0 {
            process.runtime.fail(anyhow!(
                "the suspension-token service could not receive: {code:#x}"
            ));
            return;
        }
        let word = |index: usize| (buffer[index / 2] >> (32 * (index % 2))) as u32;
        let (bits, size, reply, port, voucher, id) =
            (word(0), word(1), word(2), word(3), word(4), word(5));
        // A request's voucher is not the kernel object's to keep.
        super::server::release_send(voucher);
        let thread = {
            let mut context = 0u64;
            // SAFETY: a name of this space and a local out argument.
            unsafe { mach_port_get_context(host::task(), port, &mut context) };
            process.runtime.registry.control_by_port(context as u32)
        };
        match id {
            // `mach_no_senders_notification_t`: the NDR record, then
            // `not_count`.
            id if id == MACH_NOTIFY_NO_SENDERS as u32 => {
                let count = word(8);
                if let Some(thread) = thread {
                    thread.tokens_released(
                        port,
                        || make_send_count(port) == Some(count),
                        || arm(port),
                    );
                }
            }
            THREAD_RESUME2 => {
                let code = if bits & MACH_MSGH_BITS_COMPLEX != 0 || size != 24 {
                    MIG_BAD_ARGUMENTS
                } else {
                    thread.map_or(control::KERN_TERMINATED, |thread| {
                        thread.resume_from_token()
                    })
                };
                answer(bits, reply, code);
            }
            _ => {
                process.runtime.fail(anyhow!(
                    "message {id} to a thread suspension token: only thread_resume2 is \
                     implemented"
                ));
                return;
            }
        }
    }
}

/// Send `thread_resume2`'s reply (`mig_reply_error_t`) to the request's
/// reply right.
fn answer(bits: u32, reply: u32, code: u32) {
    unsafe extern "C" {
        fn mach_msg_destroy(message: *mut u32);
    }
    if reply == 0 {
        return;
    }
    let mut message = [0u32; 10];
    message[0] = bits & 0x1f;
    message[1] = 36;
    message[2] = reply;
    message[5] = THREAD_RESUME2 + MIG_REPLY_OFFSET;
    // The NDR record: little-endian, ASCII, IEEE floats.
    message[7] = 1;
    message[8] = code;
    // SAFETY: a send of the local message; a full or dead reply port
    // drops it and its reply right.
    unsafe {
        if mach_msg(
            message.as_mut_ptr().cast(),
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            36,
            0,
            0,
            0,
            0,
        ) != 0
        {
            mach_msg_destroy(message.as_mut_ptr());
        }
    }
}
