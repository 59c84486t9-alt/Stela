//! The `thread_act` routines of this process's guest threads beyond
//! suspension and thread state ([`super::server`]): termination, abort,
//! information, scheduling policy, special and exception ports, and state
//! conversion. A guest thread is a host thread, so a routine whose answer
//! is the arm64 kernel's is forwarded to its port; the others answer from
//! the thread's [`Control`] or restate the host kernel's answer in arm64
//! terms (time in the guest's 24 MHz ticks, its TSD base, its suspension).
use super::super::control::{self, Control, Kind};
use super::super::{End, Kernel};
use super::exception::{self, Target};
use super::server::{
    KERN_INVALID_ARGUMENT, KERN_NOT_SUPPORTED, MIG_BAD_ARGUMENTS, Reply, Request, release_send,
};
use crate::hosted::host;
use crate::hosted::threads::lock;
use anyhow::{Result, bail};
use std::sync::Arc;

unsafe extern "C" {
    fn thread_info(thread: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    fn thread_policy_set(thread: u32, flavor: u32, policy: *const i32, count: u32) -> i32;
    fn thread_policy_get(
        thread: u32,
        flavor: u32,
        info: *mut u32,
        count: *mut u32,
        get_default: *mut u32,
    ) -> i32;
    fn mach_port_get_refs(task: u32, name: u32, right: u32, refs: *mut u32) -> i32;
}

const KERN_SUCCESS: u32 = 0;
/// `KERN_NO_ACCESS`.
const KERN_NO_ACCESS: u32 = 8;
const KERN_INSUFFICIENT_BUFFER_SIZE: u32 = 52;
const KERN_DENIED: u32 = 53;
/// `MACH_SEND_INVALID_DEST`.
pub(super) const MACH_SEND_INVALID_DEST: u32 = 0x1000_0003;

/// Thread routines whose answer is the arm64 kernel's, forwarded to the
/// thread's port: they act on the host thread's priority depression,
/// legacy scheduling policy (`POLICY_RR` quanta are milliseconds) and
/// vouchers, all the arm64 thread's own.
pub(super) const FORWARDED: &[&str] = &[
    "thread_depress_abort_from_user",
    "_kernelrpc_thread_policy",
    "_kernelrpc_thread_set_policy",
    "thread_get_mach_voucher",
    "thread_set_mach_voucher",
    "thread_swap_mach_voucher",
];

/// `thread_info` flavors and counts.
const THREAD_BASIC_INFO: u32 = 3;
const THREAD_IDENTIFIER_INFO: u32 = 4;
const THREAD_EXTENDED_INFO: u32 = 5;
const THREAD_BASIC_INFO_COUNT: u32 = 10;
const THREAD_IDENTIFIER_INFO_COUNT: u32 = 6;
const THREAD_EXTENDED_INFO_COUNT: u32 = 28;
/// `THREAD_INFO_MAX`, MIG's bound on the out count.
const THREAD_INFO_MAX: u32 = 32;
/// `run_state` in the basic and extended layouts, `suspend_count` in the
/// basic one.
const BASIC_RUN_STATE: usize = 6;
const BASIC_SUSPEND_COUNT: usize = 8;
const EXTENDED_RUN_STATE: usize = 6;
/// `TH_STATE_UNINTERRUPTIBLE`: a created thread not yet resumed waits in
/// `thread_create`'s uninterruptible start.
const TH_STATE_UNINTERRUPTIBLE: u32 = 4;

/// `thread_policy` flavors the arm64 kernel answers apart from the host.
const THREAD_TIME_CONSTRAINT_POLICY: u32 = 2;
const THREAD_AFFINITY_POLICY: u32 = 4;
const THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY: u32 = 10;
/// `THREAD_POLICY_INFO_MAX`, MIG's bound on the policy count.
const THREAD_POLICY_INFO_MAX: u32 = 16;
/// The time-constraint fields in absolute time: period, computation,
/// constraint.
const TIME_FIELDS: usize = 3;

/// `thread_get_special_port`'s `which`.
const THREAD_KERNEL_PORT: u32 = 1;
const THREAD_INSPECT_PORT: u32 = 2;
const THREAD_READ_PORT: u32 = 3;
/// `KERN_INVALID_RIGHT`: a right the routine may not take.
const KERN_INVALID_RIGHT: u32 = 17;

/// `thread_convert_thread_state`'s directions.
const TO_SELF: u32 = 1;
const FROM_SELF: u32 = 2;

/// Answer a `thread_act` routine sent to the guest thread `port`, or
/// `None` when this module does not serve it.
pub(super) fn serve(
    kernel: &mut Kernel,
    port: u32,
    routine: &str,
    complex: bool,
    request: &Request,
) -> Result<Option<Reply>> {
    Ok(Some(match (routine, complex) {
        (routine, _) if FORWARDED.contains(&routine) => Reply::Forward,
        ("thread_terminate_from_user", false) => {
            if !request.body.is_empty() {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            }
            terminate(kernel, port)
        }
        (routine @ ("thread_abort" | "thread_abort_safely"), false) => {
            if !request.body.is_empty() {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            }
            match target(kernel, port) {
                Some(control) => status(control.abort(port, routine == "thread_abort_safely")),
                None => Reply::Failure(control::KERN_TERMINATED),
            }
        }
        ("thread_info", false) => info(kernel, port, request)?,
        ("_kernelrpc_thread_policy_set", false) => policy_set(kernel, port, request)?,
        ("thread_policy_get", false) => policy_get(kernel, port, request)?,
        // `which_port`. The kernel port is the thread's own; its read and
        // inspect ports would be the host thread's, whose state routines
        // the host kernel answers for the x86 thread.
        // The kernel port is this thread's own kernel object, whose name
        // the reply repeats; the kernels refuse every unknown number alike.
        ("thread_get_special_port_from_user", false) => match request.word(8) {
            Some(which @ (THREAD_INSPECT_PORT | THREAD_READ_PORT)) => bail!(
                "thread_get_special_port({which}): the host thread's read and inspect ports \
                 would answer for the x86 thread, which is not implemented"
            ),
            Some(_) => Reply::Forward,
            None => Reply::Failure(MIG_BAD_ARGUMENTS),
        },
        // One port descriptor, then `which_port`: this task's own control
        // ports are immovable sends of a platform-restricted task, which
        // no special port may hold (`KERN_INVALID_RIGHT`); the kernel port
        // is settable only with SIP's kernel-debugger allowance, which a
        // stock Mac does not grant (`KERN_NO_ACCESS`); no other port is.
        ("thread_set_special_port", true) => {
            let immovable = request
                .word(4)
                .is_some_and(|name| immovable_send(kernel, name));
            let name = match exception::carried_send(kernel, routine, request, 28)? {
                Ok(name) => name,
                Err(reply) => return Ok(Some(reply)),
            };
            release_send(name);
            match request.word(24) {
                _ if immovable => Reply::Failure(KERN_INVALID_RIGHT),
                Some(THREAD_KERNEL_PORT) => Reply::Failure(KERN_NO_ACCESS),
                _ => Reply::Failure(KERN_INVALID_ARGUMENT),
            }
        }
        ("thread_set_exception_ports", true) => {
            exception::set(kernel, request, false, Target::Thread(port))?
        }
        ("thread_swap_exception_ports", true) => {
            exception::set(kernel, request, true, Target::Thread(port))?
        }
        ("thread_get_exception_ports_from_user", false) => {
            exception::get(kernel, request, Target::Thread(port))?
        }
        ("thread_get_exception_ports_info", false) => {
            exception::info(kernel, request, Target::Thread(port))?
        }
        ("thread_adopt_exception_handler", true) => exception::adopt(kernel, request)?,
        ("thread_convert_thread_state", false) => convert(kernel, request)?,
        ("thread_suspend2", false) => {
            if !request.body.is_empty() {
                return Ok(Some(Reply::Failure(MIG_BAD_ARGUMENTS)));
            }
            super::suspension::suspend(kernel, port)?
        }
        // A thread port is no suspension token (`IKOT_THREAD_RESUME`).
        ("thread_resume2", false) => Reply::Failure(KERN_INVALID_ARGUMENT),
        _ => return Ok(None),
    }))
}

/// A routine whose only out argument is its `kern_return_t`.
fn status(code: u32) -> Reply {
    if code == KERN_SUCCESS {
        Reply::Success(Vec::new())
    } else {
        Reply::Failure(code)
    }
}

/// The control of the guest thread `port`.
fn target(kernel: &Kernel, port: u32) -> Option<Arc<Control>> {
    kernel.process.runtime.registry.control_by_port(port)
}

/// The send references this space holds for `port` beyond the one its
/// host thread library keeps for every host thread: the guest's.
pub(super) fn guest_references(port: u32) -> u32 {
    const MACH_PORT_RIGHT_SEND: u32 = 0;
    let mut references = 0u32;
    // SAFETY: a name of this task's own space and a local out argument.
    let status = unsafe {
        mach_port_get_refs(
            host::task(),
            port,
            MACH_PORT_RIGHT_SEND,
            &raw mut references,
        )
    };
    if status == 0 {
        references.saturating_sub(1)
    } else {
        0
    }
}

/// Whether `name` is an immovable send right of this space
/// (`ipc_should_mark_immovable_send`): the task's own control port or one
/// of its threads', in a task whose control ports are immovable. macOS
/// makes them immovable for first-party code, the platform-restricted
/// tasks (`ICP_OPTIONS_IMMOVABLE_1P_HARD`), and movable for others.
pub(super) fn immovable_send(kernel: &Kernel, name: u32) -> bool {
    let own = name == kernel.process.task_port()
        || name == kernel.thread_port
        || kernel.process.runtime.registry.contains_port(name);
    own && lock(&kernel.process.executable)
        .signature
        .as_ref()
        .is_some_and(|signature| signature.platform_restricted())
}

/// Whether the guest thread `port`'s right is pinned in this space: every
/// thread's but one `thread_create` made (`ipc_thread_set_immovable_pinned`
/// pins the main thread's and each pthread's).
pub(super) fn pinned(kernel: &Kernel, port: u32) -> bool {
    target(kernel, port).is_some_and(|control| control.kind() != Kind::Mach)
}

/// `thread_terminate_from_user`: a pthread is refused (`KERN_DENIED`, it
/// ends through `bsdthread_terminate`); the main thread or one
/// `thread_create` made ends, the caller's own at its return to user
/// space, after its reply.
fn terminate(kernel: &mut Kernel, port: u32) -> Reply {
    let Some(control) = target(kernel, port) else {
        return Reply::Failure(control::KERN_TERMINATED);
    };
    if control.kind() == Kind::Pthread {
        return Reply::Failure(KERN_DENIED);
    }
    if port == kernel.thread_port {
        if !control.active() {
            return Reply::Failure(control::KERN_TERMINATED);
        }
        kernel.end = Some(End::Thread);
        return Reply::Success(Vec::new());
    }
    status(control.terminate(port))
}

/// `thread_info(flavor, thread_info_outCnt)`. The basic, identifier and
/// extended flavors restate the host kernel's answer for the guest
/// thread: its suspension, a created thread's unstarted wait, and its
/// TSD base and dispatch queue address. The scheduling flavors are the
/// host thread's, forwarded.
fn info(kernel: &Kernel, port: u32, request: &Request) -> Result<Reply> {
    let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if !matches!(
        flavor,
        THREAD_BASIC_INFO | THREAD_IDENTIFIER_INFO | THREAD_EXTENDED_INFO
    ) {
        return Ok(Reply::Forward);
    }
    let Some(control) = target(kernel, port).filter(|control| control.active()) else {
        return Ok(Reply::Failure(control::KERN_TERMINATED));
    };
    let count = count.min(THREAD_INFO_MAX);
    let mut words = vec![0u32; THREAD_INFO_MAX as usize];
    let mut answered = count;
    // SAFETY: a thread port of this task and a buffer of `count` words.
    let code = unsafe {
        thread_info(
            port,
            flavor as i32,
            words.as_mut_ptr().cast(),
            &raw mut answered,
        )
    } as u32;
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code));
    }
    let (stops, unstarted) = control.suspension();
    match flavor {
        THREAD_BASIC_INFO => {
            words[BASIC_SUSPEND_COUNT] = stops;
            if unstarted && stops > 0 {
                words[BASIC_RUN_STATE] = TH_STATE_UNINTERRUPTIBLE;
            }
            debug_assert_eq!(answered, THREAD_BASIC_INFO_COUNT);
        }
        THREAD_EXTENDED_INFO => {
            if unstarted && stops > 0 {
                words[EXTENDED_RUN_STATE] = TH_STATE_UNINTERRUPTIBLE;
            }
            debug_assert_eq!(answered, THREAD_EXTENDED_INFO_COUNT);
        }
        _ => {
            // `thread_handle` is `cthread_self`; `dispatch_qaddr` adds the
            // registered queue offset, none for a thread without one. The
            // count is left as asked.
            let handle = control.thread_pointer();
            let offset = kernel
                .process
                .threads
                .registration()
                .map_or(0, |registration| registration.dispatch_queue_offset);
            let queue = if handle == 0 { 0 } else { handle + offset };
            words[2] = handle as u32;
            words[3] = (handle >> 32) as u32;
            words[4] = queue as u32;
            words[5] = (queue >> 32) as u32;
            answered = count;
            debug_assert!(count >= THREAD_IDENTIFIER_INFO_COUNT);
        }
    }
    let mut body = answered.to_le_bytes().to_vec();
    for word in &words[..answered as usize] {
        body.extend(word.to_le_bytes());
    }
    Ok(Reply::Success(body))
}

/// Host absolute time (x86 nanoseconds) for guest ticks, rounded up so
/// that [`ticks`] of it is the same count of ticks again: `None` past the
/// host's 32-bit field.
fn host_time(ticks: u32) -> Option<u32> {
    let nanoseconds = (u64::from(ticks) * 1_000_000_000).div_ceil(host::COUNTER_HZ);
    u32::try_from(nanoseconds).ok()
}

/// Guest ticks for host absolute time.
fn ticks(nanoseconds: u32) -> u32 {
    (u64::from(nanoseconds) * host::COUNTER_HZ / 1_000_000_000) as u32
}

/// `thread_policy_set(flavor, policy_infoCnt, policy_info)`. A time
/// constraint is in absolute time, which the host thread takes in its
/// nanoseconds: the bounds the kernel checks (50 us to 50 ms of
/// computation) and its rounding of the computation to half the
/// constraint then fall on the same values. Affinity sets do not exist
/// on arm64 (`ml_get_max_affinity_sets`): the host kernel's checks that
/// precede the flavor's are asked with an empty affinity policy, whose
/// count it refuses where the arm64 kernel refuses the flavor.
fn policy_set(kernel: &Kernel, port: u32, request: &Request) -> Result<Reply> {
    let (Some(flavor), Some(count)) = (request.word(8), request.word(12)) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if count > THREAD_POLICY_INFO_MAX || request.body.len() != 16 + count as usize * 4 {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    }
    let mut words: Vec<u32> = (0..count as usize)
        .map(|index| request.word(16 + index * 4).expect("the count was checked"))
        .collect();
    match flavor {
        THREAD_TIME_CONSTRAINT_POLICY | THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY => {
            for (index, word) in words.iter_mut().enumerate().take(TIME_FIELDS) {
                let Some(converted) = host_time(*word) else {
                    bail!(
                        "thread_policy_set time constraint field {index} of {word} ticks: the \
                         host's 32-bit nanoseconds cannot hold it, which is not implemented"
                    );
                };
                *word = converted;
            }
        }
        THREAD_AFFINITY_POLICY => {
            if target(kernel, port).is_some_and(|control| !control.active()) {
                return Ok(Reply::Failure(control::KERN_TERMINATED));
            }
            // SAFETY: a thread port of this task and an empty policy.
            let code = unsafe { thread_policy_set(port, flavor, words.as_ptr().cast(), 0) } as u32;
            return Ok(Reply::Failure(match code {
                KERN_INVALID_ARGUMENT => KERN_NOT_SUPPORTED,
                other => other,
            }));
        }
        _ => return Ok(Reply::Forward),
    }
    // SAFETY: a thread port of this task and `count` words.
    let code = unsafe { thread_policy_set(port, flavor, words.as_ptr().cast(), count) } as u32;
    Ok(status(code))
}

/// `thread_policy_get(flavor, policy_infoCnt, get_default)`: a time
/// constraint restated in guest ticks, the affinity flavor refused as on
/// arm64; the others are the host thread's, forwarded. The reply carries
/// the count the kernel leaves, the policy words and `get_default`.
fn policy_get(kernel: &Kernel, port: u32, request: &Request) -> Result<Reply> {
    let (Some(flavor), Some(count), Some(get_default)) =
        (request.word(8), request.word(12), request.word(16))
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if request.body.len() != 20 {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    }
    match flavor {
        THREAD_TIME_CONSTRAINT_POLICY | THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY => {}
        THREAD_AFFINITY_POLICY => {
            return Ok(Reply::Failure(
                if target(kernel, port).is_some_and(|control| !control.active()) {
                    control::KERN_TERMINATED
                } else {
                    KERN_NOT_SUPPORTED
                },
            ));
        }
        _ => return Ok(Reply::Forward),
    }
    let mut count = count.min(THREAD_POLICY_INFO_MAX);
    let mut words = vec![0u32; THREAD_POLICY_INFO_MAX as usize];
    let mut get_default = get_default;
    // SAFETY: a thread port of this task and buffers of the sizes given.
    let code = unsafe {
        thread_policy_get(
            port,
            flavor,
            words.as_mut_ptr(),
            &raw mut count,
            &raw mut get_default,
        )
    } as u32;
    if code != KERN_SUCCESS {
        return Ok(Reply::Failure(code));
    }
    for word in words.iter_mut().take(TIME_FIELDS) {
        *word = ticks(*word);
    }
    let mut body = count.to_le_bytes().to_vec();
    for word in &words[..count as usize] {
        body.extend(word.to_le_bytes());
    }
    body.extend(get_default.to_le_bytes());
    Ok(Reply::Success(body))
}

/// `thread_convert_thread_state(direction, flavor, in_stateCnt, in_state,
/// out_stateCnt)`: a state of one of this process's threads made the
/// other's, which share the process's user JOP key.
fn convert(kernel: &Kernel, request: &Request) -> Result<Reply> {
    let (Some(direction), Some(flavor), Some(in_count)) =
        (request.word(8), request.word(12), request.word(16))
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if in_count > control::THREAD_STATE_MAX || request.body.len() != 24 + in_count as usize * 4 {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    }
    let out_count = request
        .word(20 + in_count as usize * 4)
        .expect("the size was checked")
        .min(control::THREAD_STATE_MAX);
    if direction != TO_SELF && direction != FROM_SELF {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    if in_count > out_count {
        return Ok(Reply::Failure(KERN_INSUFFICIENT_BUFFER_SIZE));
    }
    let mut words: Vec<u32> = (0..in_count as usize)
        .map(|index| request.word(20 + index * 4).expect("the size was checked"))
        .collect();
    control::convert_state(flavor, &mut words, kernel.process.signer.as_ref())?;
    let mut body = in_count.to_le_bytes().to_vec();
    for word in words {
        body.extend(word.to_le_bytes());
    }
    Ok(Reply::Success(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_constraints_round_trip_through_host_nanoseconds() {
        // The kernel's bounds fall on whole microseconds.
        assert_eq!(host_time(1_200), Some(50_000));
        assert_eq!(host_time(1_200_000), Some(50_000_000));
        for value in [1, 2, 3, 1_201, 999_999, 240_000, 103_079_215] {
            assert_eq!(ticks(host_time(value).unwrap()), value);
        }
        // The release defaults, half the 10 ms quantum and the quantum.
        assert_eq!(ticks(5_000_000), 120_000);
        assert_eq!(ticks(10_000_000), 240_000);
        assert_eq!(host_time(u32::MAX), None);
    }

    #[test]
    fn a_thread_state_converts_unchanged_without_user_jop() {
        let mut words = vec![0u32; 68];
        words[64] = 0x4000;
        words[67] = 0;
        control::convert_state(6, &mut words, None).unwrap();
        // The flags say the state carries no pointer authentication.
        assert_eq!(words[67], 1);
        assert_eq!(words[64], 0x4000);
        // Another flavor passes as given.
        let mut other = vec![7u32; 4];
        control::convert_state(7, &mut other, None).unwrap();
        assert_eq!(other, vec![7; 4]);
    }
}
