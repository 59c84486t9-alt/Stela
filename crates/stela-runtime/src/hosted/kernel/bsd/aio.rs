//! Asynchronous I/O (`bsd/kern/kern_aio.c`), with the 26A434 kernel's
//! additions: `aio_readv` and `aio_writev` (numbers 246 and 247), the
//! vectored `lio_listio` opcodes `LIO_READV` (3) and `LIO_WRITEV` (4), a
//! completing `LIO_NOP`, lists of 32 requests, `O_APPEND` writes, and a
//! list-wide `SIGEV_KEVENT` notification (filter -19). The x86-64 host has
//! none of these, and its own queue answers `aio_error`, `aio_return`,
//! `aio_suspend` and `aio_cancel` only for the requests it queued, so the
//! whole family is modeled here and the host only performs each transfer.
//!
//! Each contract is the 26A434 kernel's, read from its handlers (where
//! they keep xnu-12377's, its source):
//!
//! - A request is the user `aiocb` copied in at submission (EFAULT), its
//!   opcode mapped for a list (0 `LIO_NOP`, 1 read, 2 write, 3 and 4 the
//!   vectored ones, others EINVAL), then validated: a transfer needs
//!   `aio_nbytes` at most `INT_MAX`, a buffer and a non-negative offset, a
//!   vectored one 1 to `UIO_MAXIOV` vectors at `aio_buf`; `SIGEV_SIGNAL`
//!   needs a catchable signal, `SIGEV_KEVENT` a descriptor up to
//!   `kern.maxfilesperproc`, and any other notification is EINVAL; the
//!   descriptor must be open with the access the operation needs (EBADF),
//!   a plain write descriptor must not be write-guarded (the guard
//!   exception) and every descriptor must be a vnode (ESPIPE).
//! - Queueing fails with EAGAIN past `kern.aioprocmax` requests of the
//!   process or `kern.aiomax` in all, for an `aiocb` already queued or
//!   done, or while the process exits. The system-wide count is this
//!   process's: hosted processes share no kernel. Requests run in queue
//!   order on up to 16 worker threads of the process (the per-process
//!   AIO workqueue), each a host `pread`, `pwrite`, `preadv`, `pwritev`
//!   (or `write`/`writev` for an `O_APPEND` descriptor), `fsync` or
//!   `fdatasync` at the request's offset, whose result is the request's
//!   return value; a failed transfer returns 0 with its error, as the
//!   kernel's read and write paths leave `uu_rval`. An `aio_fsync` with
//!   `O_SYNC` waits until it is the process's oldest request.
//! - Completion moves a request to the done queue, counts down its list
//!   and notifies: `SIGEV_SIGNAL` sends the signal to the process (for a
//!   list, at its last completion), `SIGEV_KEVENT` activates the request's
//!   `EVFILT_AIO` knote if it completed rather than being cancelled, and a
//!   list-wide kevent activates every member's knote when the list is
//!   done. A knote reports the request's error and return value in
//!   `ext[0]` and `ext[1]` and, when delivered, frees the request, which
//!   `aio_return` never does for a kevent-notified one.
//! - `aio_cancel` (whose fd 0x80414c4c names every descriptor) cancels
//!   queued requests with ECANCELED and reports `AIO_CANCELED`,
//!   `AIO_NOTCANCELED` for a running one, `AIO_ALLDONE`, or EBADF when
//!   nothing matches; a raw disk descriptor is always `AIO_NOTCANCELED`.
//!   Closing a descriptor (`_aio_close`) cancels its queued requests and
//!   waits for its running ones; the process's end (`_aio_exit`) cancels
//!   every queued request without notifying and waits for the rest. An
//!   exec (`_aio_exec`) is the host's: its point of no return ends the
//!   workers, which run no request past it, and waits for a running one.
//!   A fork child has no requests (`forkproc`).
//!
//! A knote the kernel registers is carried on the host by an
//! `EVFILT_MACHPORT` knote of a port only this module holds, on the same
//! kqueue and with the same user data: completion sends the port a
//! message, and [`Aio::events_to_guest`] presents the delivered event as
//! the arm64 kernel's, so a kqueue's waiters, its readability and
//! `EV_ONESHOT` behave as the kernel's knote's.
use super::{
    Call, EAGAIN, EFAULT, EINVAL, EPERM, Kernel, Outcome, forward, number_of, timer::Layout,
};
use crate::hosted::memory::{self, PAGE_BYTES};
use crate::hosted::threads::{lock, try_lock};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

pub(super) const CALLS: &[&str] = &[
    "aio_read",
    "aio_write",
    "aio_fsync",
    "lio_listio",
    "aio_error",
    "aio_return",
    "aio_suspend",
    "aio_suspend_nocancel",
    "aio_cancel",
];

/// The forwarded calls that close a descriptor, which first wait for its
/// asynchronous I/O (`fp_close_and_unlock` calling `_aio_close`).
pub(super) const CLOSING: &[&str] = &[
    "sys_close",
    "sys_close_nocancel",
    "guarded_close_np",
    "sys_dup2",
];

/// The model the forwarding of [`CLOSING`] follows.
pub(crate) const OVERLAY: &str = "a descriptor's queued asynchronous I/O is cancelled and its \
     running I/O waited for before it closes";

const EBADF: u64 = 9;
const EINTR: u64 = 4;
const ENOMEM: u64 = 12;
const ESPIPE: u64 = 29;
const EINPROGRESS: u64 = 36;
const ENOTSUP: u64 = 45;
const ETIMEDOUT: u64 = 60;
const ECANCELED: u64 = 89;
/// `aio_cancel` results.
const AIO_ALLDONE: u64 = 1;
const AIO_CANCELED: u64 = 2;
const AIO_NOTCANCELED: u64 = 4;
/// `lio_listio` modes and opcodes.
const LIO_NOWAIT: u64 = 1;
const LIO_WAIT: u64 = 2;
const LIO_NOP: i32 = 0;
const LIO_READ: i32 = 1;
const LIO_WRITE: i32 = 2;
const LIO_READV: i32 = 3;
const LIO_WRITEV: i32 = 4;
/// `AIO_LISTIO_MAX` in 26A434 (xnu-12377: 16).
const LISTIO_MAX: u64 = 32;
/// `sigev_notify` values.
const SIGEV_NONE: i32 = 0;
const SIGEV_SIGNAL: i32 = 1;
const SIGEV_KEVENT: i32 = 4;
const NSIG: i32 = 32;
const SIGKILL: i32 = 9;
const SIGSTOP: i32 = 17;
/// `aio_fsync` operations; 0 is `O_SYNC` for Panther binaries.
const O_SYNC: u64 = 0x80;
const O_DSYNC: u64 = 0x40_0000;
/// The 26A434 `aio_cancel` descriptor that names every descriptor.
const ALL_DESCRIPTORS: i32 = 0x8041_4c4c_u32 as i32;
const INT_MAX: u64 = i32::MAX as u64;
const UIO_MAXIOV: u64 = 1024;
/// `WORKQUEUE_AIO_MAXTHREADS`, and how long an idle one waits for work
/// (`WQ_REDUCE_POOL_WINDOW_USECS`).
const MAX_WORKERS: usize = 16;
const IDLE: Duration = Duration::from_secs(5);
/// `struct user64_aiocb` and `struct user64_sigevent` fields.
const AIOCB_BYTES: usize = 80;
/// `struct user64_iovec`.
const IOVEC_BYTES: usize = 16;
const AIO_FILDES: usize = 0;
const AIO_OFFSET: usize = 8;
const AIO_BUF: usize = 16;
const AIO_NBYTES: usize = 24;
const AIO_SIGEVENT: usize = 40;
const AIO_LIO_OPCODE: usize = 72;
const SIGEVENT_BYTES: usize = 32;
const SIGEV_NOTIFY: usize = 0;
const SIGEV_SIGNO: usize = 4;
const SIGEV_VALUE: usize = 8;
/// `fcntl` access flags.
const F_GETFL: u64 = 3;
const O_ACCMODE: u64 = 3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_APPEND: u64 = 0x8;
const O_EXEC: u64 = 0x4000_0000;
/// The kevent filters and flags the kernel registers, and the carrier's.
const EVFILT_AIO: i16 = -3;
const EVFILT_MACHPORT: i16 = -8;
/// The 26A434 list filter (`EVFILT_SYSCOUNT` grew past xnu-12377's 18).
const EVFILT_LIST: i16 = -19;
const EV_ADD: u16 = 0x1;
const EV_DELETE: u16 = 0x2;
const EV_ENABLE: u16 = 0x4;
const EV_ONESHOT: u16 = 0x10;
const EV_CLEAR: u16 = 0x20;
const EV_ERROR: u16 = 0x4000;
/// The flags `aio_register_kevent` registers with, less `EV_KERNEL`,
/// which the filter's attach clears.
const KNOTE_FLAGS: u16 = EV_ADD | EV_ENABLE | EV_CLEAR | EV_ONESHOT;
/// The activation hint `KNOTE` passes, which an `EV_CLEAR` knote reports
/// in `fflags`.
const KNOTE_HINT: u32 = 1;
/// `struct kevent64_s`, the carrier's registration.
const KEVENT64_BYTES: usize = 48;
/// `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`: `struct
/// vnode_fdinfowithpath` and its fields.
const PROC_PIDFDVNODEPATHINFO: i32 = 2;
const VNODE_PATH_INFO_BYTES: usize = 1200;
const FILE_GUARD_FLAGS: usize = 20;
const VNODE_MODE: usize = 28;
const VNODE_PATH: usize = 176;
const PROC_FI_GUARD_CLOSE: u32 = 1 << 0;
const PROC_FI_GUARD_DUP: u32 = 1 << 1;
const S_IFMT: u16 = 0o170_000;
const S_IFCHR: u16 = 0o020_000;
/// Mach constants for the carrier ports and the waiters' semaphores.
const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;
const MACH_MSG_TYPE_COPY_SEND: u32 = 19;
const MACH_SEND_MSG: i32 = 1;
const MACH_SEND_TIMEOUT: i32 = 0x10;
const SYNC_POLICY_FIFO: i32 = 0;

#[allow(non_upper_case_globals)]
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_port_allocate(task: u32, right: u32, name: *mut u32) -> i32;
    fn mach_port_insert_right(task: u32, name: u32, right: u32, kind: u32) -> i32;
    fn mach_port_destruct(task: u32, name: u32, send_delta: i32, guard: u64) -> i32;
    fn mach_msg(
        message: *mut u8,
        option: i32,
        send_size: u32,
        receive_size: u32,
        receive_name: u32,
        timeout: u32,
        notify: u32,
    ) -> i32;
    fn semaphore_create(task: u32, semaphore: *mut u32, policy: i32, value: i32) -> i32;
    fn semaphore_destroy(task: u32, semaphore: u32) -> i32;
    fn semaphore_signal(semaphore: u32) -> i32;
}

/// `mach_msg_header_t`.
#[repr(C)]
struct MessageHeader {
    bits: u32,
    size: u32,
    remote: u32,
    local: u32,
    voucher: u32,
    id: i32,
}

fn task() -> u32 {
    // SAFETY: the host's task port name, set before `main`.
    unsafe { mach_task_self_ }
}

/// The host call `name` of the pinned catalog: X0, or the errno.
fn host(name: &str, arguments: &[u64]) -> std::result::Result<u64, u64> {
    let returned = forward::bsd(number_of(name), arguments);
    if returned.carry {
        Err(returned.rax)
    } else {
        Ok(returned.rax)
    }
}

/// The kernel's AIO limits: the host's, which the guest's `kern.*` are.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// `aio_max_requests` (`kern.aiomax`).
    max: usize,
    /// `aio_max_requests_per_process` (`kern.aioprocmax`).
    per_process: usize,
    /// `maxfilesperproc`.
    files: i64,
}

fn sysctl(name: &core::ffi::CStr, default: i32) -> i32 {
    let mut value = 0i32;
    let mut length = size_of::<i32>();
    // SAFETY: an int-sized value into this frame.
    let read = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut length,
            core::ptr::null_mut(),
            0,
        )
    };
    if read == 0 { value } else { default }
}

fn limits() -> Limits {
    static LIMITS: OnceLock<Limits> = OnceLock::new();
    *LIMITS.get_or_init(|| Limits {
        max: sysctl(c"kern.aiomax", 90).max(0) as usize,
        per_process: sysctl(c"kern.aioprocmax", 16).max(0) as usize,
        files: i64::from(sysctl(c"kern.maxfilesperproc", 10240)),
    })
}

/// What a request does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Read,
    Write,
    ReadVector,
    WriteVector,
    /// `aio_fsync(O_SYNC)`.
    Sync,
    /// `aio_fsync(O_DSYNC)`.
    DataSync,
    /// `LIO_NOP`.
    Nothing,
}

impl Operation {
    fn reads(self) -> bool {
        matches!(self, Self::Read | Self::ReadVector)
    }

    fn writes(self) -> bool {
        matches!(self, Self::Write | Self::WriteVector)
    }

    /// A list opcode's operation.
    fn of_opcode(opcode: i32) -> Option<Self> {
        Some(match opcode {
            LIO_NOP => Self::Nothing,
            LIO_READ => Self::Read,
            LIO_WRITE => Self::Write,
            LIO_READV => Self::ReadVector,
            LIO_WRITEV => Self::WriteVector,
            _ => return None,
        })
    }
}

/// `struct user_sigevent`: what completion notifies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Notification {
    notify: i32,
    signal: i32,
    value: u64,
}

impl Notification {
    fn decode(bytes: &[u8]) -> Self {
        Self {
            notify: i32::from_le_bytes(bytes[SIGEV_NOTIFY..SIGEV_NOTIFY + 4].try_into().unwrap()),
            signal: i32::from_le_bytes(bytes[SIGEV_SIGNO..SIGEV_SIGNO + 4].try_into().unwrap()),
            value: u64::from_le_bytes(bytes[SIGEV_VALUE..SIGEV_VALUE + 8].try_into().unwrap()),
        }
    }

    /// `aio_sigev_validate`.
    fn validate(self, limits: &Limits) -> std::result::Result<(), u64> {
        match self.notify {
            SIGEV_NONE => Ok(()),
            SIGEV_SIGNAL
                if (1..NSIG).contains(&self.signal)
                    && self.signal != SIGKILL
                    && self.signal != SIGSTOP =>
            {
                Ok(())
            }
            SIGEV_KEVENT if self.signal >= 1 && i64::from(self.signal) <= limits.files => Ok(()),
            _ => Err(EINVAL),
        }
    }
}

/// The transfer a worker performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Request {
    fd: i32,
    operation: Operation,
    offset: i64,
    buffer: u64,
    bytes: u64,
    /// The descriptor was `O_APPEND` at submission: written at its end.
    append: bool,
}

impl Request {
    /// The guest pages the transfer reaches: its buffer, or its vector
    /// list and each vector's buffer.
    fn pages(self) -> Vec<u64> {
        let span = |start: u64, length: u64| {
            let first = start & !(PAGE_BYTES - 1);
            let end = start.saturating_add(length);
            (first..end).step_by(PAGE_BYTES as usize)
        };
        match self.operation {
            Operation::Read | Operation::Write => span(self.buffer, self.bytes).collect(),
            Operation::ReadVector | Operation::WriteVector => {
                let list = self.bytes * IOVEC_BYTES as u64;
                let mut pages: Vec<u64> = span(self.buffer, list).collect();
                if let Some(vectors) = memory::read(self.buffer, list as usize) {
                    for vector in vectors.as_chunks::<IOVEC_BYTES>().0 {
                        pages.extend(span(u64_at(vector, 0), u64_at(vector, 8)));
                    }
                }
                pages
            }
            Operation::Sync | Operation::DataSync | Operation::Nothing => Vec::new(),
        }
    }

    /// Perform the transfer on the host: the return value and error.
    fn perform(self) -> (i64, u64) {
        let fd = i64::from(self.fd) as u64;
        let at = self.offset as u64;
        let result = match self.operation {
            Operation::Read => host("pread", &[fd, self.buffer, self.bytes, at]),
            Operation::Write if self.append => host("write", &[fd, self.buffer, self.bytes]),
            Operation::Write => host("pwrite", &[fd, self.buffer, self.bytes, at]),
            Operation::ReadVector => host("sys_preadv", &[fd, self.buffer, self.bytes, at]),
            Operation::WriteVector if self.append => host("writev", &[fd, self.buffer, self.bytes]),
            Operation::WriteVector => host("sys_pwritev", &[fd, self.buffer, self.bytes, at]),
            Operation::Sync => host("fsync", &[fd]),
            Operation::DataSync => host("fdatasync", &[fd]),
            Operation::Nothing => Ok(0),
        };
        match result {
            Ok(count) => (count as i64, 0),
            Err(errno) => (0, errno),
        }
    }
}

/// A kevent the kernel registered, carried on the host by a port's
/// `EVFILT_MACHPORT` knote on the same kqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Carrier {
    port: u32,
    kqueue: i32,
    /// The guest deleted the knote: completion no longer activates it.
    deleted: bool,
}

/// `aio_workq_entry`.
#[derive(Debug)]
struct Entry {
    id: u64,
    /// `uaiocbp`.
    address: u64,
    request: Request,
    notification: Notification,
    /// The list (its leader's id) whose pending count the entry holds.
    list: Option<u64>,
    started: bool,
    completed: bool,
    close_wait: bool,
    exit_wait: bool,
    returned: i64,
    error: u64,
    /// Its `EVFILT_AIO` knote.
    carrier: Option<Carrier>,
    /// Its list-wide knote.
    list_carrier: Option<Carrier>,
}

impl Entry {
    fn carriers(&self) -> [Option<Carrier>; 2] {
        [self.carrier, self.list_carrier]
    }
}

/// A `lio_listio` batch: its leader's `lio_pending`, `AIO_LIO_WAIT` and
/// list-wide kevent.
#[derive(Debug, Default)]
struct List {
    pending: u32,
    waiting: bool,
    kevent: bool,
}

/// Why a cancellation scans the queues (`do_aio_cancel_locked`'s reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    Cancel,
    /// `AIO_CLOSE_WAIT`.
    Close,
    /// `AIO_EXIT_WAIT`.
    Exit,
}

#[derive(Debug, Default)]
pub(super) struct State {
    next: u64,
    /// `p_aio_activeq`: queued and running, in submission order.
    active: Vec<Entry>,
    /// `p_aio_doneq`.
    done: Vec<Entry>,
    /// The workqueue, by entry id.
    queue: VecDeque<u64>,
    lists: BTreeMap<u64, List>,
    workers: usize,
    idle: usize,
    /// `_aio_exit` began: nothing more is queued.
    exiting: bool,
    /// The semaphores of threads waiting interruptibly.
    waiters: Vec<u32>,
    /// Carrier port → (entry id, the filter the guest sees).
    carriers: BTreeMap<u32, (u64, i16)>,
}

/// The process's asynchronous I/O.
#[derive(Debug, Default)]
pub(crate) struct Aio {
    state: Mutex<State>,
    /// Signalled at every completion and for idle workers.
    changed: Condvar,
    /// Requests on either queue, read without the lock by `close`.
    extant: AtomicUsize,
    /// Live carriers, read without the lock by every `kevent`.
    carried: AtomicUsize,
}

/// What a guest's kevent change became on the host, to restore an
/// `EV_ERROR` echo of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Rewrite {
    pub(super) host: (u64, i16),
    guest: (u64, i16),
}

/// How an interruptible wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waited {
    Woken,
    TimedOut,
    Interrupted,
}

/// The descriptor's vnode as `proc_pidfdinfo` describes it, or `None`
/// for a descriptor that is no vnode's.
struct Vnode {
    guards: u32,
    character: bool,
    name: Vec<u8>,
}

fn vnode(fd: i32) -> Option<Vnode> {
    let mut info = vec![0u8; VNODE_PATH_INFO_BYTES];
    // SAFETY: a buffer of the flavor's size.
    let read = unsafe {
        libc::proc_pidfdinfo(
            libc::getpid(),
            fd,
            PROC_PIDFDVNODEPATHINFO,
            info.as_mut_ptr().cast(),
            VNODE_PATH_INFO_BYTES as i32,
        )
    };
    if read != VNODE_PATH_INFO_BYTES as i32 {
        return None;
    }
    let guards = u32::from_le_bytes(
        info[FILE_GUARD_FLAGS..FILE_GUARD_FLAGS + 4]
            .try_into()
            .unwrap(),
    );
    let mode = u16::from_le_bytes([info[VNODE_MODE], info[VNODE_MODE + 1]]);
    let path = &info[VNODE_PATH..];
    let path = &path[..path
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(path.len())];
    let name = path.rsplit(|&byte| byte == b'/').next().unwrap_or_default();
    Some(Vnode {
        guards,
        character: mode & S_IFMT == S_IFCHR,
        name: name.to_vec(),
    })
}

/// The descriptor's status flags, or EBADF.
fn status_flags(fd: i32) -> std::result::Result<u64, u64> {
    host("sys_fcntl", &[i64::from(fd) as u64, F_GETFL]).map_err(|_| EBADF)
}

/// Whether the status flags give `FREAD` or `FWRITE`.
fn readable(flags: u64) -> bool {
    flags & O_EXEC == 0 && matches!(flags & O_ACCMODE, O_RDONLY | O_RDWR)
}

fn writable(flags: u64) -> bool {
    flags & O_EXEC == 0 && matches!(flags & O_ACCMODE, O_WRONLY | O_RDWR)
}

/// The little-endian words of `bytes`.
fn words(bytes: &[u8]) -> impl Iterator<Item = u64> + '_ {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|word| u64::from_le_bytes(*word))
}

/// Free requests that were never queued, with their knotes.
fn discard(entries: Vec<Entry>) {
    for carrier in entries.iter().flat_map(Entry::carriers).flatten() {
        unregister(carrier);
    }
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn i32_at(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// `aio_create_queue_entry` and `aio_validate`: the request the user
/// `aiocb` at `address` makes, `operation` for a single call or its
/// opcode's for a list; or the errno.
fn validate(
    address: u64,
    operation: Option<Operation>,
    limits: &Limits,
) -> std::result::Result<(Request, Notification), u64> {
    let block = memory::read(address, AIOCB_BYTES).ok_or(EFAULT)?;
    let operation = match operation {
        Some(operation) => operation,
        None => Operation::of_opcode(i32_at(&block, AIO_LIO_OPCODE)).ok_or(EINVAL)?,
    };
    let fd = i32_at(&block, AIO_FILDES);
    let offset = u64_at(&block, AIO_OFFSET) as i64;
    let buffer = u64_at(&block, AIO_BUF);
    let bytes = u64_at(&block, AIO_NBYTES);
    match operation {
        Operation::Read | Operation::Write if bytes > INT_MAX || buffer == 0 || offset < 0 => {
            return Err(EINVAL);
        }
        Operation::ReadVector | Operation::WriteVector
            if !(1..=UIO_MAXIOV).contains(&bytes) || buffer == 0 || offset < 0 =>
        {
            return Err(EINVAL);
        }
        _ => {}
    }
    let notification = Notification::decode(&block[AIO_SIGEVENT..AIO_SIGEVENT + SIGEVENT_BYTES]);
    notification.validate(limits)?;
    let flags = status_flags(fd)?;
    let access = match operation {
        Operation::Nothing => true,
        operation if operation.reads() => readable(flags),
        _ => writable(flags),
    };
    if !access {
        return Err(EBADF);
    }
    // Guards apply to vnodes alone, so a guarded descriptor passes the
    // type check, which `proc_pidfdinfo` makes first.
    let Some(node) = vnode(fd) else {
        return Err(ESPIPE);
    };
    // Every guard includes `GUARD_DUP`, and only a write-guarded
    // descriptor refuses an empty write: with the guard exception
    // `fp_guard_exception` raises, and EPERM.
    if operation == Operation::Write && node.guards & PROC_FI_GUARD_DUP != 0 {
        let empty = [0u8; 1];
        if host("write", &[i64::from(fd) as u64, empty.as_ptr() as u64, 0]) == Err(EPERM) {
            return Err(EPERM);
        }
    }
    let request = Request {
        fd,
        operation,
        offset,
        buffer,
        bytes,
        append: operation.writes() && flags & O_APPEND != 0,
    };
    Ok((request, notification))
}

/// Make the carrier of a knote with user data `value` on the kqueue
/// `kqueue`: a fresh receive right with a send right, registered there.
fn register(kqueue: i32, value: u64) -> std::result::Result<Carrier, u64> {
    let mut port = 0u32;
    // SAFETY: a new right in this task, named into this frame.
    let allocated = unsafe {
        mach_port_allocate(task(), MACH_PORT_RIGHT_RECEIVE, &raw mut port) == 0
            && mach_port_insert_right(task(), port, port, MACH_MSG_TYPE_MAKE_SEND) == 0
    };
    if !allocated {
        return Err(ENOMEM);
    }
    let carrier = Carrier {
        port,
        kqueue,
        deleted: false,
    };
    if let Err(errno) = change(carrier, KNOTE_FLAGS, value) {
        destroy(port);
        return Err(errno);
    }
    Ok(carrier)
}

/// Apply `flags` to the carrier's knote.
fn change(carrier: Carrier, flags: u16, value: u64) -> std::result::Result<(), u64> {
    let mut event = [0u8; KEVENT64_BYTES];
    event[..8].copy_from_slice(&u64::from(carrier.port).to_le_bytes());
    event[8..10].copy_from_slice(&EVFILT_MACHPORT.to_le_bytes());
    event[10..12].copy_from_slice(&flags.to_le_bytes());
    event[24..32].copy_from_slice(&value.to_le_bytes());
    host(
        "kevent64",
        &[
            i64::from(carrier.kqueue) as u64,
            event.as_ptr() as u64,
            1,
            0,
            0,
            0,
            0,
        ],
    )
    .map(drop)
}

/// Remove a carrier whose knote was never activated.
fn unregister(carrier: Carrier) {
    let _ = change(carrier, EV_DELETE, 0);
    destroy(carrier.port);
}

fn destroy(port: u32) {
    // SAFETY: the receive and send rights `register` made.
    unsafe { mach_port_destruct(task(), port, -1, 0) };
}

/// Activate a carrier's knote: a message on its port.
fn trigger(carrier: Carrier) {
    if carrier.deleted {
        return;
    }
    let mut message = MessageHeader {
        bits: MACH_MSG_TYPE_COPY_SEND,
        size: size_of::<MessageHeader>() as u32,
        remote: carrier.port,
        local: 0,
        voucher: 0,
        id: 0,
    };
    // SAFETY: a header-only message to the carrier's own send right.
    unsafe {
        mach_msg(
            (&raw mut message).cast(),
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            message.size,
            0,
            0,
            0,
            0,
        )
    };
}

/// Send `signal` to this process, as `psignal` from one of its threads.
fn signal_process(signal: i32) {
    // SAFETY: a signal to this process.
    unsafe { libc::kill(libc::getpid(), signal) };
}

impl State {
    fn total(&self) -> usize {
        self.active.len() + self.done.len()
    }

    fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.active.iter().chain(self.done.iter())
    }

    fn entry_mut(&mut self, id: u64) -> Option<&mut Entry> {
        self.active
            .iter_mut()
            .chain(self.done.iter_mut())
            .find(|entry| entry.id == id)
    }

    /// `is_already_queued`.
    fn queued(&self, address: u64) -> bool {
        self.entries().any(|entry| entry.address == address)
    }

    /// A kernel knote already registered for `address` on `kqueue`, which
    /// a second registration would touch (ENOTSUP): the request's own, or
    /// with `list` its list's.
    fn knote_exists(&self, address: u64, kqueue: i32, list: bool) -> bool {
        self.entries().any(|entry| {
            let carrier = if list {
                entry.list_carrier
            } else {
                entry.carrier
            };
            entry.address == address
                && carrier.is_some_and(|carrier| carrier.kqueue == kqueue && !carrier.deleted)
        })
    }

    fn new_entry(&mut self, address: u64, request: Request, notification: Notification) -> Entry {
        self.next += 1;
        Entry {
            id: self.next,
            address,
            request,
            notification,
            list: None,
            started: false,
            completed: false,
            close_wait: false,
            exit_wait: false,
            returned: 0,
            error: 0,
            carrier: None,
            list_carrier: None,
        }
    }

    /// Note the carriers of the entry `id` so that delivered events find
    /// it.
    fn carry(&mut self, id: u64, carriers: [Option<Carrier>; 2], carried: &AtomicUsize) {
        for (carrier, filter) in carriers.into_iter().zip([EVFILT_AIO, EVFILT_LIST]) {
            if let Some(carrier) = carrier {
                self.carriers.insert(carrier.port, (id, filter));
                carried.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// Forget a freed entry's carriers, destroying their ports.
    fn release(&mut self, entry: &Entry, carried: &AtomicUsize) {
        for carrier in entry.carriers().into_iter().flatten() {
            if self.carriers.remove(&carrier.port).is_some() {
                carried.fetch_sub(1, Ordering::SeqCst);
                destroy(carrier.port);
            }
        }
    }

    /// The 26A434 list-wide kevent of a `LIO_NOWAIT` list: every request
    /// counts in the list from the start and gets a knote of the list
    /// filter on the list's kqueue; a request with a knote of its own is
    /// EINVAL, and a list kqueue that is no kqueue EBADF.
    fn carry_list(
        &mut self,
        entries: &mut [Entry],
        leader: u64,
        notification: Notification,
    ) -> std::result::Result<(), u64> {
        let kqueue = notification.signal;
        // An empty `kevent64` is a kqueue's lookup alone.
        host("kevent64", &[i64::from(kqueue) as u64, 0, 0, 0, 0, 0, 0]).map_err(|_| EBADF)?;
        for index in 0..entries.len() {
            self.join(&mut entries[index], Some(leader));
            let address = entries[index].address;
            if entries[index].carrier.is_some() {
                return Err(EINVAL);
            }
            let duplicate = self.knote_exists(address, kqueue, true)
                || entries[..index]
                    .iter()
                    .any(|other| other.address == address);
            if duplicate {
                return Err(ENOTSUP);
            }
            entries[index].list_carrier = Some(register(kqueue, notification.value)?);
        }
        Ok(())
    }

    /// `aio_try_enqueue_work_locked`: queue `entry`, counting it in
    /// `list`, or give it back.
    fn try_enqueue(
        &mut self,
        mut entry: Entry,
        list: Option<u64>,
        limits: &Limits,
        carried: &AtomicUsize,
    ) -> std::result::Result<(), Box<Entry>> {
        let total = self.total();
        if self.exiting
            || total >= limits.per_process
            || total >= limits.max
            || self.queued(entry.address)
        {
            return Err(Box::new(entry));
        }
        self.join(&mut entry, list);
        self.carry(entry.id, entry.carriers(), carried);
        self.queue.push_back(entry.id);
        self.active.push(entry);
        Ok(())
    }

    /// Count `entry` in `list` once.
    fn join(&mut self, entry: &mut Entry, list: Option<u64>) {
        if let Some(key) = list
            && entry.list.is_none()
            && let Some(record) = self.lists.get_mut(&key)
        {
            record.pending += 1;
            entry.list = Some(key);
        }
    }

    /// `do_aio_completion_and_unlock`: move active entry `id` to the done
    /// queue and notify.
    fn complete(&mut self, id: u64, cancelled: bool) {
        let Some(index) = self.active.iter().position(|entry| entry.id == id) else {
            return;
        };
        let mut entry = self.active.remove(index);
        entry.completed = !cancelled;
        let mut pending = 0;
        let mut list_done = None;
        if let Some(key) = entry.list
            && let Some(list) = self.lists.get_mut(&key)
        {
            list.pending = list.pending.saturating_sub(1);
            pending = list.pending;
            if pending == 0 {
                if list.kevent && !list.waiting {
                    list_done = Some(key);
                }
                if !list.waiting {
                    self.lists.remove(&key);
                }
            }
            if entry.list_carrier.is_none() {
                entry.list = None;
            }
        }
        if !entry.exit_wait {
            match entry.notification.notify {
                SIGEV_SIGNAL if pending == 0 => signal_process(entry.notification.signal),
                // `filt_aioevent` activates a completed request only.
                SIGEV_KEVENT if entry.completed => {
                    if let Some(carrier) = entry.carrier {
                        trigger(carrier);
                    }
                }
                _ => {}
            }
        }
        self.done.push(entry);
        if let Some(key) = list_done {
            for entry in self.entries() {
                if entry.list == Some(key)
                    && let Some(carrier) = entry.list_carrier
                {
                    trigger(carrier);
                }
            }
        }
        self.wake();
    }

    /// Wake the threads waiting interruptibly.
    fn wake(&self) {
        for &semaphore in &self.waiters {
            // SAFETY: a semaphore its waiter destroys only once removed.
            unsafe { semaphore_signal(semaphore) };
        }
    }

    /// `do_aio_cancel_locked`: cancel what matches `fd` (`None`: every
    /// descriptor) and `address` (0: every request), marking it with
    /// `reason`. -1 when nothing matched, else the `aio_cancel` result.
    fn cancel(&mut self, fd: Option<i32>, address: u64, reason: Reason) -> i64 {
        let matches = |entry: &Entry| {
            reason == Reason::Exit
                || (fd.is_none_or(|fd| entry.request.fd == fd)
                    && (address == 0 || entry.address == address))
        };
        'again: loop {
            let mut result = -1;
            let ids: Vec<u64> = self.active.iter().map(|entry| entry.id).collect();
            for id in ids {
                let Some(entry) = self.active.iter_mut().find(|entry| entry.id == id) else {
                    continue;
                };
                if !matches(entry) {
                    continue;
                }
                match reason {
                    Reason::Close => entry.close_wait = true,
                    Reason::Exit => entry.exit_wait = true,
                    Reason::Cancel => {}
                }
                if !entry.started {
                    entry.error = ECANCELED;
                    entry.returned = -1;
                    self.queue.retain(|&queued| queued != id);
                    self.complete(id, true);
                    if address == 0 {
                        continue 'again;
                    }
                    return AIO_CANCELED as i64;
                }
                result = AIO_NOTCANCELED as i64;
                if address != 0 {
                    return result;
                }
            }
            if result != -1 {
                return result;
            }
            for entry in &self.done {
                if matches(entry) {
                    result = AIO_ALLDONE as i64;
                    if address != 0 {
                        return result;
                    }
                }
            }
            return result;
        }
    }

    /// The next request a worker may start: the oldest queued one, but an
    /// `O_SYNC` fsync only once it is the process's oldest request
    /// (`aio_delay_fsync_request`), unless the process is exiting.
    fn take_work(&mut self) -> Option<(u64, Request)> {
        let oldest = self.active.first().map(|entry| entry.id);
        let exiting = self.exiting;
        let active = &self.active;
        let position = self.queue.iter().position(|&id| {
            active
                .iter()
                .find(|entry| entry.id == id)
                .is_some_and(|entry| {
                    entry.request.operation != Operation::Sync || exiting || Some(id) == oldest
                })
        })?;
        let id = self.queue.remove(position)?;
        let entry = self.active.iter_mut().find(|entry| entry.id == id)?;
        entry.started = true;
        Some((id, entry.request))
    }
}

impl Aio {
    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Recount the entries after a change of the queues.
    fn recount(&self, state: &State) {
        self.extant.store(state.total(), Ordering::SeqCst);
    }

    /// Give queued work a worker: an idle one, or a new one up to the
    /// workqueue's limit.
    fn dispatch(self: &Arc<Self>, state: &mut State) {
        if state.queue.is_empty() {
            return;
        }
        if state.idle > 0 {
            self.changed.notify_all();
            return;
        }
        if state.workers >= MAX_WORKERS {
            return;
        }
        state.workers += 1;
        let aio = Arc::clone(self);
        // Workers run no guest code: every signal stays blocked, so the
        // host routes the process's signals to a guest thread.
        let spawned = super::signal::host::without_signals(|| {
            std::thread::Builder::new()
                .name("stela-aio".into())
                .spawn(move || aio.work())
        });
        if spawned.is_err() {
            state.workers -= 1;
        }
    }

    /// A worker thread: run requests until idle for [`IDLE`].
    fn work(self: Arc<Self>) {
        let mut state = self.state();
        loop {
            if let Some((id, request)) = state.take_work() {
                drop(state);
                let (returned, error) = request.perform();
                state = self.state();
                if let Some(entry) = state.entry_mut(id) {
                    entry.returned = returned;
                    entry.error = error;
                }
                state.complete(id, false);
                self.recount(&state);
                self.changed.notify_all();
                continue;
            }
            state.idle += 1;
            let (next, timeout) = self
                .changed
                .wait_timeout(state, IDLE)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            state.idle -= 1;
            if timeout.timed_out() && state.queue.is_empty() {
                state.workers -= 1;
                return;
            }
        }
    }

    /// Wait, interruptibly (by the calling thread's signal flag
    /// `interrupt`), for a completion or `deadline`, with the state's lock
    /// given up meanwhile.
    fn wait<'a>(
        &'a self,
        interrupt: *const u8,
        mut state: MutexGuard<'a, State>,
        deadline: Option<Instant>,
    ) -> Result<(MutexGuard<'a, State>, Waited)> {
        let mut semaphore = 0u32;
        // SAFETY: a new semaphore of this task, named into this frame.
        if unsafe { semaphore_create(task(), &raw mut semaphore, SYNC_POLICY_FIFO, 0) } != 0 {
            bail!("asynchronous I/O: no semaphore for a waiting thread");
        }
        state.waiters.push(semaphore);
        drop(state);
        let (timed, seconds, nanoseconds) = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                (1, left.as_secs(), u64::from(left.subsec_nanos()))
            }
            None => (0, 0, 0),
        };
        let returned = forward::bsd_interruptible(
            number_of("__semwait_signal"),
            &[u64::from(semaphore), 0, timed, 1, seconds, nanoseconds],
            interrupt,
        );
        let mut state = self.state();
        state.waiters.retain(|&waiter| waiter != semaphore);
        // SAFETY: the semaphore this call made, no longer listed.
        unsafe { semaphore_destroy(task(), semaphore) };
        let waited = match returned {
            forward::Returned { carry: false, .. } => Waited::Woken,
            forward::Returned { rax: ETIMEDOUT, .. } => Waited::TimedOut,
            forward::Returned {
                rax: EINTR | forward::ERESTART,
                ..
            } => Waited::Interrupted,
            forward::Returned { rax, .. } => {
                bail!("asynchronous I/O: waiting for a completion failed with {rax}")
            }
        };
        Ok((state, waited))
    }

    /// `aio_queue_async_request` for `aio_read`, `aio_write`,
    /// `aio_readv`, `aio_writev` and `aio_fsync`; `page_in` makes the
    /// guest pages a request reaches present.
    fn submit(
        self: &Arc<Self>,
        address: u64,
        operation: Operation,
        page_in: &mut PageIn<'_>,
    ) -> Result<Outcome> {
        let limits = limits();
        let (request, notification) = match validate(address, Some(operation), &limits) {
            Ok(validated) => validated,
            Err(errno) => return Ok(Outcome::Error(errno)),
        };
        page_in(&request.pages())?;
        let mut state = self.state();
        let mut entry = state.new_entry(address, request, notification);
        if notification.notify == SIGEV_KEVENT {
            // A second knote for the request touches the first's.
            if state.knote_exists(address, notification.signal, false) {
                return Ok(Outcome::Error(ENOTSUP));
            }
            match register(notification.signal, notification.value) {
                Ok(carrier) => entry.carrier = Some(carrier),
                Err(errno) => return Ok(Outcome::Error(errno)),
            }
        }
        Ok(
            match state.try_enqueue(entry, None, &limits, &self.carried) {
                Ok(()) => {
                    self.recount(&state);
                    self.dispatch(&mut state);
                    Outcome::value(0)
                }
                Err(entry) => {
                    if let Some(carrier) = entry.carrier {
                        unregister(carrier);
                    }
                    Outcome::Error(EAGAIN)
                }
            },
        )
    }

    /// `lio_listio(mode, aiocblist, nent, sigp)`.
    fn list(
        self: &Arc<Self>,
        arguments: [u64; 4],
        interrupt: *const u8,
        page_in: &mut PageIn<'_>,
    ) -> Result<Outcome> {
        let [mode, addresses, count, signal] = arguments;
        let mode = u64::from(mode as u32);
        let count = count as u32 as i32;
        if !matches!(mode, LIO_NOWAIT | LIO_WAIT) || !(1..=LISTIO_MAX as i32).contains(&count) {
            return Ok(Outcome::Error(EINVAL));
        }
        let limits = limits();
        let mut list_notification = Notification::default();
        if signal != 0 {
            let Some(bytes) = memory::read(signal, SIGEVENT_BYTES) else {
                return Ok(Outcome::Error(EAGAIN));
            };
            list_notification = Notification::decode(&bytes);
            if let Err(errno) = list_notification.validate(&limits) {
                return Ok(Outcome::Error(errno));
            }
        }
        let list_kevent = mode == LIO_NOWAIT && list_notification.notify == SIGEV_KEVENT;
        let Some(table) = memory::read(addresses, count as usize * 8) else {
            return Ok(Outcome::Error(EAGAIN));
        };
        let mut entries: Vec<Entry> = Vec::new();
        let mut failure = None;
        for address in words(&table).filter(|&address| address != 0) {
            let (request, notification) = match validate(address, None, &limits) {
                Ok(validated) => validated,
                Err(errno) => {
                    failure = Some(errno);
                    break;
                }
            };
            page_in(&request.pages())?;
            let mut entry = self.state().new_entry(address, request, notification);
            // A list that is waited for notifies nothing per request.
            if mode == LIO_NOWAIT {
                if notification.notify == SIGEV_KEVENT {
                    let kqueue = notification.signal;
                    let duplicate = self.state().knote_exists(address, kqueue, false)
                        || entries.iter().any(|other| {
                            other.address == address
                                && other
                                    .carrier
                                    .is_some_and(|carrier| carrier.kqueue == kqueue)
                        });
                    let registered = if duplicate {
                        Err(ENOTSUP)
                    } else {
                        register(kqueue, notification.value)
                    };
                    match registered {
                        Ok(carrier) => entry.carrier = Some(carrier),
                        Err(errno) => {
                            failure = Some(errno);
                            break;
                        }
                    }
                } else {
                    entry.notification = list_notification;
                }
            }
            entries.push(entry);
        }
        if let Some(errno) = failure {
            discard(entries);
            return Ok(Outcome::Error(errno));
        }
        let Some(leader) = entries.first().map(|entry| entry.id) else {
            return Ok(Outcome::value(0));
        };
        let mut state = self.state();
        state.lists.insert(
            leader,
            List {
                pending: 0,
                waiting: mode == LIO_WAIT,
                kevent: list_kevent,
            },
        );
        if list_kevent && let Err(errno) = state.carry_list(&mut entries, leader, list_notification)
        {
            state.lists.remove(&leader);
            drop(state);
            discard(entries);
            return Ok(Outcome::Error(errno));
        }
        let mut result = 0;
        for entry in entries {
            let kernel_knote = entry.carrier.is_some() || entry.list_carrier.is_some();
            match state.try_enqueue(entry, Some(leader), &limits, &self.carried) {
                Ok(()) => {}
                // 26A434 completes a kevent-notified request it cannot
                // queue with EAGAIN, so that its knote fires.
                Err(mut entry) if kernel_knote => {
                    state.join(&mut entry, Some(leader));
                    entry.error = EAGAIN;
                    entry.returned = -1;
                    entry.started = true;
                    let id = entry.id;
                    state.carry(id, entry.carriers(), &self.carried);
                    state.active.push(*entry);
                    state.complete(id, false);
                }
                Err(_) => result = EAGAIN,
            }
        }
        self.recount(&state);
        self.dispatch(&mut state);
        if mode == LIO_WAIT && result == 0 {
            while state
                .lists
                .get(&leader)
                .is_some_and(|list| list.pending > 0)
            {
                let (next, waited) = self.wait(interrupt, state, None)?;
                state = next;
                if waited == Waited::Interrupted {
                    result = EINTR;
                    break;
                }
            }
        }
        // Completions after the call free the list with its last request.
        if let Some(list) = state.lists.get_mut(&leader) {
            list.waiting = false;
            if list.pending == 0 {
                state.lists.remove(&leader);
            }
        }
        Ok(if result == 0 {
            Outcome::value(0)
        } else {
            Outcome::Error(result)
        })
    }

    /// `aio_error(aiocbp)`.
    fn error(&self, address: u64) -> Outcome {
        let state = self.state();
        if let Some(entry) = state.done.iter().find(|entry| entry.address == address) {
            return Outcome::value(entry.error);
        }
        if state.active.iter().any(|entry| entry.address == address) {
            return Outcome::value(EINPROGRESS);
        }
        Outcome::Error(EINVAL)
    }

    /// `aio_return(aiocbp)`: a done request not notified by kevent is
    /// freed and returns its value, or its error when the value is -1.
    fn reap(&self, address: u64) -> Outcome {
        let mut state = self.state();
        if let Some(index) = state
            .done
            .iter()
            .position(|entry| entry.address == address && entry.notification.notify != SIGEV_KEVENT)
        {
            let entry = state.done.remove(index);
            state.release(&entry, &self.carried);
            self.recount(&state);
            return if entry.returned == -1 {
                Outcome::Error(entry.error)
            } else {
                Outcome::value(entry.returned as u64)
            };
        }
        if state.active.iter().any(|entry| entry.address == address) {
            return Outcome::Error(EINPROGRESS);
        }
        Outcome::Error(EINVAL)
    }

    /// `aio_suspend(aiocblist, nent, timeoutp)` and its `_nocancel` form.
    fn suspend(
        &self,
        interrupt: *const u8,
        arguments: [u64; 3],
        cancellable: bool,
    ) -> Result<Outcome> {
        let [list, count, timeout] = arguments;
        if cancellable {
            // `__pthread_testcancel(1)`: the host thread's cancellation,
            // tested by the host's own `aio_suspend` before anything else.
            if host("aio_suspend", &[0, 0, 0]) == Err(EINTR) {
                return Ok(Outcome::Error(EINTR));
            }
        }
        let count = count as u32 as i32;
        if self.state().total() == 0 {
            return Ok(Outcome::Error(EINVAL));
        }
        if count < 1 || count as usize > limits().per_process {
            return Ok(Outcome::Error(EINVAL));
        }
        let mut deadline = None;
        if timeout != 0 {
            let Some(bytes) = memory::read(timeout, 16) else {
                return Ok(Outcome::Error(EAGAIN));
            };
            let seconds = u64_at(&bytes, 0) as i64;
            let nanoseconds = u64_at(&bytes, 8) as i64;
            if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
                return Ok(Outcome::Error(EINVAL));
            }
            let interval = Duration::new(seconds as u64, nanoseconds as u32);
            deadline = Some(
                Instant::now()
                    .checked_add(interval)
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(u64::from(u32::MAX))),
            );
        }
        let Some(table) = memory::read(list, count as usize * 8) else {
            return Ok(Outcome::Error(EAGAIN));
        };
        let wanted: Vec<u64> = words(&table).filter(|&address| address != 0).collect();
        let mut state = self.state();
        loop {
            if state
                .done
                .iter()
                .any(|entry| wanted.contains(&entry.address))
            {
                return Ok(Outcome::value(0));
            }
            let (next, waited) = self.wait(interrupt, state, deadline)?;
            state = next;
            match waited {
                Waited::Woken => {}
                Waited::TimedOut => return Ok(Outcome::Error(EAGAIN)),
                Waited::Interrupted => return Ok(Outcome::Error(EINTR)),
            }
        }
    }

    /// `aio_cancel(fd, aiocbp)`.
    fn cancel_call(&self, fd: i32, address: u64) -> Outcome {
        if fd != ALL_DESCRIPTORS {
            let Some(node) = vnode(fd) else {
                return Outcome::Error(EBADF);
            };
            if node.character && node.name.starts_with(b"rdisk") {
                return Outcome::value(AIO_NOTCANCELED);
            }
        }
        if self.state().total() == 0 {
            return Outcome::value(AIO_ALLDONE);
        }
        if address != 0 {
            let Some(block) = memory::read(address, AIOCB_BYTES) else {
                return Outcome::Error(EAGAIN);
            };
            if i32_at(&block, AIO_FILDES) != fd {
                return Outcome::Error(EBADF);
            }
        }
        let mut state = self.state();
        let selected = (fd != ALL_DESCRIPTORS).then_some(fd);
        let result = state.cancel(selected, address, Reason::Cancel);
        self.recount(&state);
        self.changed.notify_all();
        if result == -1 {
            Outcome::Error(EBADF)
        } else {
            Outcome::value(result as u64)
        }
    }

    /// `_aio_close(p, fd)`: before a close of `fd`, cancel its queued
    /// requests and wait for its running ones.
    fn close(&self, fd: i32) {
        let mut state = self.state();
        if state.cancel(Some(fd), 0, Reason::Close) == AIO_NOTCANCELED as i64 {
            while state.active.iter().any(|entry| entry.request.fd == fd) {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        self.recount(&state);
    }

    /// Whether the process has no request on either queue.
    fn idle(&self) -> bool {
        self.extant.load(Ordering::SeqCst) == 0
    }

    /// `_aio_exit` (and `_aio_exec`): stop queueing, cancel every queued
    /// request without notifying, wait for the running ones and free the
    /// done ones.
    pub(crate) fn exit(&self) {
        let mut state = self.state();
        state.exiting = true;
        if state.total() == 0 {
            return;
        }
        if state.cancel(None, 0, Reason::Exit) == AIO_NOTCANCELED as i64 {
            while !state.active.is_empty() {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        let done = std::mem::take(&mut state.done);
        for entry in &done {
            state.release(entry, &self.carried);
        }
        state.lists.clear();
        self.recount(&state);
    }

    /// The state, held across a host `fork`.
    pub(super) fn hold_for_fork(&self) -> Option<MutexGuard<'_, State>> {
        try_lock(&self.state)
    }

    /// The fork child's queues: empty, with no workers (`forkproc`).
    pub(super) fn fork_child(&self, state: &mut State) {
        *state = State::default();
        self.extant.store(0, Ordering::SeqCst);
        self.carried.store(0, Ordering::SeqCst);
    }

    /// A guest change to the kqueue `kqueue` as the host takes it:
    /// deleting a kernel knote deletes its carrier, and the list filter,
    /// which the host lacks, is `EVFILT_AIO`, whose user registration both
    /// kernels refuse with EPERM. `None` for a change that needs nothing.
    pub(super) fn change_to_host(
        &self,
        kqueue: i32,
        ident: u64,
        filter: i16,
        flags: u16,
    ) -> Option<Rewrite> {
        if !matches!(filter, EVFILT_AIO | EVFILT_LIST) {
            return None;
        }
        let guest = (ident, filter);
        if flags & EV_DELETE != 0 && self.carried.load(Ordering::SeqCst) != 0 {
            let mut guard = self.state();
            let state = &mut *guard;
            let list = filter == EVFILT_LIST;
            let carrier = state
                .active
                .iter_mut()
                .chain(state.done.iter_mut())
                .filter(|entry| entry.address == ident)
                .find_map(|entry| {
                    if list {
                        entry.list_carrier.as_mut()
                    } else {
                        entry.carrier.as_mut()
                    }
                    .filter(|carrier| carrier.kqueue == kqueue && !carrier.deleted)
                });
            if let Some(carrier) = carrier {
                // `filt_aiodetach`: the request stays until the process
                // ends, and its completion activates nothing.
                carrier.deleted = true;
                return Some(Rewrite {
                    host: (u64::from(carrier.port), EVFILT_MACHPORT),
                    guest,
                });
            }
        }
        (filter == EVFILT_LIST).then_some(Rewrite {
            host: (ident, EVFILT_AIO),
            guest,
        })
    }

    /// Present the `count` events the host wrote at `events` as the
    /// guest's kernel delivers them: a carrier's as its kernel knote's
    /// (`filt_aioprocess`, which frees the request), and an `EV_ERROR`
    /// echo of a rewritten change as the guest's change. False when the
    /// list cannot be rewritten.
    pub(super) fn events_to_guest(
        &self,
        layout: Layout,
        events: u64,
        count: u64,
        rewrites: &[Rewrite],
    ) -> bool {
        if self.carried.load(Ordering::SeqCst) == 0 && rewrites.is_empty() {
            return true;
        }
        for index in 0..count {
            let at = events + index * layout.size as u64;
            let Some(mut bytes) = memory::read(at, layout.size) else {
                return false;
            };
            let ident = u64_at(&bytes, 0);
            let filter = i16::from_le_bytes([bytes[8], bytes[9]]);
            let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
            if flags & EV_ERROR != 0 {
                if let Some(rewrite) = rewrites
                    .iter()
                    .find(|rewrite| rewrite.host == (ident, filter))
                {
                    bytes[..8].copy_from_slice(&rewrite.guest.0.to_le_bytes());
                    bytes[8..10].copy_from_slice(&rewrite.guest.1.to_le_bytes());
                    if !memory::write(at, &bytes) {
                        return false;
                    }
                }
                continue;
            }
            if filter != EVFILT_MACHPORT {
                continue;
            }
            let delivered = {
                let mut state = self.state();
                let Some(&(id, kind)) = u32::try_from(ident)
                    .ok()
                    .and_then(|port| state.carriers.get(&port))
                else {
                    continue;
                };
                let index = state.done.iter().position(|entry| entry.id == id);
                let delivered = index.map(|index| {
                    let entry = state.done.remove(index);
                    state.release(&entry, &self.carried);
                    (entry.address, kind, entry.error, entry.returned)
                });
                self.recount(&state);
                delivered
            };
            let Some((address, kind, error, returned)) = delivered else {
                continue;
            };
            layout.fill_kernel_event(
                &mut bytes,
                address,
                kind,
                KNOTE_HINT,
                [i64::from(error as u32 as i32) as u64, returned as u64],
            );
            if !memory::write(at, &bytes) {
                return false;
            }
        }
        true
    }
}

/// What makes the guest pages a request reaches present.
type PageIn<'a> = dyn FnMut(&[u64]) -> Result<()> + 'a;

/// The guest's asynchronous I/O calls.
pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    let aio = Arc::clone(&kernel.process.aio);
    let name = call.entry.name;
    let interrupt = kernel.signals.interrupt_flag();
    let [first, second, third, fourth, ..] = call.arguments;
    let pointers: &[u64] = match name {
        "aio_read" | "aio_write" => &[first],
        "aio_fsync" | "aio_cancel" => &[second],
        "lio_listio" => &[second, fourth],
        "aio_suspend" | "aio_suspend_nocancel" => &[first, third],
        _ => &[],
    };
    kernel.page_in_arguments(pointers)?;
    let mut page_in = |pages: &[u64]| kernel.page_in_arguments(pages);
    Ok(Some(match name {
        "aio_read" => aio.submit(first, Operation::Read, &mut page_in)?,
        "aio_write" => aio.submit(first, Operation::Write, &mut page_in)?,
        "aio_fsync" => match fsync_operation(first) {
            Some(operation) => aio.submit(second, operation, &mut page_in)?,
            None => Outcome::Error(EINVAL),
        },
        "lio_listio" => aio.list([first, second, third, fourth], interrupt, &mut page_in)?,
        "aio_error" => aio.error(first),
        "aio_return" => aio.reap(first),
        "aio_suspend" | "aio_suspend_nocancel" => {
            aio.suspend(interrupt, [first, second, third], name == "aio_suspend")?
        }
        "aio_cancel" => aio.cancel_call(first as u32 as i32, second),
        _ => return Ok(None),
    }))
}

/// The operation of `aio_fsync(op, aiocbp)`: 0 is `O_SYNC` for Panther
/// binaries.
fn fsync_operation(op: u64) -> Option<Operation> {
    match op as u32 as u64 {
        0 | O_SYNC => Some(Operation::Sync),
        O_DSYNC => Some(Operation::DataSync),
        _ => None,
    }
}

/// 26A434's `aio_readv(aiocbp)` and `aio_writev(aiocbp)`.
pub(super) fn vectored(kernel: &mut Kernel, address: u64, write: bool) -> Result<Outcome> {
    kernel.page_in_arguments(&[address])?;
    let operation = if write {
        Operation::WriteVector
    } else {
        Operation::ReadVector
    };
    let aio = Arc::clone(&kernel.process.aio);
    aio.submit(address, operation, &mut |pages| {
        kernel.page_in_arguments(pages)
    })
}

/// Whether closing `fd` raises a guard exception before anything else.
fn close_guarded(fd: i32) -> bool {
    vnode(fd).is_some_and(|node| node.guards & PROC_FI_GUARD_CLOSE != 0)
}

/// Before a forwarded call of [`CLOSING`] closes a descriptor, its
/// asynchronous I/O (`_aio_close`), unless the close fails first: a
/// close-guarded descriptor's `close`, or `dup2` over it, raises the guard
/// exception, as does `guarded_close_np` with another guard.
pub(super) fn closing(kernel: &Kernel, call: &Call) {
    if !CLOSING.contains(&call.entry.name) || kernel.process.aio.idle() {
        return;
    }
    let fd = |index| call.argument(index) as u32 as i32;
    match call.entry.name {
        "sys_close" | "sys_close_nocancel" if !close_guarded(fd(0)) => {
            kernel.process.aio.close(fd(0));
        }
        "guarded_close_np" => {
            let guard = memory::read(call.argument(1), 8).map(|bytes| u64_at(&bytes, 0));
            if guard.is_some_and(|guard| super::additions::guard_matches(fd(0), guard).is_ok()) {
                kernel.process.aio.close(fd(0));
            }
        }
        "sys_dup2" => duplicating(kernel, fd(0), fd(1)),
        _ => {}
    }
}

/// Before `dup2(from, to)` or `dup3` replaces `to`: its asynchronous I/O,
/// when the duplication goes ahead (`from` is open and is not `to`).
pub(super) fn duplicating(kernel: &Kernel, from: i32, to: i32) {
    let aio = &kernel.process.aio;
    if !aio.idle() && from != to && status_flags(from).is_ok() && !close_guarded(to) {
        aio.close(to);
    }
}

#[cfg(test)]
mod tests {
    use super::super::timer::KEVENT64;
    use super::*;
    use std::os::fd::AsRawFd;

    static NOT_INTERRUPTED: u8 = 0;

    fn interrupt() -> *const u8 {
        &raw const NOT_INTERRUPTED
    }

    fn no_page_in(_: &[u64]) -> Result<()> {
        Ok(())
    }

    /// A `struct user64_aiocb`.
    fn aiocb(fd: i32, offset: i64, buffer: u64, bytes: u64, opcode: i32) -> Box<[u8; AIOCB_BYTES]> {
        let mut block = Box::new([0u8; AIOCB_BYTES]);
        block[AIO_FILDES..AIO_FILDES + 4].copy_from_slice(&fd.to_le_bytes());
        block[AIO_OFFSET..AIO_OFFSET + 8].copy_from_slice(&offset.to_le_bytes());
        block[AIO_BUF..AIO_BUF + 8].copy_from_slice(&buffer.to_le_bytes());
        block[AIO_NBYTES..AIO_NBYTES + 8].copy_from_slice(&bytes.to_le_bytes());
        block[AIO_LIO_OPCODE..AIO_LIO_OPCODE + 4].copy_from_slice(&opcode.to_le_bytes());
        block
    }

    /// A `struct user64_sigevent`.
    fn sigevent(notification: Notification) -> [u8; SIGEVENT_BYTES] {
        let mut bytes = [0u8; SIGEVENT_BYTES];
        bytes[SIGEV_NOTIFY..SIGEV_NOTIFY + 4].copy_from_slice(&notification.notify.to_le_bytes());
        bytes[SIGEV_SIGNO..SIGEV_SIGNO + 4].copy_from_slice(&notification.signal.to_le_bytes());
        bytes[SIGEV_VALUE..SIGEV_VALUE + 8].copy_from_slice(&notification.value.to_le_bytes());
        bytes
    }

    fn set_notification(block: &mut [u8; AIOCB_BYTES], notification: Notification) {
        block[AIO_SIGEVENT..AIO_SIGEVENT + SIGEVENT_BYTES].copy_from_slice(&sigevent(notification));
    }

    fn address<T: ?Sized>(value: &T) -> u64 {
        (value as *const T).cast::<u8>() as u64
    }

    fn file() -> (tempfile::TempDir, std::fs::File, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        (directory, file, path)
    }

    /// Wait (cancellably, at most ten seconds) for the request at `block`.
    fn wait_for(aio: &Aio, block: u64) {
        let list = [block];
        let timeout = [10u64, 0];
        let suspended = aio.suspend(interrupt(), [address(&list), 1, address(&timeout)], true);
        assert_eq!(suspended.unwrap(), Outcome::value(0));
    }

    #[test]
    fn a_request_is_validated_as_aio_validate_does() {
        let limits = limits();
        let (_directory, file, path) = file();
        let reader = std::fs::File::open(&path).unwrap();
        let appender = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        let fd = file.as_raw_fd();
        let buffer = [0u8; 16];
        let at = address(&buffer);
        let check = |block: &[u8; AIOCB_BYTES], operation| {
            validate(address(block), operation, &limits).map(|(request, _)| request)
        };
        let read = check(&aiocb(fd, 0, at, 16, LIO_READ), None).unwrap();
        assert_eq!(
            (read.operation, read.fd, read.bytes),
            (Operation::Read, fd, 16)
        );
        assert_eq!(validate(8, Some(Operation::Read), &limits), Err(EFAULT));
        assert_eq!(check(&aiocb(fd, 0, at, 16, 9), None), Err(EINVAL));
        assert_eq!(check(&aiocb(fd, -1, at, 16, LIO_READ), None), Err(EINVAL));
        assert_eq!(check(&aiocb(fd, 0, 0, 16, LIO_WRITE), None), Err(EINVAL));
        assert_eq!(
            check(&aiocb(fd, 0, at, INT_MAX + 1, LIO_WRITE), None),
            Err(EINVAL)
        );
        assert_eq!(check(&aiocb(fd, 0, at, 0, LIO_READV), None), Err(EINVAL));
        assert_eq!(
            check(&aiocb(fd, 0, at, UIO_MAXIOV + 1, LIO_WRITEV), None),
            Err(EINVAL)
        );
        // The notification: a catchable signal, a descriptor-sized
        // kqueue, nothing else.
        let mut signalled = aiocb(fd, 0, at, 16, LIO_READ);
        for (notify, signal, valid) in [
            (SIGEV_SIGNAL, 30, true),
            (SIGEV_SIGNAL, SIGKILL, false),
            (SIGEV_SIGNAL, NSIG, false),
            (SIGEV_KEVENT, 0, false),
            (SIGEV_KEVENT, 3, true),
            (3, 0, false),
        ] {
            let notification = Notification {
                notify,
                signal,
                value: 0,
            };
            set_notification(&mut signalled, notification);
            assert_eq!(check(&signalled, None).is_ok(), valid, "{notify} {signal}");
        }
        // The descriptor's access, kind and append mode.
        let reading = reader.as_raw_fd();
        assert_eq!(
            check(&aiocb(reading, 0, at, 16, LIO_WRITE), None),
            Err(EBADF)
        );
        assert!(check(&aiocb(reading, 0, at, 16, LIO_NOP), None).is_ok());
        assert_eq!(check(&aiocb(-1, 0, at, 16, LIO_READ), None), Err(EBADF));
        let appended = check(&aiocb(appender.as_raw_fd(), 0, at, 16, LIO_WRITE), None);
        assert!(appended.unwrap().append);
        let mut pipe = [0i32; 2];
        // SAFETY: a two-descriptor array.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        assert_eq!(
            check(&aiocb(pipe[0], 0, at, 16, LIO_READ), None),
            Err(ESPIPE)
        );
        for descriptor in pipe {
            // SAFETY: the pipe this test opened.
            unsafe { libc::close(descriptor) };
        }
        assert_eq!(fsync_operation(0), Some(Operation::Sync));
        assert_eq!(fsync_operation(O_DSYNC), Some(Operation::DataSync));
        assert_eq!(fsync_operation(1), None);
    }

    #[test]
    fn requests_complete_on_the_workers_and_are_reaped_once() {
        let aio = Arc::new(Aio::default());
        let (_directory, file, _) = file();
        let fd = file.as_raw_fd();
        let data = *b"stela asynchronous";
        let write = aiocb(fd, 4, address(&data), data.len() as u64, 0);
        let submitted = aio.submit(address(&*write), Operation::Write, &mut no_page_in);
        assert_eq!(submitted.unwrap(), Outcome::value(0));
        // A known aiocb is not queued again.
        let again = aio.submit(address(&*write), Operation::Write, &mut no_page_in);
        assert_eq!(again.unwrap(), Outcome::Error(EAGAIN));
        wait_for(&aio, address(&*write));
        assert_eq!(aio.error(address(&*write)), Outcome::value(0));
        assert_eq!(
            aio.reap(address(&*write)),
            Outcome::value(data.len() as u64)
        );
        assert_eq!(aio.reap(address(&*write)), Outcome::Error(EINVAL));
        assert_eq!(aio.error(address(&*write)), Outcome::Error(EINVAL));
        // Read it back through two vectors.
        let mut first = [0u8; 5];
        let mut second = [0u8; 32];
        let vectors = [first.as_mut_ptr() as u64, 5, second.as_mut_ptr() as u64, 32];
        let read = aiocb(fd, 4, address(&vectors), 2, 0);
        let submitted = aio.submit(address(&*read), Operation::ReadVector, &mut no_page_in);
        assert_eq!(submitted.unwrap(), Outcome::value(0));
        wait_for(&aio, address(&*read));
        assert_eq!(aio.reap(address(&*read)), Outcome::value(data.len() as u64));
        assert_eq!(&first, b"stela");
        assert_eq!(&second[..13], b" asynchronous");
        // A failed transfer returns 0 with its error.
        let fault = aiocb(fd, 0, 8, 4, 0);
        let submitted = aio.submit(address(&*fault), Operation::Read, &mut no_page_in);
        assert_eq!(submitted.unwrap(), Outcome::value(0));
        wait_for(&aio, address(&*fault));
        assert_eq!(aio.error(address(&*fault)), Outcome::value(EFAULT));
        assert_eq!(aio.reap(address(&*fault)), Outcome::value(0));
        // A data sync.
        let sync = aiocb(fd, 0, 0, 0, 0);
        let submitted = aio.submit(address(&*sync), Operation::DataSync, &mut no_page_in);
        assert_eq!(submitted.unwrap(), Outcome::value(0));
        wait_for(&aio, address(&*sync));
        assert_eq!(aio.reap(address(&*sync)), Outcome::value(0));
        assert!(aio.idle());
    }

    #[test]
    fn a_waited_list_completes_every_member() {
        let aio = Arc::new(Aio::default());
        let (_directory, file, path) = file();
        let fd = file.as_raw_fd();
        let head = *b"head";
        let tail = *b"tail";
        let blocks = [
            aiocb(fd, 0, address(&head), 4, LIO_WRITE),
            aiocb(fd, 0, 0, 0, LIO_NOP),
            aiocb(fd, 4, address(&tail), 4, LIO_WRITE),
        ];
        let table: Vec<u64> = blocks.iter().map(|block| address(&**block)).collect();
        let list = |mode, count| {
            aio.list(
                [mode, address(&table[..]), count, 0],
                interrupt(),
                &mut no_page_in,
            )
            .unwrap()
        };
        assert_eq!(list(3, 3), Outcome::Error(EINVAL));
        assert_eq!(list(LIO_WAIT, 0), Outcome::Error(EINVAL));
        assert_eq!(list(LIO_WAIT, LISTIO_MAX + 1), Outcome::Error(EINVAL));
        assert_eq!(list(LIO_WAIT, 3), Outcome::value(0));
        for (block, returned) in table.iter().zip([4, 0, 4]) {
            assert_eq!(aio.error(*block), Outcome::value(0));
            assert_eq!(aio.reap(*block), Outcome::value(returned));
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"headtail");
        // A member that fails validation queues nothing.
        let invalid = aiocb(fd, 0, 0, 0, 7);
        let bad = [address(&*blocks[0]), address(&*invalid)];
        let failed = aio.list(
            [LIO_NOWAIT, address(&bad), 2, 0],
            interrupt(),
            &mut no_page_in,
        );
        assert_eq!(failed.unwrap(), Outcome::Error(EINVAL));
        assert!(aio.idle());
    }

    /// Queue the request at `block` without giving it a worker.
    fn queue(aio: &Aio, block: u64, operation: Option<Operation>) -> u64 {
        let (request, notification) = validate(block, operation, &limits()).unwrap();
        let mut state = aio.state();
        let entry = state.new_entry(block, request, notification);
        let id = entry.id;
        state
            .try_enqueue(entry, None, &limits(), &aio.carried)
            .unwrap();
        aio.recount(&state);
        id
    }

    #[test]
    fn cancellation_reports_as_aio_cancel_does() {
        let aio = Arc::new(Aio::default());
        let (_directory, file, path) = file();
        let other = std::fs::File::open(&path).unwrap();
        let fd = file.as_raw_fd();
        let buffer = [0u8; 8];
        let block = aiocb(fd, 0, address(&buffer), 8, LIO_WRITE);
        let at = address(&*block);
        assert_eq!(aio.cancel_call(fd, at), Outcome::value(AIO_ALLDONE));
        queue(&aio, at, Some(Operation::Write));
        assert_eq!(aio.error(at), Outcome::value(EINPROGRESS));
        assert_eq!(aio.reap(at), Outcome::Error(EINPROGRESS));
        // The aiocb's descriptor must be the one named.
        assert_eq!(
            aio.cancel_call(other.as_raw_fd(), at),
            Outcome::Error(EBADF)
        );
        assert_eq!(aio.cancel_call(ALL_DESCRIPTORS, at), Outcome::Error(EBADF));
        assert_eq!(aio.cancel_call(-1, at), Outcome::Error(EBADF));
        assert_eq!(aio.cancel_call(fd, at), Outcome::value(AIO_CANCELED));
        assert_eq!(aio.error(at), Outcome::value(ECANCELED));
        assert_eq!(aio.cancel_call(fd, at), Outcome::value(AIO_ALLDONE));
        assert_eq!(aio.cancel_call(other.as_raw_fd(), 0), Outcome::Error(EBADF));
        assert_eq!(aio.reap(at), Outcome::Error(ECANCELED));
        // A running request is not cancelled.
        queue(&aio, at, Some(Operation::Write));
        assert!(aio.state().take_work().is_some());
        assert_eq!(
            aio.cancel_call(ALL_DESCRIPTORS, 0),
            Outcome::value(AIO_NOTCANCELED)
        );
        assert_eq!(aio.cancel_call(fd, at), Outcome::value(AIO_NOTCANCELED));
    }

    #[test]
    fn an_fsync_waits_to_be_the_oldest_request() {
        let aio = Arc::new(Aio::default());
        let (_directory, file, _) = file();
        let fd = file.as_raw_fd();
        let buffer = [0u8; 8];
        let blocks = [
            aiocb(fd, 0, address(&buffer), 8, 0),
            aiocb(fd, 0, 0, 0, 0),
            aiocb(fd, 8, address(&buffer), 8, 0),
        ];
        let older = queue(&aio, address(&*blocks[0]), Some(Operation::Write));
        let sync = queue(&aio, address(&*blocks[1]), Some(Operation::Sync));
        let newer = queue(&aio, address(&*blocks[2]), Some(Operation::Write));
        let mut state = aio.state();
        assert_eq!(state.take_work().map(|(id, _)| id), Some(older));
        assert_eq!(state.take_work().map(|(id, _)| id), Some(newer));
        assert_eq!(state.take_work(), None);
        state.complete(older, false);
        assert_eq!(state.take_work().map(|(id, _)| id), Some(sync));
    }

    #[test]
    fn the_process_end_cancels_queued_requests_and_refuses_more() {
        let aio = Arc::new(Aio::default());
        let (_directory, file, _) = file();
        let fd = file.as_raw_fd();
        let buffer = [0u8; 8];
        let mut block = aiocb(fd, 0, address(&buffer), 8, 0);
        // Its signal would end this test: the end notifies nothing.
        set_notification(
            &mut block,
            Notification {
                notify: SIGEV_SIGNAL,
                signal: libc::SIGTERM,
                value: 0,
            },
        );
        queue(&aio, address(&*block), Some(Operation::Write));
        aio.exit();
        assert!(aio.idle());
        let refused = aio.submit(address(&*block), Operation::Write, &mut no_page_in);
        assert_eq!(refused.unwrap(), Outcome::Error(EAGAIN));
        // A fork child starts with no requests and queues again.
        let mut state = aio.hold_for_fork().unwrap();
        aio.fork_child(&mut state);
        assert!(!state.exiting);
    }

    /// The next event of the host kqueue `queue`, waiting at most ten
    /// seconds.
    fn next_event(queue: i32) -> [u8; KEVENT64_BYTES] {
        let mut event = [0u8; KEVENT64_BYTES];
        let timeout = [10u64, 0];
        let count = host(
            "kevent64",
            &[
                queue as u64,
                0,
                0,
                event.as_mut_ptr() as u64,
                1,
                0,
                address(&timeout),
            ],
        );
        assert_eq!(count, Ok(1));
        event
    }

    #[test]
    fn a_kevent_notification_is_delivered_as_the_kernel_knote() {
        let aio = Arc::new(Aio::default());
        let (_directory, file, _) = file();
        let fd = file.as_raw_fd();
        // SAFETY: a new kqueue this test owns.
        let queue = unsafe { libc::kqueue() };
        let data = *b"knote";
        let mut block = aiocb(fd, 0, address(&data), 5, 0);
        let notification = Notification {
            notify: SIGEV_KEVENT,
            signal: queue,
            value: 0x5157,
        };
        set_notification(&mut block, notification);
        let at = address(&*block);
        let submitted = aio.submit(at, Operation::Write, &mut no_page_in);
        assert_eq!(submitted.unwrap(), Outcome::value(0));
        // A second knote of the request's touches the first's.
        let again = aio.submit(at, Operation::Write, &mut no_page_in);
        assert_eq!(again.unwrap(), Outcome::Error(ENOTSUP));
        let event = next_event(queue);
        assert_eq!(i16::from_le_bytes([event[8], event[9]]), EVFILT_MACHPORT);
        assert!(aio.events_to_guest(KEVENT64, address(&event), 1, &[]));
        assert_eq!(u64_at(&event, 0), at);
        assert_eq!(i16::from_le_bytes([event[8], event[9]]), EVFILT_AIO);
        assert_eq!(i32_at(&event, 12), KNOTE_HINT as i32);
        assert_eq!(u64_at(&event, 24), 0x5157);
        assert_eq!((u64_at(&event, 32), u64_at(&event, 40)), (0, 5));
        // Delivery freed the request: aio_return never sees it.
        assert_eq!(aio.error(at), Outcome::Error(EINVAL));
        assert_eq!(aio.carried.load(Ordering::SeqCst), 0);
        // SAFETY: the kqueue this test opened.
        unsafe { libc::close(queue) };
    }

    #[test]
    fn a_list_kevent_fires_for_every_member_when_the_list_is_done() {
        let aio = Arc::new(Aio::default());
        let (_directory, file, _) = file();
        let fd = file.as_raw_fd();
        // SAFETY: a new kqueue this test owns.
        let queue = unsafe { libc::kqueue() };
        let data = *b"list";
        let blocks = [
            aiocb(fd, 0, address(&data), 4, LIO_WRITE),
            aiocb(fd, 4, address(&data), 4, LIO_WRITE),
        ];
        let table: Vec<u64> = blocks.iter().map(|block| address(&**block)).collect();
        let signal = sigevent(Notification {
            notify: SIGEV_KEVENT,
            signal: queue,
            value: 7,
        });
        let listed = aio.list(
            [LIO_NOWAIT, address(&table[..]), 2, address(&signal)],
            interrupt(),
            &mut no_page_in,
        );
        assert_eq!(listed.unwrap(), Outcome::value(0));
        let mut delivered = Vec::new();
        for _ in 0..2 {
            let event = next_event(queue);
            assert!(aio.events_to_guest(KEVENT64, address(&event), 1, &[]));
            assert_eq!(i16::from_le_bytes([event[8], event[9]]), EVFILT_LIST);
            assert_eq!(u64_at(&event, 24), 7);
            assert_eq!(u64_at(&event, 40), 4);
            delivered.push(u64_at(&event, 0));
        }
        delivered.sort_unstable();
        let mut expected = table.clone();
        expected.sort_unstable();
        assert_eq!(delivered, expected);
        assert!(aio.idle());
        // SAFETY: the kqueue this test opened.
        unsafe { libc::close(queue) };
    }

    #[test]
    fn guest_kevent_changes_reach_the_host_as_its_filters() {
        let aio = Aio::default();
        // The list filter registers as EVFILT_AIO, which the host refuses
        // from user space as the arm64 kernel refuses both.
        let rewrite = aio.change_to_host(3, 0x1000, EVFILT_LIST, EV_ADD).unwrap();
        assert_eq!(rewrite.host, (0x1000, EVFILT_AIO));
        assert_eq!(aio.change_to_host(3, 0x1000, EVFILT_AIO, EV_ADD), None);
        assert_eq!(aio.change_to_host(3, 0x1000, -1, EV_DELETE), None);
    }
}
