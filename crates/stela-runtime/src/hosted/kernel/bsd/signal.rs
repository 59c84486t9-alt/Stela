//! Signal dispositions and masks (`bsd/kern/kern_sig.c`). The guest's
//! actions, mask and alternate stack are this kernel's state; the host
//! process mirrors them so that the host kernel generates, ignores, blocks
//! and defaults signals as the guest asked, except the synchronous signals
//! the hosted runtime's own fault recovery owns.
//!
//! A signal arriving for a guest handler is recorded by a host handler,
//! and the next kernel entry stops the process naming it: delivery onto the
//! guest stack through its `sigtramp` (`sendsig`) and `sigreturn` are not
//! implemented yet.
use super::{Call, EFAULT, EINVAL, Kernel, Outcome, forward};
use crate::hosted::memory;
use crate::hosted::threads::lock;
use anyhow::{Result, bail};
use core::sync::atomic::{AtomicU32, Ordering};

/// `NSIG`.
const SIGNALS: usize = 32;
const SIGKILL: u64 = 9;
const SIGSTOP: u64 = 17;
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SA_ONSTACK: u32 = 0x0001;
const SA_RESTART: u32 = 0x0002;
const SA_RESETHAND: u32 = 0x0004;
const SA_NOCLDSTOP: u32 = 0x0008;
const SA_NODEFER: u32 = 0x0010;
const SA_NOCLDWAIT: u32 = 0x0020;
const SA_SIGINFO: u32 = 0x0040;
const SA_USERSPACE_MASK: u32 =
    SA_ONSTACK | SA_RESTART | SA_RESETHAND | SA_NOCLDSTOP | SA_NODEFER | SA_NOCLDWAIT | SA_SIGINFO;
const SIG_BLOCK: u64 = 1;
const SIG_UNBLOCK: u64 = 2;
const SIG_SETMASK: u64 = 3;
/// `MINSIGSTKSZ`.
const MINIMUM_STACK: u64 = 32 << 10;
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 4;
/// The signals the hosted runtime's fault recovery handles on the host.
const OWNED: [i32; 3] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL];

/// Host signals that arrived for a guest handler.
static PENDING: AtomicU32 = AtomicU32::new(0);

extern "C" fn record(signal: libc::c_int) {
    PENDING.fetch_or(1 << signal, Ordering::SeqCst);
}

const fn bit(signal: u64) -> u32 {
    1 << (signal - 1)
}

#[derive(Debug, Clone, Copy, Default)]
struct Action {
    handler: u64,
    mask: u32,
    flags: u32,
}

/// The process's signal actions (`p_sigacts`).
#[derive(Debug, Clone)]
pub(crate) struct Actions([Action; SIGNALS]);

impl Actions {
    /// The actions exec leaves: ignored signals stay ignored, every other
    /// signal is defaulted.
    pub(crate) fn inherit() -> Self {
        let mut actions = [Action {
            flags: SA_RESTART,
            ..Action::default()
        }; SIGNALS];
        for (signal, action) in actions.iter_mut().enumerate().skip(1) {
            // SAFETY: a query of the disposition into this frame.
            let mut current: libc::sigaction = unsafe { core::mem::zeroed() };
            unsafe { libc::sigaction(signal as i32, core::ptr::null(), &raw mut current) };
            if current.sa_sigaction == libc::SIG_IGN {
                action.handler = SIG_IGN;
            }
        }
        Self(actions)
    }
}

/// One thread's signal state (`uu_sigmask`, `uu_sigstk`).
#[derive(Debug, Clone)]
pub(crate) struct ThreadSignals {
    mask: u32,
    alternate: (u64, u64, u32),
}

impl ThreadSignals {
    /// The state of a thread whose mask its host thread already holds: the
    /// main thread's from exec, a created thread's from its creator.
    pub(crate) fn inherit() -> Self {
        let mut mask: libc::sigset_t = 0;
        // SAFETY: a query of the calling thread's mask.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut mask) };
        Self {
            mask,
            alternate: (0, 0, SS_DISABLE),
        }
    }

    /// A signal that arrived for a guest handler and is not blocked.
    pub(crate) fn deliverable(&self) -> Option<u32> {
        let pending = PENDING.load(Ordering::SeqCst) >> 1 & !self.mask;
        (pending != 0).then(|| pending.trailing_zeros() + 1)
    }

    /// Block every signal outside `allowed` that a workqueue thread may
    /// block (`~workq_threadmask`), as a new workqueue thread starts and
    /// as one returns to the pool (`workq_thread_return`).
    pub(crate) fn reset_for_workqueue(&mut self, allowed: u32) {
        self.set_mask(self.mask | (!WORKQ_THREADMASK & !allowed));
    }

    /// Set the mask, mirrored to the host thread except the signals the
    /// hosted runtime's fault recovery owns.
    pub(crate) fn set_mask(&mut self, mask: u32) {
        let mask = mask & !CANT_MASK;
        let owned = OWNED
            .iter()
            .fold(0, |bits, &signal| bits | bit(signal as u64));
        let host: libc::sigset_t = mask & !owned;
        // SAFETY: the set is this frame's.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const host, core::ptr::null_mut()) };
        self.mask = mask;
    }
}

/// Signals that are always delivered to a workqueue thread
/// (`workq_threadmask`: `threadmask`, `sigcantmask` and SIGPROF, less
/// SIGABRT).
pub(crate) const WORKQ_THREADMASK: u32 = (bit(4) // SIGILL
    | bit(5) // SIGTRAP
    | bit(7) // SIGEMT
    | bit(8) // SIGFPE
    | bit(10) // SIGBUS
    | bit(11) // SIGSEGV
    | bit(12) // SIGSYS
    | bit(13) // SIGPIPE
    | bit(SIGKILL)
    | bit(SIGSTOP)
    | bit(27)) // SIGPROF
    & !bit(6); // SIGABRT
/// `sigcantmask`.
const CANT_MASK: u32 = bit(SIGKILL) | bit(SIGSTOP);

pub(super) const CALLS: &[&str] = &[
    "sigaction",
    "sigprocmask",
    "__pthread_sigmask",
    "__pthread_kill",
    "sigaltstack",
    "sigpending",
    "kill",
    "__sigwait",
    "__sigwait_nocancel",
    "__disable_threadsignal",
    "__pthread_markcancel",
    "__pthread_canceled",
    "setitimer",
    "getitimer",
];

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "sigaction" => sigaction(kernel, call)?,
        "sigprocmask" | "__pthread_sigmask" => mask(kernel, call)?,
        "__pthread_kill" => thread_kill(kernel, call)?,
        "sigaltstack" => alternate_stack(kernel, call)?,
        "sigpending"
        | "kill"
        | "__sigwait"
        | "__sigwait_nocancel"
        | "__disable_threadsignal"
        | "__pthread_markcancel"
        | "__pthread_canceled"
        | "setitimer"
        | "getitimer" => forward(kernel, call)?,
        _ => return Ok(None),
    }))
}

/// `sigaction(signum, struct __sigaction *nsa, struct sigaction *osa)`.
fn sigaction(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [signal, new, old, ..] = call.arguments;
    if signal == 0 || signal as usize >= SIGNALS || signal == SIGKILL || signal == SIGSTOP {
        return Ok(Outcome::Error(EINVAL));
    }
    let index = signal as usize;
    let previous = lock(&kernel.process.actions).0[index];
    if new != 0 {
        // `struct __user64_sigaction`: handler, trampoline, mask, flags. The
        // trampoline matters only to delivery.
        let Some(bytes) = memory::read(new, 24) else {
            return Ok(Outcome::Error(EFAULT));
        };
        let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let half = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let action = Action {
            handler: word(0),
            mask: half(16),
            flags: half(20) & SA_USERSPACE_MASK,
        };
        mirror(signal as i32, action.handler)?;
        lock(&kernel.process.actions).0[index] = action;
    }
    if old != 0 {
        // `struct user64_sigaction`: handler, mask, flags.
        let mut bytes = previous.handler.to_le_bytes().to_vec();
        bytes.extend(previous.mask.to_le_bytes());
        bytes.extend(previous.flags.to_le_bytes());
        if !memory::write(old, &bytes) {
            return Ok(Outcome::Error(EFAULT));
        }
    }
    Ok(Outcome::value(0))
}

/// Give the host the disposition that makes it generate the guest's
/// behaviour: the same default or ignore, or the recording handler.
fn mirror(signal: i32, handler: u64) -> Result<()> {
    if OWNED.contains(&signal) {
        return Ok(());
    }
    let host_handler = match handler {
        SIG_DFL => libc::SIG_DFL,
        SIG_IGN => libc::SIG_IGN,
        _ => record as extern "C" fn(libc::c_int) as usize,
    };
    // SAFETY: an all-zero sigaction with a handler and empty mask.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = host_handler;
    // SAFETY: the action is this frame's.
    if unsafe { libc::sigaction(signal, &raw const action, core::ptr::null_mut()) } != 0 {
        bail!("the host refused the disposition of signal {signal}");
    }
    Ok(())
}

/// `sigprocmask(how, set, oset)` and `__pthread_sigmask`: both change the
/// calling thread's mask.
fn mask(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [how, set, old, ..] = call.arguments;
    let previous = kernel.signals.mask;
    if set != 0 {
        let Some(requested) = memory::read_u32(set) else {
            return Ok(Outcome::Error(EFAULT));
        };
        let mask = match how {
            SIG_BLOCK => previous | requested,
            SIG_UNBLOCK => previous & !requested,
            SIG_SETMASK => requested,
            _ => return Ok(Outcome::Error(EINVAL)),
        };
        kernel.signals.set_mask(mask);
    }
    if old != 0 && !memory::write_u32(old, previous) {
        return Ok(Outcome::Error(EFAULT));
    }
    Ok(Outcome::value(0))
}

/// `sigaltstack(nss, oss)` with `struct user64_sigaltstack`: base, size,
/// flags.
fn alternate_stack(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [new, old, ..] = call.arguments;
    let (base, size, flags) = kernel.signals.alternate;
    if old != 0 {
        let mut bytes = base.to_le_bytes().to_vec();
        bytes.extend(size.to_le_bytes());
        bytes.extend(flags.to_le_bytes());
        bytes.extend([0u8; 4]);
        if !memory::write(old, &bytes) {
            return Ok(Outcome::Error(EFAULT));
        }
    }
    if new != 0 {
        let Some(bytes) = memory::read(new, 24) else {
            return Ok(Outcome::Error(EFAULT));
        };
        let base = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let flags = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        if flags & SS_ONSTACK != 0 {
            return Ok(Outcome::Error(super::EPERM));
        }
        if flags & !SS_DISABLE != 0 {
            return Ok(Outcome::Error(EINVAL));
        }
        if flags & SS_DISABLE == 0 && size < MINIMUM_STACK {
            return Ok(Outcome::Error(super::ENOMEM));
        }
        kernel.signals.alternate = (base, size, flags);
    }
    Ok(Outcome::value(0))
}

/// `__pthread_kill(thread_port, signal)`: a workqueue thread takes signals
/// only once it allowed them (`BSDTHREAD_CTL_WORKQ_ALLOW_KILL`); otherwise
/// the host kernel signals the thread the port names, which is the guest
/// thread's host thread.
fn thread_kill(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let port = call.argument(0) as u32;
    if call.argument(1) as usize >= SIGNALS {
        return Ok(Outcome::Error(EINVAL));
    }
    if kernel.process.workqueue.refuses_kill(port) {
        return Ok(Outcome::Error(ENOTSUP));
    }
    forward(kernel, call)
}

const ENOTSUP: u64 = 45;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_workqueue_thread_mask_is_xnus() {
        assert_eq!(WORKQ_THREADMASK, 0x0401_1fd8);
        assert_eq!(CANT_MASK & WORKQ_THREADMASK, CANT_MASK);
    }
}
