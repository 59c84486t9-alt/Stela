//! The host half of guest signals, with ordinary POSIX calls: the host
//! process holds a disposition mirroring each guest action, so the host
//! kernel generates, ignores, defaults and restarts as the guest asked, and
//! a signal the guest catches runs one recording handler on the host thread
//! the host kernel chose. The handler only records it, async-signal-safely,
//! in that thread's [`Slot`]; the guest thread delivers it to the guest
//! handler at its next kernel exit or time-slice stop (`super`), as XNU's
//! AST does.
//!
//! A forwarded call is the one place a guest thread waits in the host
//! kernel, so the host call stub has an interruptible window
//! ([`forward::interruptible`]): a signal recorded before the `syscall`
//! instruction executes, or one the host kernel rewound the call for
//! (`SA_RESTART`), makes the call return `ERESTART` without running it,
//! and the guest repeats it after its handler. Without `SA_RESTART` the
//! host call returns EINTR itself, as XNU's would. Every host thread that
//! runs no guest thread blocks all signals but the synchronous ones the
//! runtime's fault recovery owns, so the host kernel picks a guest thread
//! for a process-directed signal.
use crate::hosted::darwin::{SA_NOCLDSTOP, SA_NOCLDWAIT, SA_RESTART, SIG_DFL, SIG_IGN};
use crate::hosted::{forward, host::UserContext};
use anyhow::{Result, bail};
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::{cell::Cell, sync::Arc};

/// `NSIG`.
pub(super) const SIGNALS: usize = 32;
/// The synchronous signals the hosted runtime's fault recovery handles on
/// the host (`host::NativeRunner`): never blocked on a host thread and
/// never given a guest disposition.
pub(super) const OWNED: [i32; 3] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL];
/// RFLAGS.CF, which a host BSD call's error sets.
const RFLAGS_CARRY: u64 = 1;

const fn bit(signal: i32) -> u32 {
    1 << (signal - 1)
}

/// The owned signals as a mask.
pub(super) const OWNED_MASK: u32 = bit(OWNED[0]) | bit(OWNED[1]) | bit(OWNED[2]);

/// What one recorded signal carries into the guest's `siginfo_t`
/// (`p->si_pid`, `si_uid`, `si_code`, `si_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Sender {
    pub pid: i32,
    pub uid: u32,
    pub code: i32,
    pub status: i32,
}

/// One guest thread's signals as the recording handler sees them.
pub(crate) struct Slot {
    /// Signals recorded for the thread (`uu_siglist`), bit `signal - 1`.
    pending: AtomicU32,
    /// The thread's guest mask (`uu_sigmask`), which `sigprocmask` on
    /// another thread of the process also sets.
    mask: AtomicU32,
    /// Set while a recorded signal may be deliverable: the next
    /// interruptible forwarded call returns `ERESTART` instead of running.
    interrupt: AtomicU8,
    /// The last recorded occurrence of each signal: pid and uid, code and
    /// status.
    senders: [AtomicU64; SIGNALS],
    details: [AtomicU64; SIGNALS],
}

impl Slot {
    pub(crate) const fn new(mask: u32) -> Self {
        Self {
            pending: AtomicU32::new(0),
            mask: AtomicU32::new(mask),
            interrupt: AtomicU8::new(0),
            senders: [const { AtomicU64::new(0) }; SIGNALS],
            details: [const { AtomicU64::new(0) }; SIGNALS],
        }
    }

    /// Record `signal` as a host handler does: async-signal-safe.
    pub(crate) fn record(&self, signal: i32, sender: Sender) {
        let index = signal as usize;
        self.senders[index].store(
            u64::from(sender.pid as u32) | u64::from(sender.uid) << 32,
            Ordering::SeqCst,
        );
        self.details[index].store(
            u64::from(sender.code as u32) | u64::from(sender.status as u32) << 32,
            Ordering::SeqCst,
        );
        self.pending.fetch_or(bit(signal), Ordering::SeqCst);
        self.interrupt.store(1, Ordering::SeqCst);
    }

    pub(crate) fn pending(&self) -> u32 {
        self.pending.load(Ordering::SeqCst)
    }

    /// Take `signal` off the pending set: whether it was pending, and what
    /// it carried.
    pub(crate) fn take(&self, signal: i32) -> Option<Sender> {
        if self.pending.fetch_and(!bit(signal), Ordering::SeqCst) & bit(signal) == 0 {
            return None;
        }
        let index = signal as usize;
        let sender = self.senders[index].swap(0, Ordering::SeqCst);
        let detail = self.details[index].swap(0, Ordering::SeqCst);
        Some(Sender {
            pid: sender as u32 as i32,
            uid: (sender >> 32) as u32,
            code: detail as u32 as i32,
            status: (detail >> 32) as u32 as i32,
        })
    }

    /// Forget every pending signal (`forkproc`).
    pub(crate) fn clear(&self) {
        self.pending.store(0, Ordering::SeqCst);
        self.interrupt.store(0, Ordering::SeqCst);
    }

    pub(crate) fn mask(&self) -> u32 {
        self.mask.load(Ordering::SeqCst)
    }

    pub(crate) fn set_mask(&self, mask: u32) {
        self.mask.store(mask, Ordering::SeqCst);
    }

    /// Change the mask as `sigprocmask` does on each thread: the bits of
    /// `set` and `clear` with `clear` applied last.
    pub(crate) fn update_mask(&self, set: u32, clear: u32) {
        let _ = self
            .mask
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |mask| {
                Some((mask | set) & !clear)
            });
    }

    /// Set the interrupt flag for whether `deliverable` signals remain. A
    /// signal the handler records meanwhile sets it again.
    pub(crate) fn rearm(&self, deliverable: impl FnOnce() -> bool) {
        self.interrupt.store(0, Ordering::SeqCst);
        if deliverable() {
            self.interrupt.store(1, Ordering::SeqCst);
        }
    }

    /// The flag the host call stub checks before its `syscall`.
    pub(crate) fn interrupt_flag(&self) -> *const u8 {
        self.interrupt.as_ptr()
    }
}

/// Signals a host thread running no guest thread received: any guest
/// thread delivers them.
static UNCLAIMED: Slot = Slot::new(0);

pub(crate) fn unclaimed() -> &'static Slot {
    &UNCLAIMED
}

std::thread_local! {
    /// The slot of the guest thread this host thread runs.
    static CURRENT: Cell<*const Slot> = const { Cell::new(core::ptr::null()) };
}

/// A guest thread's slot registered with its host thread's handler for as
/// long as the thread runs, which the registration keeps alive.
pub(crate) struct Registration {
    _slot: Arc<Slot>,
}

impl Registration {
    /// Register `slot` for the calling host thread.
    pub(crate) fn new(slot: Arc<Slot>) -> Self {
        CURRENT.with(|current| current.set(Arc::as_ptr(&slot)));
        Self { _slot: slot }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // An ending thread takes no more signals: the host kernel picks
        // another for them.
        block_all();
        CURRENT.with(|current| current.set(core::ptr::null()));
    }
}

/// The recording handler.
extern "C" fn record(signal: libc::c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    if !(1..SIGNALS as i32).contains(&signal) {
        return;
    }
    // SAFETY: CURRENT points at the registered slot, which its
    // Registration keeps alive until it clears CURRENT.
    let slot = unsafe { CURRENT.with(Cell::get).as_ref() }.unwrap_or(&UNCLAIMED);
    // SAFETY: the host kernel passes this signal's siginfo.
    let sender = unsafe { info.as_ref() }.map_or_else(Sender::default, |info| Sender {
        pid: info.si_pid,
        uid: info.si_uid,
        code: info.si_code,
        status: info.si_status,
    });
    slot.record(signal, sender);
    // SAFETY: the host kernel passes the interrupted thread's ucontext.
    unsafe { interrupt(context.cast()) };
}

/// Make the interrupted thread's forwarded call return `ERESTART` if it
/// stopped in the stub's window: before its `syscall` instruction ran, or
/// at it again because the host kernel rewound the call to restart it.
///
/// # Safety
/// `context` is the ucontext the host kernel passed the handler.
unsafe fn interrupt(context: *mut UserContext) {
    let window = forward::interruptible();
    // SAFETY: the caller's ucontext holds its machine context.
    let Some(machine) = (unsafe { context.as_mut() })
        .and_then(|context| unsafe { context.machine_context.as_mut() })
    else {
        return;
    };
    let thread = &mut machine.thread;
    if (window.ready..=window.instruction).contains(&thread.rip)
        && thread.r13 != 0
        && forward::is_bsd_selector(thread.rax)
    {
        thread.rip = window.done;
        thread.rax = forward::ERESTART;
        thread.rflags |= RFLAGS_CARRY;
    }
}

/// Give the host the disposition that makes it act on `signal` as the
/// guest's `handler` and `flags` ask: the same default or ignore, or the
/// recording handler, restarting interrupted calls when the guest's action
/// does, with the guest's SIGCHLD flags.
pub(crate) fn mirror(signal: i32, handler: u64, flags: u32) -> Result<()> {
    if OWNED.contains(&signal) {
        return Ok(());
    }
    // SAFETY: an all-zero sigaction, filled below.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = match handler {
        SIG_DFL => libc::SIG_DFL,
        SIG_IGN => libc::SIG_IGN,
        _ => {
            action.sa_flags = libc::SA_SIGINFO;
            record as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) as usize
        }
    };
    if flags & SA_RESTART != 0 {
        action.sa_flags |= libc::SA_RESTART;
    }
    if signal == libc::SIGCHLD {
        action.sa_flags |= (flags & (SA_NOCLDSTOP | SA_NOCLDWAIT)) as i32;
    }
    // The handler runs with every other signal blocked.
    action.sa_mask = !OWNED_MASK;
    // SAFETY: the action is this frame's.
    if unsafe { libc::sigaction(signal, &raw const action, core::ptr::null_mut()) } != 0 {
        bail!("the host refused the disposition of signal {signal}");
    }
    Ok(())
}

/// The calling host thread's mask.
pub(crate) fn host_mask() -> u32 {
    let mut mask: libc::sigset_t = 0;
    // SAFETY: a query of the calling thread's mask.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut mask) };
    mask
}

/// Set the calling host thread's mask to a guest mask, less the owned
/// signals.
pub(crate) fn set_host_mask(mask: u32) {
    let host: libc::sigset_t = mask & !OWNED_MASK;
    // SAFETY: the set is this frame's.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const host, core::ptr::null_mut()) };
}

/// Block every signal but the owned ones on the calling host thread: its
/// previous mask.
pub(crate) fn block_all() -> u32 {
    let previous = host_mask();
    set_host_mask(!0);
    previous
}

/// Run `section` with every signal blocked on the calling host thread, so
/// that a host thread it creates starts with them blocked.
pub(crate) fn without_signals<T>(section: impl FnOnce() -> T) -> T {
    let previous = block_all();
    let result = section();
    let host: libc::sigset_t = previous;
    // SAFETY: the set is this frame's.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const host, core::ptr::null_mut()) };
    result
}

/// Send `signal` to the calling host thread, whose host disposition then
/// acts (a default stop, or a default action the host kernel performs).
pub(crate) fn raise(signal: i32) {
    // SAFETY: a signal to the calling thread.
    unsafe { libc::pthread_kill(libc::pthread_self(), signal) };
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGUSR2: i32 = 31;
    const READ: u16 = 3;

    #[test]
    fn a_slot_takes_what_it_recorded_once() {
        let slot = Slot::new(0);
        let sender = Sender {
            pid: 501,
            uid: 20,
            code: 1,
            status: 3,
        };
        slot.record(20, sender);
        assert_eq!(slot.pending(), bit(20));
        assert_eq!(slot.take(20), Some(sender));
        assert_eq!(slot.take(20), None);
        // The flag stays set until the thread rearms it.
        assert_eq!(unsafe { *slot.interrupt_flag() }, 1);
        slot.rearm(|| false);
        assert_eq!(unsafe { *slot.interrupt_flag() }, 0);
        slot.update_mask(bit(2) | bit(3), bit(3));
        assert_eq!(slot.mask(), bit(2));
    }

    #[test]
    fn a_blocked_forwarded_call_returns_erestart_for_a_recorded_signal() {
        // The guest caught SIGUSR2 with SA_RESTART: the host kernel
        // restarts the interrupted read, and the window turns it into
        // ERESTART for the guest to repeat after its handler.
        mirror(SIGUSR2, 0x1_0000_4000, SA_RESTART).unwrap();
        let mut pipe = [0i32; 2];
        // SAFETY: two descriptors into this frame.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let slot = Arc::new(Slot::new(0));
            let _registration = Registration::new(slot.clone());
            set_host_mask(0);
            let thread = unsafe { libc::pthread_self() } as usize;
            sender.send(thread).unwrap();
            let mut byte = 0u8;
            let returned = forward::bsd_interruptible(
                READ,
                &[pipe[0] as u64, &raw mut byte as u64, 1],
                slot.interrupt_flag(),
            );
            (returned, slot.take(SIGUSR2).is_some())
        });
        let thread = receiver.recv().unwrap() as libc::pthread_t;
        // Signal until the reader is past the stub's flag check.
        while !reader.is_finished() {
            // SAFETY: the reader is alive until it is joined.
            unsafe { libc::pthread_kill(thread, SIGUSR2) };
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let (returned, recorded) = reader.join().unwrap();
        assert!(recorded);
        assert!(returned.carry);
        assert_eq!(returned.rax, forward::ERESTART);
        // SAFETY: the pipe is this test's.
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        mirror(SIGUSR2, SIG_DFL, SA_RESTART).unwrap();
    }
}
