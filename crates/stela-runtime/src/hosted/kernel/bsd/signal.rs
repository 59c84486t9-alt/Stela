//! Signals (`bsd/kern/kern_sig.c`, `bsd/dev/arm/unix_signal.c`). The
//! guest's actions, masks, alternate stacks and pending signals are this
//! kernel's state; the host process mirrors the dispositions and masks so
//! that the host kernel generates, ignores, defaults, stops and restarts as
//! the guest asked ([`host`]), except for the synchronous signals the hosted
//! runtime's own fault recovery owns.
//!
//! A signal a guest handler catches is recorded by the host handler on the
//! host thread the host kernel chose, and that guest thread delivers it at
//! its next kernel exit or time-slice stop, every deliverable signal in
//! turn from the lowest number (`bsd_ast`, `postsig_locked`): the handler's
//! mask is applied, `SA_RESETHAND` defaults the action, and the
//! `user_sigframe64` goes onto the guest stack (its alternate stack when
//! the action asks and the thread is not on it) before the thread enters
//! the registered trampoline with the catcher, infostyle, signal, siginfo,
//! ucontext and sigreturn token ([`frame`], `sendsig`). `sigreturn` checks
//! the token, authenticates the returned thread state and restores it. A
//! signal whose action changed to the default before delivery takes the
//! default action, as the host kernel would have; a synchronous exception's
//! signal nobody catches ends the process by that signal.
use super::{Call, EFAULT, EINVAL, ENOMEM, EPERM, Kernel, Outcome, forward};
use crate::hosted::kernel::{End, Pe, status};
use crate::hosted::{Termination, forward as host_call, memory, threads::lock};
use crate::machine::system::Register;
use anyhow::Result;
use frame::{MachineContext, Placement, Siginfo, ThreadState, UserContext};
use host::{SIGNALS, Sender, Slot};
use std::sync::{Arc, Mutex, Weak};

mod frame;
pub(crate) mod host;

pub(crate) const SIGILL: u32 = 4;
pub(crate) const SIGTRAP: u32 = 5;
const SIGKILL: u64 = 9;
pub(crate) const SIGBUS: u32 = 10;
pub(crate) const SIGSEGV: u32 = 11;
const SIGSTOP: u64 = 17;
const SIGCHLD: u32 = 20;
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SA_ONSTACK: u32 = 0x0001;
const SA_RESTART: u32 = 0x0002;
const SA_RESETHAND: u32 = 0x0004;
const SA_NOCLDSTOP: u32 = 0x0008;
const SA_NODEFER: u32 = 0x0010;
const SA_NOCLDWAIT: u32 = 0x0020;
const SA_SIGINFO: u32 = 0x0040;
const SA_VALIDATE_SIGRETURN_FROM_SIGTRAMP: u32 = 0x0400;
const SA_USERSPACE_MASK: u32 =
    SA_ONSTACK | SA_RESTART | SA_RESETHAND | SA_NOCLDSTOP | SA_NODEFER | SA_NOCLDWAIT | SA_SIGINFO;
const SIG_BLOCK: u64 = 1;
const SIG_UNBLOCK: u64 = 2;
const SIG_SETMASK: u64 = 3;
/// `OLDMINSIGSTKSZ`: the smallest alternate stack `sigaltstack` takes.
const MINIMUM_STACK: u64 = 8 << 10;
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 4;
/// `UC_TRAD` and `UC_FLAVOR`: the infostyle of a handler without and with
/// `SA_SIGINFO`.
const UC_TRAD: u64 = 1;
const UC_FLAVOR: u64 = 30;
/// `sigprop`'s `SA_IGNORE` signals: URG, CONT, CHLD, IO, WINCH and INFO.
const DEFAULT_IGNORED: u32 = bit(16) | bit(19) | bit(20) | bit(23) | bit(28) | bit(29);
/// `sigprop`'s `SA_STOP` signals a handler can catch: TSTP, TTIN and TTOU.
const DEFAULT_STOPS: u32 = bit(18) | bit(21) | bit(22);
/// `si_code`s `sendsig` sets.
const ILL_ILLTRP: i32 = 2;
const BUS_ADRALN: i32 = 1;
const SEGV_MAPERR: i32 = 1;
pub(crate) const SEGV_ACCERR: i32 = 2;
pub(super) const EINTR: u64 = 4;
const ENOTSUP: u64 = 45;

const fn bit(signal: u64) -> u32 {
    1 << (signal - 1)
}

#[derive(Debug, Clone, Copy, Default)]
struct Action {
    handler: u64,
    /// The signal trampoline (`sa_tramp`, `ps_trampact`), authenticated as
    /// a function pointer.
    trampoline: u64,
    /// `ps_catchmask`.
    mask: u32,
    flags: u32,
}

impl Action {
    fn caught(&self) -> bool {
        self.handler != SIG_DFL && self.handler != SIG_IGN
    }
}

/// `ps_sigreturn_validation`: fixed by the process's first `sigaction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigreturnValidation {
    Default,
    Enabled,
    Disabled,
}

/// The process's signal actions (`p_sigacts`) and SIGCHLD flags.
#[derive(Debug, Clone)]
pub(crate) struct Actions {
    actions: [Action; SIGNALS],
    /// `P_NOCLDSTOP` and `P_NOCLDWAIT`.
    no_child_stop: bool,
    no_child_wait: bool,
    validation: SigreturnValidation,
}

impl Actions {
    /// The actions exec leaves (`execsigs`): ignored signals stay ignored,
    /// every other signal is defaulted.
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
        Self {
            no_child_wait: actions[SIGCHLD as usize].handler == SIG_IGN,
            actions,
            no_child_stop: false,
            validation: SigreturnValidation::Default,
        }
    }

    fn get(&self, signal: u32) -> Action {
        self.actions[signal as usize]
    }

    /// `setsigvec`.
    fn set(&mut self, signal: u32, action: Action) {
        self.actions[signal as usize] = Action {
            mask: action.mask & !CANT_MASK,
            ..action
        };
        if signal == SIGCHLD {
            self.no_child_stop = action.flags & SA_NOCLDSTOP != 0;
            self.no_child_wait = action.flags & SA_NOCLDWAIT != 0 || action.handler == SIG_IGN;
        }
    }

    /// The `struct sigaction` `sigaction` reports: the mask and every flag
    /// but `SA_RESETHAND`, with the SIGCHLD flags from the process.
    fn reported(&self, signal: u32) -> Action {
        let action = self.get(signal);
        let mut flags = action.flags & (SA_ONSTACK | SA_RESTART | SA_SIGINFO | SA_NODEFER);
        if signal == SIGCHLD {
            if self.no_child_stop {
                flags |= SA_NOCLDSTOP;
            }
            if self.no_child_wait {
                flags |= SA_NOCLDWAIT;
            }
        }
        Action { flags, ..action }
    }
}

/// The signal slots of the process's threads, which `sigprocmask` sets
/// the masks of.
#[derive(Default)]
pub(crate) struct Slots(Mutex<Vec<Weak<Slot>>>);

impl Slots {
    fn add(&self, slot: &Arc<Slot>) {
        let mut slots = lock(&self.0);
        slots.retain(|slot| slot.strong_count() != 0);
        slots.push(Arc::downgrade(slot));
    }

    fn each(&self, mut apply: impl FnMut(&Slot)) {
        for slot in lock(&self.0).iter().filter_map(Weak::upgrade) {
            apply(&slot);
        }
    }
}

/// In a fork child: the forking thread is the only one, and no signal is
/// pending (`forkproc` clears `p_siglist`).
pub(super) fn fork_child(kernel: &Kernel) {
    let own = Arc::downgrade(&kernel.signals.slot);
    *lock(&kernel.process.signal_slots.0) = vec![own];
    kernel.signals.slot.clear();
    host::unclaimed().clear();
}

/// A thread's alternate signal stack (`uu_sigstk`, `UT_ALTSTACK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Alternate {
    base: u64,
    size: u64,
    flags: u32,
    enabled: bool,
}

/// One thread's signal state: its slot (pending signals and mask), the
/// mask its host thread holds, its alternate stack, its sigreturn
/// validation state and the mask a `sigsuspend` or `pselect` saved
/// (`uu_oldmask` with `UT_SAS_OLDMASK`).
pub(crate) struct ThreadSignals {
    slot: Arc<Slot>,
    _registration: Option<host::Registration>,
    host_mask: Option<u32>,
    alternate: Alternate,
    sigreturn: frame::Sigreturn,
    old_mask: Option<u32>,
}

impl ThreadSignals {
    /// The state of a new thread on its own host thread, with `mask`: the
    /// creator's (`uthread` creation), or the one exec left the main
    /// thread.
    pub(crate) fn new(slots: &Slots, mask: u32) -> Self {
        let slot = Arc::new(Slot::new(mask & !CANT_MASK));
        slots.add(&slot);
        let mut signals = Self {
            _registration: Some(host::Registration::new(slot.clone())),
            slot,
            host_mask: None,
            alternate: Alternate {
                base: 0,
                size: 0,
                flags: SS_DISABLE,
                enabled: false,
            },
            sigreturn: frame::Sigreturn::default(),
            old_mask: None,
        };
        signals.sync();
        signals
    }

    /// The thread's mask (`uu_sigmask`).
    pub(crate) fn mask(&self) -> u32 {
        self.slot.mask()
    }

    /// The mask a thread this one creates starts with.
    pub(crate) fn creation_mask(&self) -> u32 {
        self.old_mask.unwrap_or_else(|| self.mask())
    }

    /// Set the thread's mask.
    pub(crate) fn set_mask(&mut self, mask: u32) {
        self.slot.set_mask(mask & !CANT_MASK);
        self.sync();
    }

    /// Bring the host thread's mask to the guest mask, which another
    /// thread's `sigprocmask` may have changed, and the interrupt flag to
    /// whether a signal is deliverable.
    pub(crate) fn sync(&mut self) {
        if self._registration.is_some() {
            let mask = self.mask();
            if self.host_mask != Some(mask) {
                host::set_host_mask(mask);
                self.host_mask = Some(mask);
            }
        }
        self.slot.rearm(|| self.deliverable().is_some());
    }

    /// Signals recorded for this thread or for no thread in particular.
    fn pending(&self) -> u32 {
        self.slot.pending() | host::unclaimed().pending()
    }

    /// The lowest-numbered pending signal the mask admits (`issignal`).
    pub(crate) fn deliverable(&self) -> Option<u32> {
        let pending = self.pending() & !self.mask();
        (pending != 0).then(|| pending.trailing_zeros() + 1)
    }

    /// Take `signal` off the thread's or the process's pending signals.
    fn take(&self, signal: u32) -> Option<Sender> {
        self.slot
            .take(signal as i32)
            .or_else(|| host::unclaimed().take(signal as i32))
    }

    /// The flag an interruptible forwarded call checks.
    pub(crate) fn interrupt_flag(&self) -> *const u8 {
        self.slot.interrupt_flag()
    }

    /// Block every signal outside `allowed` that a workqueue thread may
    /// block (`~workq_threadmask`), as a new workqueue thread starts and
    /// as one returns to the pool (`workq_thread_return`).
    pub(crate) fn reset_for_workqueue(&mut self, allowed: u32) {
        self.set_mask(self.mask() | (!WORKQ_THREADMASK & !allowed));
    }

    fn on_alternate_stack(&self) -> bool {
        self.alternate.flags & SS_ONSTACK != 0
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
    "sigreturn",
    "sigsuspend",
    "sigsuspend_nocancel",
    "pselect",
    "pselect_nocancel",
];

pub(super) fn call(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "sigaction" => sigaction(kernel, call)?,
        "sigprocmask" => process_mask(kernel, call)?,
        "__pthread_sigmask" => thread_mask(kernel, call)?,
        "__pthread_kill" => thread_kill(kernel, call)?,
        "sigaltstack" => alternate_stack(kernel, call)?,
        "sigreturn" => sigreturn(kernel, pe, call)?,
        "sigsuspend" | "sigsuspend_nocancel" => suspend(kernel, call),
        "pselect" | "pselect_nocancel" => pselect(kernel, call)?,
        "sigpending" => pending(kernel, call)?,
        "__sigwait" | "__sigwait_nocancel" => wait(kernel, call)?,
        "kill"
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
    let signal = signal as u32;
    let mut requested = None;
    if new != 0 {
        // `struct __user64_sigaction`: handler, trampoline, mask, flags.
        let Some(bytes) = memory::read(new, 24) else {
            return Ok(Outcome::Error(EFAULT));
        };
        let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let half = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let flags = half(20);
        requested = Some((
            Action {
                handler: word(0),
                // `__sigaction_user64_to_kern`.
                trampoline: status::function_pointer_from_user(
                    kernel.process.signer.as_ref(),
                    word(8),
                )?,
                mask: half(16),
                flags: flags & SA_USERSPACE_MASK,
            },
            if flags & SA_VALIDATE_SIGRETURN_FROM_SIGTRAMP != 0 {
                SigreturnValidation::Enabled
            } else {
                SigreturnValidation::Disabled
            },
        ));
    }
    let mut actions = lock(&kernel.process.actions);
    if old != 0 {
        // `struct user64_sigaction`: handler, mask, flags.
        let previous = actions.reported(signal);
        let mut bytes = previous.handler.to_le_bytes().to_vec();
        bytes.extend(previous.mask.to_le_bytes());
        bytes.extend(previous.flags.to_le_bytes());
        if !memory::write(old, &bytes) {
            return Ok(Outcome::Error(EFAULT));
        }
    }
    if let Some((action, validation)) = requested {
        if actions.validation == SigreturnValidation::Default {
            actions.validation = validation;
        }
        host::mirror(signal as i32, action.handler, action.flags)?;
        actions.set(signal, action);
    }
    Ok(Outcome::value(0))
}

/// `sigprocmask(how, set, oset)`: the mask of every thread of the process
/// (`block_procsigmask`, `unblock_procsigmask`, `set_procsigmask`), the
/// calling thread's old mask reported. The other threads' host masks
/// follow at their next kernel exit or time-slice stop.
fn process_mask(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [how, set, old, ..] = call.arguments;
    let previous = kernel.signals.mask();
    if set != 0 {
        let Some(requested) = memory::read_u32(set) else {
            return Ok(Outcome::Error(EFAULT));
        };
        let requested = requested & !CANT_MASK;
        let (set, clear) = match how {
            SIG_BLOCK => (requested, 0),
            SIG_UNBLOCK => (0, requested),
            SIG_SETMASK => (requested, !requested),
            _ => return Ok(Outcome::Error(EINVAL)),
        };
        kernel
            .process
            .signal_slots
            .each(|slot| slot.update_mask(set, clear));
        kernel.signals.sync();
    }
    if old != 0 {
        // `copyout`'s failure is not reported.
        memory::write_u32(old, previous);
    }
    Ok(Outcome::value(0))
}

/// `__pthread_sigmask(how, set, oset)`: the calling thread's mask.
fn thread_mask(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [how, set, old, ..] = call.arguments;
    let previous = kernel.signals.mask();
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
    if old != 0 {
        memory::write_u32(old, previous);
    }
    Ok(Outcome::value(0))
}

/// `sigaltstack(nss, oss)` with `struct user64_sigaltstack`: base, size,
/// flags.
fn alternate_stack(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [new, old, ..] = call.arguments;
    let alternate = &mut kernel.signals.alternate;
    if !alternate.enabled {
        alternate.flags |= SS_DISABLE;
    }
    let on_stack = alternate.flags & SS_ONSTACK != 0;
    if old != 0 {
        let mut bytes = alternate.base.to_le_bytes().to_vec();
        bytes.extend(alternate.size.to_le_bytes());
        bytes.extend(alternate.flags.to_le_bytes());
        bytes.extend([0u8; 4]);
        if !memory::write(old, &bytes) {
            return Ok(Outcome::Error(EFAULT));
        }
    }
    if new == 0 {
        return Ok(Outcome::value(0));
    }
    let Some(bytes) = memory::read(new, 24) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let base = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    // `sigaltstack`'s order: unknown flags; a disable, refused while the
    // thread runs on the stack; then an enable, refused while it does,
    // and refused below the old 8 KiB minimum.
    if flags & !SS_DISABLE != 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    if flags & SS_DISABLE != 0 {
        if alternate.flags & SS_ONSTACK != 0 {
            return Ok(Outcome::Error(EINVAL));
        }
        alternate.enabled = false;
        alternate.flags = flags;
        return Ok(Outcome::value(0));
    }
    if on_stack {
        return Ok(Outcome::Error(EPERM));
    }
    if size < MINIMUM_STACK {
        return Ok(Outcome::Error(ENOMEM));
    }
    *alternate = Alternate {
        base,
        size,
        flags,
        enabled: true,
    };
    Ok(Outcome::value(0))
}

/// `sigreturn` infostyles that only set or clear whether the thread runs
/// on its alternate stack (`UC_SET_ALT_STACK`, `UC_RESET_ALT_STACK`), as
/// `siglongjmp` out of a handler does.
const UC_SET_ALT_STACK: u64 = 0x4000_0000;
const UC_RESET_ALT_STACK: u64 = 0x8000_0000;

impl ThreadSignals {
    /// Apply a `sigreturn` alternate-stack infostyle: whether it was one.
    fn set_on_stack(&mut self, infostyle: u64) -> bool {
        match infostyle as u32 as u64 {
            UC_SET_ALT_STACK => self.alternate.flags |= SS_ONSTACK,
            UC_RESET_ALT_STACK => self.alternate.flags &= !SS_ONSTACK,
            _ => return false,
        }
        true
    }
}

/// `sigreturn(uctx, infostyle, token)`: restore the context a signal
/// frame holds. The alternate-stack flag and the mask are restored first;
/// a token or a thread state that does not validate then refuses the rest
/// with EINVAL.
fn sigreturn(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let [context, infostyle, token, ..] = call.arguments;
    if kernel.signals.set_on_stack(infostyle) {
        return Ok(Outcome::value(0));
    }
    // `sigreturn_copyin_ctx64`.
    let Some(bytes) = memory::read(context, frame::UCONTEXT_BYTES) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let user = UserContext::from_bytes(&bytes);
    if user.mcsize != frame::UC_FLAVOR_SIZE64 {
        return Ok(Outcome::Error(EINVAL));
    }
    let Some(bytes) = memory::read(user.mcontext, frame::MCONTEXT_BYTES) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let mut machine = MachineContext::from_bytes(&bytes);
    if user.onstack & 1 != 0 {
        kernel.signals.alternate.flags |= SS_ONSTACK;
    } else {
        kernel.signals.alternate.flags &= !SS_ONSTACK;
    }
    kernel.signals.set_mask(user.sigmask);
    let validation = lock(&kernel.process.actions).validation;
    let process = kernel.process.clone();
    let signer = process.signer.as_ref();
    let expected = frame::ucontext_pointer(signer, context)? ^ kernel.signals.sigreturn.token;
    if token != expected && validation != SigreturnValidation::Disabled {
        return Ok(Outcome::Error(EINVAL));
    }
    let checks = match validation {
        SigreturnValidation::Disabled => frame::Validation::None,
        _ => frame::Validation::Tokens,
    };
    if !frame::from_user(&mut machine.ss, signer, &kernel.signals.sigreturn, checks)? {
        return Ok(Outcome::Error(EINVAL));
    }
    let state = &mut pe.cpu.state;
    state.x[..29].copy_from_slice(&machine.ss.x);
    state.x[29] = machine.ss.fp;
    state.x[30] = machine.ss.lr;
    state.v = machine.v;
    state.fpsr = machine.fpsr;
    state.fpcr = machine.fpcr;
    pe.cpu.set_sp(0, machine.ss.sp);
    set_user_pc(pe, machine.ss.pc);
    set_user_cpsr(pe, machine.ss.cpsr);
    let sigreturn = &mut kernel.signals.sigreturn;
    sigreturn.pending = sigreturn.pending.saturating_sub(1);
    Ok(Outcome::JustReturn)
}

/// `sigsuspend(mask)` and `sigsuspend_nocancel`: the mask is set until a
/// caught signal arrives, whose handler returns to the previous mask
/// (`UT_SAS_OLDMASK`); always EINTR. The host's own call with the same
/// mask sleeps (its cancellation point for `sigsuspend`), interruptibly,
/// so a signal recorded before it sleeps returns at once.
fn suspend(kernel: &mut Kernel, call: &Call) -> Outcome {
    let mask = call.argument(0) as u32 & !CANT_MASK;
    kernel.signals.old_mask = Some(kernel.signals.mask());
    kernel.signals.set_mask(mask);
    let interrupt = kernel.signals.interrupt_flag();
    kernel.forwarding(|| {
        host_call::bsd_interruptible(
            call.entry.number,
            &[u64::from(mask & !host::OWNED_MASK)],
            interrupt,
        )
    });
    Outcome::Error(EINTR)
}

/// `pselect(nd, in, ou, ex, ts, mask)`: with a mask, the mask is set for
/// the wait, and kept for the caught signal's handler to return from when
/// it ends in EINTR; otherwise restored. The host's call waits without a
/// mask of its own; `select` is never restarted after a signal.
fn pselect(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let mask_address = call.argument(5);
    if mask_address == 0 {
        return forward(kernel, call);
    }
    let Some(mask) = memory::read_u32(mask_address) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let previous = kernel.signals.mask();
    kernel.signals.old_mask = Some(previous);
    kernel.signals.set_mask(mask);
    let mut unmasked = Call {
        entry: call.entry,
        arguments: call.arguments,
    };
    unmasked.arguments[5] = 0;
    let outcome = match forward(kernel, &unmasked)? {
        Outcome::Restart => Outcome::Error(EINTR),
        outcome => outcome,
    };
    if outcome != Outcome::Error(EINTR) {
        kernel.signals.old_mask = None;
        kernel.signals.set_mask(previous);
    }
    Ok(outcome)
}

/// `sigpending(osv)`: the host's pending signals, which the host masks
/// hold, and those recorded for the thread, without SIGKILL and SIGSTOP.
fn pending(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let address = call.argument(0);
    let outcome = forward(kernel, call)?;
    if address != 0
        && outcome == Outcome::value(0)
        && let Some(host) = memory::read_u32(address)
    {
        memory::write_u32(address, (host | kernel.signals.pending()) & !CANT_MASK);
    }
    Ok(outcome)
}

/// `__sigwait(set, sig)`: a signal of the set recorded for the thread is
/// taken at once; otherwise the host waits for one.
fn wait(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [set, out, ..] = call.arguments;
    if set == 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    let Some(requested) = memory::read_u32(set) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let waited = requested & !CANT_MASK;
    if waited == 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    let recorded = kernel.signals.pending() & waited;
    if recorded != 0 {
        let signal = recorded.trailing_zeros() + 1;
        kernel.signals.take(signal);
        kernel.signals.sync();
        if out != 0 && !memory::write_u32(out, signal) {
            return Ok(Outcome::Error(EFAULT));
        }
        return Ok(Outcome::value(0));
    }
    forward(kernel, call)
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

/// The interrupted user context's pc: ELR_EL1 at a kernel entry, the PE's
/// own pc at a time-slice stop.
fn user_pc(pe: &Pe) -> u64 {
    if pe.cpu.pstate.el == 0 {
        pe.cpu.pc
    } else {
        pe.cpu.read(Register::ELR_EL1)
    }
}

fn set_user_pc(pe: &mut Pe, pc: u64) {
    if pe.cpu.pstate.el == 0 {
        pe.cpu.pc = pc;
    } else {
        pe.cpu.registers.set_raw(Register::ELR_EL1, 0, pc);
    }
}

/// The interrupted user context's CPSR.
fn user_cpsr(pe: &Pe) -> u32 {
    if pe.cpu.pstate.el == 0 {
        pe.cpu.pstate.to_spsr(pe.cpu.state.nzcv) as u32
    } else {
        pe.cpu.read(Register::SPSR_EL1) as u32
    }
}

/// Set the user CPSR as a thread state does: NZCV from `requested`, the
/// rest kept, at EL0t.
fn set_user_cpsr(pe: &mut Pe, requested: u32) {
    if pe.cpu.pstate.el == 0 {
        pe.cpu.state.nzcv = requested & frame::PSR64_NZCV_MASK;
    } else {
        let current = pe.cpu.read(Register::SPSR_EL1);
        let cpsr = frame::user_cpsr(current as u32, requested);
        pe.cpu.registers.set_raw(
            Register::SPSR_EL1,
            0,
            (current & !0xffff_ffff) | u64::from(cpsr),
        );
    }
}

/// The user thread state as `thread_getstatus` reads it.
fn thread_state(pe: &Pe) -> ThreadState {
    let mut x = [0u64; 29];
    x.copy_from_slice(&pe.cpu.state.x[..29]);
    ThreadState {
        x,
        fp: pe.cpu.state.x[29],
        lr: pe.cpu.state.x[30],
        sp: pe.cpu.sp(0),
        pc: user_pc(pe),
        cpsr: user_cpsr(pe),
        flags: 0,
    }
}

/// A fault's signal by `ux_exception`: an address no mapping holds is
/// KERN_INVALID_ADDRESS (SIGSEGV), any other fault the mapping refuses
/// KERN_PROTECTION_FAILURE or an alignment fault (SIGBUS), except that a
/// protection fault in the main stack's reach is a stack overflow
/// (SIGSEGV), whose handler must run on the alternate stack. `code` is the
/// `si_code` `sendsig` gives it from the exception's code: SEGV_MAPERR for
/// an invalid address, SEGV_ACCERR (BUS_ADRERR's value) for a protection
/// failure, BUS_ADRALN for an alignment fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FaultSignal {
    pub signal: u32,
    pub code: i32,
    pub stack_overflow: bool,
}

/// `MAXSSIZ`: how far below the main stack's top an overflow reaches.
const MAXIMUM_STACK: u64 = 64 << 20;

impl FaultSignal {
    pub(crate) fn of(address: u64, mapped: bool, alignment: bool, user_stack: u64) -> Self {
        if alignment {
            return Self {
                signal: SIGBUS,
                code: BUS_ADRALN,
                stack_overflow: false,
            };
        }
        if !mapped {
            return Self {
                signal: SIGSEGV,
                code: SEGV_MAPERR,
                stack_overflow: false,
            };
        }
        let stack_overflow =
            (user_stack.saturating_sub(MAXIMUM_STACK)..user_stack).contains(&address);
        Self {
            signal: if stack_overflow { SIGSEGV } else { SIGBUS },
            code: SEGV_ACCERR,
            stack_overflow,
        }
    }
}

impl Kernel {
    /// The signal of a synchronous exception the thread took
    /// (`handle_ux_exception`, `threadsignal`): pending for the thread
    /// when its handler catches it unmasked, and otherwise the end of the
    /// process by it. XNU drops an ignored one and holds a masked one,
    /// and the thread takes the exception again at once; the hosted
    /// process ends instead, saying why on standard error.
    pub(crate) fn exception_signal(
        &mut self,
        signal: u32,
        code: i32,
        stack_overflow: bool,
        describe: impl FnOnce() -> String,
    ) {
        let action = lock(&self.process.actions).get(signal);
        let unmasked = self.signals.mask() & bit(u64::from(signal)) == 0;
        // A stack overflow is delivered only on the alternate stack.
        let ready = !stack_overflow || action.flags & SA_ONSTACK != 0;
        if action.caught() && unmasked && ready {
            self.signals.slot.record(
                signal as i32,
                Sender {
                    code,
                    ..Sender::default()
                },
            );
            return;
        }
        eprintln!("stela: {}: signal {signal} ends the process", describe());
        self.end = Some(End::Process(Termination::Signaled(signal as i32)));
    }

    /// Deliver every deliverable signal, lowest number first, each frame
    /// above the last (`bsd_ast`): at a kernel exit or a time-slice stop.
    pub(crate) fn deliver_pending(&mut self, pe: &mut Pe) -> Result<()> {
        self.signals.sync();
        while self.end.is_none()
            && let Some(signal) = self.signals.deliverable()
        {
            self.post(pe, signal)?;
        }
        // A `sigsuspend` or `pselect` no caught signal ended returns to
        // its mask.
        if let Some(mask) = self.signals.old_mask.take() {
            self.signals.set_mask(mask);
        }
        self.signals.sync();
        Ok(())
    }

    /// `postsig_locked`: take `signal` and act on it.
    fn post(&mut self, pe: &mut Pe, signal: u32) -> Result<()> {
        let sender = self.signals.take(signal).unwrap_or_default();
        let mut actions = lock(&self.process.actions);
        let action = actions.get(signal);
        let signal_bit = bit(u64::from(signal));
        if !action.caught() {
            drop(actions);
            // The action changed since the host recorded the signal: the
            // default action, or nothing for an ignored signal.
            if action.handler == SIG_DFL && DEFAULT_IGNORED & signal_bit == 0 {
                if DEFAULT_STOPS & signal_bit != 0 {
                    host::raise(signal as i32);
                } else {
                    self.end = Some(End::Process(Termination::Signaled(signal as i32)));
                }
            }
            return Ok(());
        }
        let returnmask = self
            .signals
            .old_mask
            .take()
            .unwrap_or_else(|| self.signals.mask());
        let mut mask = self.signals.mask() | action.mask;
        if action.flags & SA_NODEFER == 0 {
            mask |= signal_bit;
        }
        let infostyle = if action.flags & SA_SIGINFO != 0 {
            UC_FLAVOR
        } else {
            UC_TRAD
        };
        if signal != SIGILL && signal != SIGTRAP && action.flags & SA_RESETHAND != 0 {
            actions.actions[signal as usize] = Action {
                handler: SIG_DFL,
                flags: action.flags & !(SA_SIGINFO | SA_NODEFER),
                ..action
            };
            host::mirror(signal as i32, SIG_DFL, action.flags)?;
        }
        drop(actions);
        self.signals.set_mask(mask);
        if !self.send(pe, &action, signal, returnmask, infostyle, sender)? {
            // `sendsig`'s failure: SIGILL by its default action.
            self.end = Some(End::Process(Termination::Signaled(SIGILL as i32)));
        }
        Ok(())
    }

    /// `sendsig`: build the signal frame and enter the trampoline. False
    /// when the frame cannot be written.
    fn send(
        &mut self,
        pe: &mut Pe,
        action: &Action,
        signal: u32,
        returnmask: u32,
        infostyle: u64,
        sender: Sender,
    ) -> Result<bool> {
        let process = self.process.clone();
        let signer = process.signer.as_ref();
        let signals = &mut self.signals;
        signals.sigreturn.arm(random_word);
        let raw = thread_state(pe);
        let mut ss = raw;
        frame::to_user(&mut ss, signer, &signals.sigreturn)?;
        let machine = MachineContext {
            far: pe.cpu.read(Register::FAR_EL1),
            esr: pe.cpu.read(Register::ESR_EL1) as u32,
            exception: 0,
            ss,
            v: pe.cpu.state.v,
            fpsr: pe.cpu.state.fpsr,
            fpcr: pe.cpu.state.fpcr,
        };
        let on_stack = signals.on_alternate_stack();
        let alternate = signals.alternate.enabled && !on_stack && action.flags & SA_ONSTACK != 0;
        let (top, stack_size) = if alternate {
            signals.alternate.flags |= SS_ONSTACK;
            (
                signals.alternate.base + signals.alternate.size,
                signals.alternate.size,
            )
        } else {
            (raw.sp, 0)
        };
        let placement = Placement::below(top);
        let user = UserContext {
            onstack: i32::from(on_stack),
            sigmask: returnmask,
            stack_pointer: placement.sp,
            stack_size,
            stack_flags: if on_stack { SS_ONSTACK } else { 0 },
            link: 0,
            mcsize: frame::UC_FLAVOR_SIZE64,
            mcontext: placement.mcontext,
        };
        let mut info = Siginfo {
            signo: signal as i32,
            addr: raw.pc,
            sp: raw.sp,
            ..Siginfo::default()
        };
        match signal {
            SIGILL => info.code = ILL_ILLTRP,
            // As `sendsig`: the fault address and the exception's code
            // (`FaultSignal`); no sender is reported.
            SIGBUS | SIGSEGV => {
                info.addr = machine.far;
                info.code = sender.code;
            }
            // `p->si_pid` and the rest: the host kernel's siginfo.
            _ => {
                info.pid = sender.pid;
                info.uid = sender.uid;
                info.code = sender.code;
                info.status = sender.status;
            }
        }
        let token = frame::ucontext_pointer(signer, placement.ucontext)? ^ signals.sigreturn.token;
        let mut bytes = Vec::with_capacity(frame::FRAME_BYTES as usize);
        bytes.extend(info.to_bytes());
        bytes.extend(user.to_bytes());
        bytes.extend(machine.to_bytes());
        if !memory::write(placement.sp, &bytes) {
            signals.sigreturn.pending -= 1;
            return Ok(false);
        }
        if self.trace {
            eprintln!(
                "stela: signal {signal} to handler {:#x} through {:#x} with frame {:#x} \
                 (interrupted pc {:#x})",
                action.handler, action.trampoline, placement.sp, raw.pc
            );
        }
        let arguments = [
            action.handler,
            infostyle,
            u64::from(signal),
            placement.siginfo,
            placement.ucontext,
            token,
        ];
        pe.cpu.state.x[..arguments.len()].copy_from_slice(&arguments);
        pe.cpu.set_sp(0, placement.sp);
        set_user_pc(pe, action.trampoline);
        // `PSR64_USER64_DEFAULT`.
        set_user_cpsr(pe, crate::hosted::pe::user_spsr() as u32);
        Ok(true)
    }
}

/// `read_random`: one word from the host's entropy source.
fn random_word() -> u64 {
    let mut word = [0u8; 8];
    // SAFETY: eight bytes into this frame.
    let status = unsafe { libc::getentropy(word.as_mut_ptr().cast(), word.len()) };
    assert_eq!(status, 0, "getentropy failed");
    u64::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detached(mask: u32) -> ThreadSignals {
        ThreadSignals {
            slot: Arc::new(Slot::new(mask)),
            _registration: None,
            host_mask: None,
            alternate: Alternate {
                base: 0x1000,
                size: 0x8000,
                flags: 0,
                enabled: true,
            },
            sigreturn: frame::Sigreturn::default(),
            old_mask: None,
        }
    }

    #[test]
    fn the_alternate_stack_flag_follows_sigreturn() {
        let mut signals = detached(0);
        assert!(signals.set_on_stack(UC_SET_ALT_STACK));
        assert_eq!(signals.alternate.flags, SS_ONSTACK);
        assert!(signals.set_on_stack(UC_RESET_ALT_STACK));
        assert_eq!(signals.alternate.flags, 0);
        assert!(!signals.set_on_stack(UC_FLAVOR));
        assert!(!signals.set_on_stack(UC_TRAD));
    }

    #[test]
    fn the_workqueue_thread_mask_is_xnus() {
        assert_eq!(WORKQ_THREADMASK, 0x0401_1fd8);
        assert_eq!(CANT_MASK & WORKQ_THREADMASK, CANT_MASK);
    }

    #[test]
    fn deliverable_signals_come_lowest_first_and_respect_the_mask() {
        let signals = detached(bit(2));
        signals.slot.record(30, Sender::default());
        signals.slot.record(2, Sender::default());
        signals.slot.record(20, Sender::default());
        assert_eq!(signals.deliverable(), Some(20));
        assert!(signals.take(20).is_some());
        assert_eq!(signals.deliverable(), Some(30));
        assert!(signals.take(30).is_some());
        // SIGINT stays pending behind the mask.
        assert_eq!(signals.deliverable(), None);
        assert_eq!(signals.pending() & bit(2), bit(2));
    }

    #[test]
    fn sigaction_reports_neither_resethand_nor_another_signals_child_flags() {
        let mut actions = Actions {
            actions: [Action::default(); SIGNALS],
            no_child_stop: false,
            no_child_wait: false,
            validation: SigreturnValidation::Default,
        };
        actions.set(
            2,
            Action {
                handler: 0x1_0000_4000,
                trampoline: 0,
                mask: bit(9) | bit(15),
                flags: SA_RESETHAND | SA_NODEFER | SA_NOCLDWAIT,
            },
        );
        let reported = actions.reported(2);
        assert_eq!(reported.flags, SA_NODEFER);
        assert_eq!(reported.mask, bit(15), "sigcantmask is never caught");
        actions.set(
            SIGCHLD,
            Action {
                handler: SIG_IGN,
                ..Action::default()
            },
        );
        // An ignored SIGCHLD also leaves no zombies (`P_NOCLDWAIT`).
        assert_eq!(actions.reported(SIGCHLD).flags, SA_NOCLDWAIT);
    }

    #[test]
    fn faults_map_to_their_signals() {
        let top = 0x1_6fe0_0000;
        let unmapped = FaultSignal::of(0x10, false, false, top);
        assert_eq!(unmapped.code, SEGV_MAPERR);
        assert_eq!(
            FaultSignal::of(0x1_0000_0000, true, false, top).code,
            SEGV_ACCERR
        );
        assert_eq!(FaultSignal::of(0x10, false, true, top).code, BUS_ADRALN);
        assert_eq!(unmapped.signal, SIGSEGV);
        let protected = FaultSignal::of(0x1_0000_0000, true, false, top);
        assert_eq!(protected.signal, SIGBUS);
        let guard = FaultSignal::of(top - (8 << 20), true, false, top);
        assert_eq!((guard.signal, guard.stack_overflow), (SIGSEGV, true));
        assert_eq!(FaultSignal::of(0x10, false, true, top).signal, SIGBUS);
    }
}
