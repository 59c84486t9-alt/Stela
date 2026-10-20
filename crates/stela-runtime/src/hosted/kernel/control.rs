//! Thread suspension and the user thread state another thread reads and
//! sets (`osfmk/kern/thread_act.c`, `osfmk/arm64/status.c`).
//!
//! XNU stops a thread for `thread_suspend` (its user stop count) and, while
//! `thread_get_state` or `thread_set_state` acts on it, for the caller
//! (`thread_hold`): the thread takes the stop at its next return to user
//! space, an AST. The caller of `thread_suspend`, `thread_get_state` and
//! `thread_set_state` then waits until the target is off its CPU
//! (`thread_wait`, `thread_stop`): stopped at that AST or blocked in the
//! kernel. The state those routines read and write is the user state the
//! thread's kernel entry saved (`thread->machine.upcb`).
//!
//! Each guest thread's run loop ([`crate::hosted::threads`]) reports to its
//! [`Control`]: [`Control::enter_kernel`] at each kernel entry publishes the
//! trap frame, and [`Control::leave`] at each return to guest code (kernel
//! exit, a time-slice boundary, the end of a wait, the thread's first
//! instruction) parks the thread while it is stopped, publishing its state,
//! and applies a state another thread set. A state set while the thread is
//! in a system call is the trap frame's, which the call's own return values
//! then overwrite, as XNU's syscall return writes them into the saved
//! state: each register the call changed keeps the call's value.
use super::Pe;
use super::status;
use crate::hosted::darwin::{
    ARM_DEBUG_STATE64, DEBUG_STATE64_COUNT, DISCRIMINATOR_FP, DISCRIMINATOR_LR, DISCRIMINATOR_PC,
    DISCRIMINATOR_SP, FLAGS_IB_SIGNED_LR, FLAGS_KERNEL_SIGNED_LR, FLAGS_KERNEL_SIGNED_PC,
    FLAGS_NO_PTRAUTH, PSR64_NZCV_MASK, USER_DIVERSIFIER_MASK, blend_discriminator, user_cpsr,
};
use crate::machine::system::Register;
use crate::pauth::{Context, Key};
use anyhow::{Result, bail};
use std::sync::{
    Condvar, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// `kern_return_t` values these routines answer.
pub(crate) const KERN_SUCCESS: u32 = 0;
pub(crate) const KERN_INVALID_ARGUMENT: u32 = 4;
pub(crate) const KERN_FAILURE: u32 = 5;
pub(crate) const KERN_PROTECTION_FAILURE: u32 = 2;
pub(crate) const KERN_TERMINATED: u32 = 37;

/// The user state of a thread, as `arm_saved_state64` and
/// `arm_neon_saved_state64` hold it: X0..X28, FP and LR in `x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct UserState {
    pub(crate) x: [u64; 31],
    pub(crate) sp: u64,
    pub(crate) pc: u64,
    pub(crate) cpsr: u32,
    pub(crate) v: [[u64; 2]; 32],
    pub(crate) fpsr: u32,
    pub(crate) fpcr: u32,
    pub(crate) far: u64,
    pub(crate) esr: u64,
}

impl UserState {
    /// The thread's user state: the trap frame at a kernel entry (ELR_EL1,
    /// SPSR_EL1, FAR_EL1 and ESR_EL1), the live registers at a time-slice
    /// boundary, where the saved exception state is an interrupt's.
    pub(crate) fn capture(pe: &Pe) -> Self {
        let cpu = &pe.cpu;
        let at_entry = cpu.pstate.el != 0;
        Self {
            x: cpu.state.x,
            sp: cpu.sp(0),
            pc: if at_entry {
                cpu.read(Register::ELR_EL1)
            } else {
                cpu.pc
            },
            cpsr: if at_entry {
                cpu.read(Register::SPSR_EL1) as u32
            } else {
                cpu.pstate.to_spsr(cpu.state.nzcv) as u32
            },
            v: cpu.state.v,
            fpsr: cpu.state.fpsr,
            fpcr: cpu.state.fpcr,
            far: if at_entry {
                cpu.read(Register::FAR_EL1)
            } else {
                0
            },
            esr: if at_entry {
                cpu.read(Register::ESR_EL1)
            } else {
                0
            },
        }
    }

    /// Make this the thread's user state, as `thread_state64_to_saved_state`
    /// and the NEON copy do: NZCV of the CPSR is copied, its mode reset to
    /// EL0t, the rest kept. The exception state is not settable.
    pub(crate) fn apply(&self, pe: &mut Pe) {
        let cpu = &mut pe.cpu;
        cpu.state.x = self.x;
        cpu.state.v = self.v;
        cpu.state.fpsr = self.fpsr;
        cpu.state.fpcr = self.fpcr;
        cpu.set_sp(0, self.sp);
        if cpu.pstate.el == 0 {
            cpu.pc = self.pc;
            cpu.state.nzcv = self.cpsr & PSR64_NZCV_MASK;
        } else {
            cpu.registers.set_raw(Register::ELR_EL1, 0, self.pc);
            let current = cpu.read(Register::SPSR_EL1);
            let cpsr = user_cpsr(current as u32, self.cpsr);
            cpu.registers.set_raw(
                Register::SPSR_EL1,
                0,
                (current & !0xffff_ffff) | u64::from(cpsr),
            );
        }
    }

    /// The state `set` leaves on a thread whose kernel entry saved `entry`
    /// and whose system call has since left `now`: each register the call
    /// changed keeps the call's value.
    fn merged(entry: &Self, now: &Self, set: &Self) -> Self {
        let pick = |entry: u64, now: u64, set: u64| if now != entry { now } else { set };
        let mut merged = *set;
        for index in 0..31 {
            merged.x[index] = pick(entry.x[index], now.x[index], set.x[index]);
        }
        merged.sp = pick(entry.sp, now.sp, set.sp);
        merged.pc = pick(entry.pc, now.pc, set.pc);
        merged.cpsr = pick(
            u64::from(entry.cpsr),
            u64::from(now.cpsr),
            u64::from(set.cpsr),
        ) as u32;
        for index in 0..32 {
            for half in 0..2 {
                merged.v[index][half] =
                    pick(entry.v[index][half], now.v[index][half], set.v[index][half]);
            }
        }
        merged.fpsr = pick(entry.fpsr.into(), now.fpsr.into(), set.fpsr.into()) as u32;
        merged.fpcr = pick(entry.fpcr.into(), now.fpcr.into(), set.fpcr.into()) as u32;
        merged
    }
}

/// Where the thread is, for those waiting for it to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Place {
    /// Created, before its first instruction.
    #[default]
    Starting,
    Running,
    /// In a kernel call, its trap frame published.
    Kernel,
    /// Stopped at a return to guest code, its state published.
    Parked,
    Ended,
}

#[derive(Debug, Default)]
struct Inner {
    /// `user_stop_count`: suspensions not yet resumed.
    user_stops: u32,
    /// `legacy_user_stop_count`: those of them `thread_suspend` made (or
    /// a thread's creation), which only `thread_resume` resumes.
    legacy_stops: u32,
    /// The thread's suspension tokens (`thread_suspend2`).
    token: Token,
    /// `thread_hold`s of callers acting on the stopped thread.
    holds: u32,
    place: Place,
    /// The state at the kernel entry, while in the kernel.
    entry: Option<UserState>,
    /// The state readers see while the thread is stopped.
    published: Option<UserState>,
    /// A state set while stopped, applied when it returns to guest code.
    pending: Option<UserState>,
    /// The process ended: nothing parks any more.
    closed: bool,
    /// `thread_terminate`: the thread never returns to guest code.
    terminated: bool,
    /// It has executed guest code.
    started: bool,
    /// In a call the host kernel performs for it, which a host
    /// `thread_abort` interrupts.
    forwarding: bool,
}

impl Inner {
    fn stopping(&self) -> bool {
        self.user_stops + self.holds > 0 || self.terminated
    }

    /// `!thread->active`.
    fn inactive(&self) -> bool {
        self.place == Place::Ended || self.terminated
    }
}

/// A thread's resume port (`thread->thread_resume_port`), which
/// [`super::mach::suspension`] keeps: the receive right, null until the
/// first `thread_suspend2`, and whether its no-senders notification is
/// requested.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) port: u32,
    pub(crate) armed: bool,
}

/// How a thread was made, which decides what `thread_terminate` may do
/// to it and whether its port right is pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Kind {
    /// The process's first thread (`THREAD_TAG_MAINTHREAD`).
    #[default]
    Main,
    /// `bsdthread_create` or the workqueue's (`THREAD_TAG_PTHREAD`).
    Pthread,
    /// `thread_create`: its port right is not pinned.
    Mach,
}

/// One guest thread's suspension and published user state.
#[derive(Debug, Default)]
pub(crate) struct Control {
    inner: Mutex<Inner>,
    changed: Condvar,
    /// `user_stops + holds > 0`, for the run loop's slice check.
    stopping: AtomicBool,
    kind: Mutex<Kind>,
    /// TPIDRRO_EL0, its TSD base (`machine.cthread_self`), which no thread
    /// state sets.
    thread_pointer: AtomicU64,
}

/// Where a thread is, as its tests see it.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// Stopped, its state published.
    State,
    /// Off its CPU before its first instruction.
    Starting,
    Ended,
}

impl Control {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait<'a>(&self, inner: MutexGuard<'a, Inner>) -> MutexGuard<'a, Inner> {
        self.changed
            .wait(inner)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn update(&self, inner: &Inner) {
        self.stopping.store(inner.stopping(), Ordering::SeqCst);
        self.changed.notify_all();
    }

    /// The run loop's slice check: a stop is requested.
    pub(crate) fn pending(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// A kernel entry: publish the trap frame.
    pub(crate) fn enter_kernel(&self, pe: &Pe) {
        let state = UserState::capture(pe);
        let mut inner = self.lock();
        inner.place = Place::Kernel;
        inner.entry = Some(state);
        inner.published = Some(state);
        self.update(&inner);
    }

    /// A return to guest code, with the execution lock not held: a state
    /// set during a kernel call is applied, then the thread parks while it
    /// is stopped, publishing its state, and takes a state set meanwhile.
    /// False once the process ended, when the thread must not run again.
    pub(crate) fn leave(&self, pe: &mut Pe) -> bool {
        let mut inner = self.lock();
        if inner.place == Place::Kernel
            && let (Some(entry), Some(set)) = (inner.entry, inner.pending.take())
        {
            UserState::merged(&entry, &UserState::capture(pe), &set).apply(pe);
        }
        inner.entry = None;
        while inner.stopping() && !inner.closed && !inner.terminated {
            if inner.place != Place::Parked {
                inner.place = Place::Parked;
                inner.published = Some(UserState::capture(pe));
                self.update(&inner);
            }
            inner = self.wait(inner);
            if let Some(set) = inner.pending.take() {
                set.apply(pe);
                inner.published = Some(set);
            }
        }
        if inner.closed || inner.terminated {
            return false;
        }
        inner.started = true;
        inner.place = Place::Running;
        inner.published = None;
        self.update(&inner);
        true
    }

    /// The thread ended: every waiter sees it gone, and its suspension
    /// tokens are dead names.
    pub(crate) fn ended(&self) {
        let mut inner = self.lock();
        inner.place = Place::Ended;
        inner.published = None;
        inner.pending = None;
        super::mach::suspension::destroy(std::mem::take(&mut inner.token));
        self.update(&inner);
    }

    /// The process ended: a parked thread returns from [`Control::leave`]
    /// and no thread parks again.
    pub(crate) fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        self.update(&inner);
    }

    /// Held across a host `fork` by the forking thread, so that its child
    /// finds the lock free: [`ForkHeld::child`] then gives the child's one
    /// thread, which XNU's fork leaves unsuspended, a fresh control.
    pub(crate) fn hold_for_fork(&self) -> Option<ForkHeld<'_>> {
        match self.inner.try_lock() {
            Ok(inner) => Some(ForkHeld {
                control: self,
                inner,
            }),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(ForkHeld {
                control: self,
                inner: poisoned.into_inner(),
            }),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    /// `thread_suspend`: one more legacy user stop; another thread's
    /// caller then waits until it is off its CPU (`thread_wait(thread,
    /// FALSE)`).
    pub(crate) fn suspend(&self, own: bool) -> u32 {
        match self.stop(own, true, |_| Ok(())) {
            Ok(()) => KERN_SUCCESS,
            Err(code) => code,
        }
    }

    /// `thread_suspend2`: one more user stop, represented by a suspension
    /// token `mint` makes on the thread's resume port while the stop is
    /// counted (`ipc_kobject_make_send` under the thread mutex), or the
    /// failure. The caller then waits as for `thread_suspend`.
    pub(crate) fn suspend_with_token<T>(
        &self,
        own: bool,
        mint: impl FnOnce(&mut Token) -> std::result::Result<T, u32>,
    ) -> std::result::Result<T, u32> {
        self.stop(own, false, mint)
    }

    fn stop<T>(
        &self,
        own: bool,
        legacy: bool,
        mint: impl FnOnce(&mut Token) -> std::result::Result<T, u32>,
    ) -> std::result::Result<T, u32> {
        let mut inner = self.lock();
        if inner.inactive() {
            return Err(KERN_TERMINATED);
        }
        let minted = mint(&mut inner.token)?;
        inner.user_stops += 1;
        if legacy {
            inner.legacy_stops += 1;
        }
        self.update(&inner);
        if !own {
            while inner.place == Place::Running && !inner.closed {
                inner = self.wait(inner);
            }
        }
        Ok(minted)
    }

    /// `thread_resume`: one legacy user stop fewer, KERN_FAILURE without
    /// one (`thread_resume_internal(THREAD_SUSPEND_LEGACY)`).
    pub(crate) fn resume(&self) -> u32 {
        self.release(true)
    }

    /// `thread_resume2`: one user stop fewer, KERN_FAILURE without one
    /// (`THREAD_SUSPEND_NORMAL`).
    pub(crate) fn resume_from_token(&self) -> u32 {
        self.release(false)
    }

    fn release(&self, legacy: bool) -> u32 {
        let mut inner = self.lock();
        if inner.inactive() {
            return KERN_TERMINATED;
        }
        if inner.user_stops == 0 || (legacy && inner.legacy_stops == 0) {
            return KERN_FAILURE;
        }
        inner.user_stops -= 1;
        if legacy {
            inner.legacy_stops -= 1;
        }
        self.update(&inner);
        KERN_SUCCESS
    }

    /// The thread's resume port `port` has no senders left, as of its
    /// make-send count `current` tells (`thread_suspension_no_senders`):
    /// with no token made since, every stop a token made is resumed
    /// (`THREAD_SUSPEND_ALL`); otherwise `rearm` requests the next
    /// notification. Nothing for another port.
    pub(crate) fn tokens_released(
        &self,
        port: u32,
        current: impl FnOnce() -> bool,
        rearm: impl FnOnce() -> bool,
    ) {
        let mut inner = self.lock();
        if inner.token.port != port || port == 0 {
            return;
        }
        inner.token.armed = false;
        if current() {
            if inner.inactive() {
                return;
            }
            inner.user_stops = inner.legacy_stops;
            self.update(&inner);
        } else {
            inner.token.armed = rearm();
        }
    }

    /// Run `act` on the stopped thread's published state as
    /// `thread_get_state_internal` and `thread_set_state_internal` do: the
    /// caller's own thread at once (its trap frame), another held until it
    /// stops (`thread_hold`, `thread_stop`). A state `act` returns becomes
    /// the thread's when it next returns to guest code.
    pub(crate) fn with_state<T>(
        &self,
        own: bool,
        act: impl FnOnce(&UserState) -> (T, Option<UserState>),
    ) -> std::result::Result<T, u32> {
        let mut inner = self.lock();
        if inner.inactive() {
            return Err(KERN_TERMINATED);
        }
        if !own {
            inner.holds += 1;
            self.update(&inner);
            while !matches!(inner.place, Place::Kernel | Place::Parked | Place::Ended)
                && !inner.closed
            {
                inner = self.wait(inner);
            }
        }
        let result = match (inner.place, inner.pending.or(inner.published)) {
            (Place::Kernel | Place::Parked, Some(state)) => {
                let (value, set) = act(&state);
                if let Some(set) = set {
                    inner.pending = Some(set);
                }
                Ok(value)
            }
            (Place::Ended, _) => Err(KERN_TERMINATED),
            // The process ended while waiting (`thread_stop` aborted).
            _ => Err(KERN_ABORTED),
        };
        if !own {
            inner.holds -= 1;
            self.update(&inner);
        }
        result
    }

    /// Where the thread is.
    #[cfg(test)]
    pub(crate) fn stopped(&self) -> Option<Stopped> {
        match self.lock().place {
            Place::Kernel | Place::Parked => Some(Stopped::State),
            Place::Starting => Some(Stopped::Starting),
            Place::Ended => Some(Stopped::Ended),
            Place::Running => None,
        }
    }

    /// Start the thread suspended (`PTHREAD_START_SUSPENDED`): it parks
    /// before its first instruction until resumed.
    pub(crate) fn start_suspended(&self) {
        let mut inner = self.lock();
        inner.user_stops += 1;
        inner.legacy_stops += 1;
        self.update(&inner);
    }

    /// Record the thread's TSD base as its entry or `thread_set_tsd_base`
    /// set it.
    pub(crate) fn set_thread_pointer(&self, pointer: u64) {
        self.thread_pointer.store(pointer, Ordering::SeqCst);
    }

    pub(crate) fn thread_pointer(&self) -> u64 {
        self.thread_pointer.load(Ordering::SeqCst)
    }

    pub(crate) fn kind(&self) -> Kind {
        *self
            .kind
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn set_kind(&self, kind: Kind) {
        *self
            .kind
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = kind;
    }

    /// `thread->active`: neither ended nor terminated.
    pub(crate) fn active(&self) -> bool {
        !self.lock().inactive()
    }

    /// `user_stop_count`, and whether the thread has yet to execute guest
    /// code.
    pub(crate) fn suspension(&self) -> (u32, bool) {
        let inner = self.lock();
        (inner.user_stops, !inner.started)
    }

    /// Perform `call`, which the host kernel serves on this thread (whose
    /// host port is `port`), where `thread_abort` can interrupt it: `None`
    /// without performing it once the thread is terminated, since it will
    /// not return to guest code.
    pub(crate) fn forwarding<T>(&self, call: impl FnOnce() -> T) -> Option<T> {
        {
            let mut inner = self.lock();
            if inner.terminated || inner.closed {
                return None;
            }
            inner.forwarding = true;
        }
        let result = call();
        let mut inner = self.lock();
        inner.forwarding = false;
        self.changed.notify_all();
        Some(result)
    }

    /// `thread_abort` and `thread_abort_safely` of another thread, whose
    /// host port is `port` (`act_abort`, `clear_wait`): a call the host
    /// kernel performs for it is interrupted as the arm64 kernel
    /// interrupts its wait; a thread in user code or stopped has no wait
    /// to interrupt, and the abort clears at its return to user space.
    pub(crate) fn abort(&self, port: u32, safely: bool) -> u32 {
        let inner = self.lock();
        if inner.inactive() {
            return KERN_TERMINATED;
        }
        if inner.forwarding {
            host_abort(port, safely);
        }
        KERN_SUCCESS
    }

    /// `thread_terminate` of another thread (`thread_terminate_internal`):
    /// it never returns to guest code, a call the host kernel performs for
    /// it is interrupted, and the caller waits until it is off its CPU
    /// (`thread_wait`).
    pub(crate) fn terminate(&self, port: u32) -> u32 {
        let mut inner = self.lock();
        if inner.inactive() {
            return KERN_TERMINATED;
        }
        inner.terminated = true;
        self.update(&inner);
        while (inner.place == Place::Running || inner.forwarding) && !inner.closed {
            inner = if inner.forwarding {
                self.abort_once(inner, port)
            } else {
                self.wait(inner)
            };
        }
        KERN_SUCCESS
    }

    /// The process ended (after [`Control::close`]): a call the host
    /// kernel performs for the thread is interrupted, as exit aborts every
    /// thread, and no further one starts.
    pub(crate) fn interrupt(&self, port: u32) {
        let mut inner = self.lock();
        while inner.forwarding {
            inner = self.abort_once(inner, port);
        }
    }

    /// Abort the thread's host call and wait a moment for it to return:
    /// an abort that reaches the host thread before it enters the call is
    /// cleared at its return to user space, so callers repeat it until
    /// the call returns.
    fn abort_once<'a>(&self, inner: MutexGuard<'a, Inner>, port: u32) -> MutexGuard<'a, Inner> {
        host_abort(port, false);
        self.changed
            .wait_timeout(inner, std::time::Duration::from_millis(1))
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
    }
}

/// The host kernel's `thread_abort` or `thread_abort_safely` of the host
/// thread `port`.
fn host_abort(port: u32, safely: bool) {
    unsafe extern "C" {
        fn thread_abort(thread: u32) -> i32;
        fn thread_abort_safely(thread: u32) -> i32;
    }
    // SAFETY: a plain thread port of this task.
    unsafe {
        if safely {
            thread_abort_safely(port);
        } else {
            thread_abort(port);
        }
    }
}

/// `KERN_ABORTED`.
pub(crate) const KERN_ABORTED: u32 = 14;

/// The forking thread's control, held across the host fork.
pub(crate) struct ForkHeld<'a> {
    control: &'a Control,
    inner: MutexGuard<'a, Inner>,
}

impl ForkHeld<'_> {
    /// In the child: the one thread is in its `fork` call, with no stop,
    /// hold or set state.
    pub(crate) fn child(mut self) {
        *self.inner = Inner {
            place: Place::Kernel,
            entry: self.inner.entry,
            published: self.inner.entry,
            ..Inner::default()
        };
        self.control.stopping.store(false, Ordering::SeqCst);
    }
}

/// `arm_thread_state64_t`: X0..X28, FP, LR, SP, PC, CPSR and flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ThreadState64 {
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
    flags: u32,
}

impl ThreadState64 {
    fn of(state: &UserState) -> Self {
        let mut x = [0; 29];
        x.copy_from_slice(&state.x[..29]);
        Self {
            x,
            fp: state.x[29],
            lr: state.x[30],
            sp: state.sp,
            pc: state.pc,
            cpsr: state.cpsr,
            flags: 0,
        }
    }

    fn into(self, state: &mut UserState) {
        state.x[..29].copy_from_slice(&self.x);
        state.x[29] = self.fp;
        state.x[30] = self.lr;
        state.sp = self.sp;
        state.pc = self.pc;
        state.cpsr = self.cpsr;
    }

    fn words(&self) -> Vec<u32> {
        let mut words = Vec::with_capacity(THREAD_STATE64_COUNT as usize);
        for value in self.x.iter().chain(&[self.fp, self.lr, self.sp, self.pc]) {
            words.push(*value as u32);
            words.push((value >> 32) as u32);
        }
        words.push(self.cpsr);
        words.push(self.flags);
        words
    }

    fn from_words(words: &[u32]) -> Self {
        let double =
            |index: usize| u64::from(words[index * 2]) | u64::from(words[index * 2 + 1]) << 32;
        let mut x = [0; 29];
        for (index, value) in x.iter_mut().enumerate() {
            *value = double(index);
        }
        Self {
            x,
            fp: double(29),
            lr: double(30),
            sp: double(31),
            pc: double(32),
            cpsr: words[66],
            flags: words[67],
        }
    }

    /// `machine_thread_state_convert_to_user` with no option flags.
    fn sign_for_user(&mut self, signer: Option<&Context>) -> Result<()> {
        let Some(signer) = signer else {
            self.flags = FLAGS_NO_PTRAUTH;
            return Ok(());
        };
        self.flags = 0;
        if self.lr != 0 && signer.strip(Key::Ib, self.lr)? != self.lr {
            self.flags |= FLAGS_IB_SIGNED_LR;
        }
        self.flags |= FLAGS_KERNEL_SIGNED_PC | FLAGS_KERNEL_SIGNED_LR;
        if self.pc != 0 {
            self.pc = signer.sign(Key::Ia, self.pc, DISCRIMINATOR_PC)?;
        }
        if self.lr != 0 && self.flags & FLAGS_IB_SIGNED_LR == 0 {
            self.lr = signer.sign(Key::Ia, self.lr, DISCRIMINATOR_LR)?;
        }
        if self.sp != 0 {
            self.sp = signer.sign(Key::Da, self.sp, DISCRIMINATOR_SP)?;
        }
        if self.fp != 0 {
            self.fp = signer.sign(Key::Da, self.fp, DISCRIMINATOR_FP)?;
        }
        Ok(())
    }

    /// `machine_thread_state_convert_to_user` with `TSSF_PRESERVE_FLAGS`:
    /// the state's user diversifier and kernel-signed flags are kept, and a
    /// PC or LR the caller signed itself (no kernel-signed flag) is signed
    /// with the diversifier blended into its discriminator.
    fn sign_preserving(&mut self, signer: Option<&Context>) -> Result<()> {
        let Some(signer) = signer else {
            self.flags = FLAGS_NO_PTRAUTH;
            return Ok(());
        };
        let old = self.flags;
        self.flags = 0;
        if self.lr != 0 && signer.strip(Key::Ib, self.lr)? != self.lr {
            self.flags |= FLAGS_IB_SIGNED_LR;
        }
        let diversifier = old & USER_DIVERSIFIER_MASK;
        self.flags |= diversifier | old & (FLAGS_KERNEL_SIGNED_PC | FLAGS_KERNEL_SIGNED_LR);
        let discriminator = |kernel_signed: u32, discriminator: u64| {
            if old & kernel_signed == 0 && diversifier != 0 {
                blend_discriminator(u64::from(diversifier), discriminator)
            } else {
                discriminator
            }
        };
        if self.pc != 0 {
            let modifier = discriminator(FLAGS_KERNEL_SIGNED_PC, DISCRIMINATOR_PC);
            self.pc = signer.sign(Key::Ia, self.pc, modifier)?;
        }
        if self.lr != 0 && self.flags & FLAGS_IB_SIGNED_LR == 0 {
            let modifier = discriminator(FLAGS_KERNEL_SIGNED_LR, DISCRIMINATOR_LR);
            self.lr = signer.sign(Key::Ia, self.lr, modifier)?;
        }
        if self.sp != 0 {
            self.sp = signer.sign(Key::Da, self.sp, DISCRIMINATOR_SP)?;
        }
        if self.fp != 0 {
            self.fp = signer.sign(Key::Da, self.fp, DISCRIMINATOR_FP)?;
        }
        Ok(())
    }

    /// `machine_thread_state_convert_from_user` with no option flags: the
    /// pointers authenticated, a failure poisoning them.
    fn authenticate_from_user(&mut self, signer: Option<&Context>) -> Result<()> {
        let Some(signer) = signer else {
            self.flags = FLAGS_NO_PTRAUTH;
            return Ok(());
        };
        // A JOP-enabled thread takes no unsigned state.
        self.flags &= !FLAGS_NO_PTRAUTH;
        if self.flags & FLAGS_IB_SIGNED_LR != 0 && signer.strip(Key::Ib, self.lr)? == self.lr {
            self.flags &= !FLAGS_IB_SIGNED_LR;
        }
        if self.pc != 0 {
            self.pc = status::authenticate(signer, Key::Ia, self.pc, DISCRIMINATOR_PC)?;
        }
        if self.lr != 0 && self.flags & FLAGS_IB_SIGNED_LR == 0 {
            self.lr = status::authenticate(signer, Key::Ia, self.lr, DISCRIMINATOR_LR)?;
        }
        if self.sp != 0 {
            self.sp = status::authenticate(signer, Key::Da, self.sp, DISCRIMINATOR_SP)?;
        }
        if self.fp != 0 {
            self.fp = status::authenticate(signer, Key::Da, self.fp, DISCRIMINATOR_FP)?;
        }
        Ok(())
    }
}

/// Flavors (`mach/arm/thread_status.h`, `mach/thread_status.h`).
const THREAD_STATE_FLAVOR_LIST: u32 = 0;
const THREAD_STATE_FLAVOR_LIST_NEW: u32 = 128;
const THREAD_STATE_FLAVOR_LIST_10_15: u32 = 131;
const ARM_THREAD_STATE: u32 = 1;
const ARM_VFP_STATE: u32 = 2;
const ARM_EXCEPTION_STATE: u32 = 3;
const ARM_DEBUG_STATE: u32 = 4;
const ARM_THREAD_STATE64: u32 = 6;
const ARM_EXCEPTION_STATE64: u32 = 7;
const ARM_EXCEPTION_STATE64_V2: u32 = 10;
const ARM_NEON_STATE64: u32 = 17;
const ARM_PAGEIN_STATE: u32 = 27;
/// Counts in `natural_t` words.
const THREAD_STATE64_COUNT: u32 = 68;
const UNIFIED_THREAD_STATE_COUNT: u32 = 70;
const EXCEPTION_STATE64_COUNT: u32 = 4;
const EXCEPTION_STATE64_V2_COUNT: u32 = 4;
const VFP_STATE_COUNT: u32 = 65;
const VFPV2_STATE_COUNT: u32 = 33;
const NEON_STATE64_COUNT: u32 = 132;
const PAGEIN_STATE_COUNT: u32 = 1;
/// `THREAD_STATE_MAX`: the largest state a message carries.
pub(crate) const THREAD_STATE_MAX: u32 = 1296;

/// `arm_neon_state64_t` (Q0..Q31, FPSR, FPCR, padding) as words.
fn neon_words(state: &UserState) -> Vec<u32> {
    let mut words = Vec::with_capacity(NEON_STATE64_COUNT as usize);
    for lane in &state.v {
        for half in lane {
            words.push(*half as u32);
            words.push((half >> 32) as u32);
        }
    }
    words.extend([state.fpsr, state.fpcr, 0, 0]);
    words
}

fn set_neon_words(state: &mut UserState, words: &[u32]) {
    let mut all = neon_words(state);
    all[..words.len()].copy_from_slice(words);
    for (index, lane) in state.v.iter_mut().enumerate() {
        for (half, value) in lane.iter_mut().enumerate() {
            let at = (index * 2 + half) * 2;
            *value = u64::from(all[at]) | u64::from(all[at + 1]) << 32;
        }
    }
    state.fpsr = all[128];
    state.fpcr = all[129];
}

/// `machine_thread_get_state` of a 64-bit thread, `count` words asked for,
/// then `machine_thread_state_convert_to_user`: the words or a
/// `kern_return_t`.
pub(crate) fn get_state(
    state: &UserState,
    flavor: u32,
    count: u32,
    signer: Option<&Context>,
) -> Result<std::result::Result<Vec<u32>, u32>> {
    let words = match flavor {
        THREAD_STATE_FLAVOR_LIST if count >= 4 => vec![
            ARM_THREAD_STATE,
            ARM_VFP_STATE,
            ARM_EXCEPTION_STATE,
            ARM_DEBUG_STATE,
        ],
        THREAD_STATE_FLAVOR_LIST_NEW if count >= 4 => vec![
            ARM_THREAD_STATE,
            ARM_VFP_STATE,
            ARM_EXCEPTION_STATE64,
            ARM_DEBUG_STATE64,
        ],
        THREAD_STATE_FLAVOR_LIST_10_15 if count >= 5 => vec![
            ARM_THREAD_STATE,
            ARM_VFP_STATE,
            ARM_EXCEPTION_STATE64,
            ARM_DEBUG_STATE64,
            ARM_PAGEIN_STATE,
        ],
        // A count below the unified state's asks for a 32-bit thread's.
        ARM_THREAD_STATE if count >= UNIFIED_THREAD_STATE_COUNT => {
            let mut thread = ThreadState64::of(state);
            thread.sign_for_user(signer)?;
            let mut words = vec![ARM_THREAD_STATE64, THREAD_STATE64_COUNT];
            words.extend(thread.words());
            words
        }
        ARM_THREAD_STATE64 if count >= THREAD_STATE64_COUNT => {
            let mut thread = ThreadState64::of(state);
            thread.sign_for_user(signer)?;
            thread.words()
        }
        ARM_EXCEPTION_STATE64 if count >= EXCEPTION_STATE64_COUNT => {
            vec![
                state.far as u32,
                (state.far >> 32) as u32,
                state.esr as u32,
                0,
            ]
        }
        ARM_EXCEPTION_STATE64_V2 if count >= EXCEPTION_STATE64_V2_COUNT => vec![
            state.far as u32,
            (state.far >> 32) as u32,
            state.esr as u32,
            (state.esr >> 32) as u32,
        ],
        // No hardware breakpoint or watchpoint is ever set (below).
        ARM_DEBUG_STATE64 if count >= DEBUG_STATE64_COUNT => vec![0; DEBUG_STATE64_COUNT as usize],
        ARM_VFP_STATE if count >= VFPV2_STATE_COUNT => {
            let words = if count >= VFP_STATE_COUNT {
                VFP_STATE_COUNT
            } else {
                VFPV2_STATE_COUNT
            };
            neon_words(state)[..words as usize].to_vec()
        }
        ARM_NEON_STATE64 if count >= NEON_STATE64_COUNT => neon_words(state),
        ARM_PAGEIN_STATE if count >= PAGEIN_STATE_COUNT => vec![0],
        // Too small a count, the 32-bit flavors, and SME and SVE state,
        // which the M2 has not.
        _ => return Ok(Err(KERN_INVALID_ARGUMENT)),
    };
    Ok(Ok(words))
}

/// `thread_convert_thread_state`'s conversion of `words`, a state of
/// `flavor`, between two threads of this process, which share its user
/// JOP key: `machine_thread_state_convert_from_user` with no option flags
/// (a thread state of exactly its count), then
/// `machine_thread_state_convert_to_user` with `TSSF_PRESERVE_FLAGS` (one
/// of at least its count). Other states pass unchanged.
pub(crate) fn convert_state(
    flavor: u32,
    words: &mut [u32],
    signer: Option<&Context>,
) -> Result<()> {
    let count = words.len() as u32;
    let (at, authenticated) = match flavor {
        ARM_THREAD_STATE
            if count >= UNIFIED_THREAD_STATE_COUNT && words[0] == ARM_THREAD_STATE64 =>
        {
            (2, true)
        }
        ARM_THREAD_STATE64 if count >= THREAD_STATE64_COUNT => (0, count == THREAD_STATE64_COUNT),
        _ => return Ok(()),
    };
    let state = &mut words[at..at + THREAD_STATE64_COUNT as usize];
    let mut thread = ThreadState64::from_words(state);
    if authenticated {
        thread.authenticate_from_user(signer)?;
    }
    thread.sign_preserving(signer)?;
    state.copy_from_slice(&thread.words());
    Ok(())
}

/// `ARM_DBGBCR_TYPE_MASK`, `ARM_DBG_CR_LINKED_MASK`,
/// `ARM_DBG_CR_ENABLE_MASK` and `MDSCR_SS`.
const DBGBCR_TYPE_MASK: u64 = 1 << 21;
const DBG_CR_LINKED_MASK: u64 = 1 << 20;
const DBG_CR_ENABLE_MASK: u64 = 1;
const MDSCR_SS: u64 = 1;

/// `machine_thread_state_convert_from_user`, then
/// `machine_thread_set_state` of a 64-bit thread whose state is `state`:
/// the new state or a `kern_return_t`.
pub(crate) fn set_state(
    state: &UserState,
    flavor: u32,
    words: &[u32],
    signer: Option<&Context>,
) -> Result<std::result::Result<UserState, u32>> {
    let count = words.len() as u32;
    let mut set = *state;
    match flavor {
        ARM_THREAD_STATE
            if count >= UNIFIED_THREAD_STATE_COUNT && words[0] == ARM_THREAD_STATE64 =>
        {
            let mut thread = ThreadState64::from_words(&words[2..]);
            thread.authenticate_from_user(signer)?;
            thread.into(&mut set);
        }
        ARM_THREAD_STATE64 if count == THREAD_STATE64_COUNT => {
            let mut thread = ThreadState64::from_words(words);
            thread.authenticate_from_user(signer)?;
            thread.into(&mut set);
        }
        // Accepted, and nothing in them is settable.
        ARM_EXCEPTION_STATE64 if count == EXCEPTION_STATE64_COUNT => {}
        ARM_EXCEPTION_STATE64_V2 if count == EXCEPTION_STATE64_V2_COUNT => {}
        ARM_DEBUG_STATE64 if count == DEBUG_STATE64_COUNT => {
            let double =
                |index: usize| u64::from(words[index * 2]) | u64::from(words[index * 2 + 1]) << 32;
            // `bvr[16]`, `bcr[16]`, `wvr[16]`, `wcr[16]`, `mdscr_el1`.
            let mut enabled = double(64) & MDSCR_SS != 0;
            for index in 0..16 {
                let (bcr, wcr) = (double(16 + index), double(48 + index));
                if bcr & DBGBCR_TYPE_MASK != 0
                    || bcr & DBG_CR_LINKED_MASK != 0
                    || wcr & DBG_CR_LINKED_MASK != 0
                {
                    return Ok(Err(KERN_PROTECTION_FAILURE));
                }
                enabled |= bcr & DBG_CR_ENABLE_MASK != 0 || wcr & DBG_CR_ENABLE_MASK != 0;
            }
            if enabled {
                bail!(
                    "thread_set_state(ARM_DEBUG_STATE64) enabling a hardware breakpoint, \
                     watchpoint or single step: guest debug exceptions are not implemented"
                );
            }
        }
        ARM_VFP_STATE if count == VFP_STATE_COUNT || count == VFPV2_STATE_COUNT => {
            set_neon_words(&mut set, words);
        }
        ARM_NEON_STATE64 if count == NEON_STATE64_COUNT => set_neon_words(&mut set, &words[..130]),
        // A 32-bit or wrongly counted state, and SME and SVE state.
        _ => return Ok(Err(KERN_INVALID_ARGUMENT)),
    }
    Ok(Ok(set))
}

#[cfg(test)]
mod tests {
    use super::*;
    const ARM_THREAD_STATE32: u32 = 9;
    const ARM_DEBUG_STATE32: u32 = 14;
    const ARM_NEON_STATE: u32 = 16;
    use std::sync::Arc;
    use std::time::Duration;

    fn state(x0: u64) -> UserState {
        let mut state = UserState::default();
        state.x[0] = x0;
        state.pc = 0x1_0000_4000;
        state
    }

    /// Mark `control` as in the kernel with `state`, as a kernel entry does.
    fn in_kernel(control: &Control, state: UserState) {
        let mut inner = control.lock();
        inner.place = Place::Kernel;
        inner.entry = Some(state);
        inner.published = Some(state);
        control.update(&inner);
    }

    fn running(control: &Control) {
        let mut inner = control.lock();
        inner.place = Place::Running;
        inner.published = None;
        control.update(&inner);
    }

    /// Park as `leave` does without a PE: publish `state`, wait while
    /// stopped. The state set meanwhile, if any.
    fn park(control: &Control, state: UserState) -> Option<UserState> {
        let mut inner = control.lock();
        let mut set = None;
        while inner.stopping() && !inner.closed {
            if inner.place != Place::Parked {
                inner.place = Place::Parked;
                inner.published = Some(state);
                control.update(&inner);
            }
            inner = control.wait(inner);
            if let Some(pending) = inner.pending.take() {
                inner.published = Some(pending);
                set = Some(pending);
            }
        }
        inner.place = Place::Running;
        control.update(&inner);
        set
    }

    #[test]
    fn suspend_waits_for_the_thread_to_stop_and_resume_releases_it() {
        let control = Arc::new(Control::default());
        running(&control);
        let target = control.clone();
        // The target runs until its slice check sees the stop.
        let thread = std::thread::spawn(move || {
            while !target.pending() {
                std::thread::yield_now();
            }
            park(&target, state(7));
        });
        assert_eq!(control.suspend(false), KERN_SUCCESS);
        assert_eq!(control.stopped(), Some(Stopped::State));
        assert!(control.pending());
        assert_eq!(control.resume(), KERN_SUCCESS);
        thread.join().unwrap();
        assert_eq!(control.stopped(), None);
        assert!(!control.pending());
        // No suspension left to resume.
        assert_eq!(control.resume(), KERN_FAILURE);
    }

    #[test]
    fn a_thread_in_the_kernel_counts_as_stopped() {
        let control = Control::default();
        in_kernel(&control, state(1));
        assert_eq!(control.suspend(false), KERN_SUCCESS);
        let read = control.with_state(false, |state| (state.x[0], None));
        assert_eq!(read, Ok(1));
        assert_eq!(control.resume(), KERN_SUCCESS);
    }

    #[test]
    fn get_state_holds_a_running_thread_until_it_stops() {
        let control = Arc::new(Control::default());
        running(&control);
        let target = control.clone();
        let thread = std::thread::spawn(move || {
            while !target.pending() {
                std::thread::yield_now();
            }
            park(&target, state(42))
        });
        // While the thread runs no state is published.
        assert_eq!(control.stopped(), None);
        let read = control.with_state(false, |state| (state.x[0], None));
        assert_eq!(read, Ok(42));
        // The hold is released with the read: the thread runs on.
        assert_eq!(thread.join().unwrap(), None);
        assert!(!control.pending());
    }

    #[test]
    fn set_state_is_applied_when_the_thread_returns() {
        let control = Arc::new(Control::default());
        running(&control);
        assert_eq!(control.suspend(true), KERN_SUCCESS);
        let target = control.clone();
        let thread = std::thread::spawn(move || park(&target, state(1)));
        // Wait for the park.
        while control.stopped() != Some(Stopped::State) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let set = control.with_state(false, |current| {
            let mut set = *current;
            set.x[0] = 99;
            ((), Some(set))
        });
        assert_eq!(set, Ok(()));
        // A later read sees the set state.
        assert_eq!(
            control.with_state(false, |state| (state.x[0], None)),
            Ok(99)
        );
        control.resume();
        assert_eq!(thread.join().unwrap().map(|state| state.x[0]), Some(99));
    }

    #[test]
    fn a_self_suspend_does_not_wait() {
        let control = Control::default();
        running(&control);
        assert_eq!(control.suspend(true), KERN_SUCCESS);
        assert!(control.pending());
        assert_eq!(control.resume(), KERN_SUCCESS);
        // Ended threads answer KERN_TERMINATED.
        control.ended();
        assert_eq!(control.suspend(false), KERN_TERMINATED);
        assert_eq!(control.resume(), KERN_TERMINATED);
        assert_eq!(
            control.with_state(false, |state| (state.x[0], None)),
            Err(KERN_TERMINATED)
        );
    }

    #[test]
    fn token_stops_and_legacy_stops_resume_apart() {
        let control = Control::default();
        running(&control);
        let minted = control.suspend_with_token(true, |token| {
            token.port = 0x1234;
            token.armed = true;
            Ok(token.port)
        });
        assert_eq!(minted, Ok(0x1234));
        assert_eq!(control.suspend(true), KERN_SUCCESS);
        assert_eq!(
            control.suspend_with_token(true, |token| Ok(token.port)),
            Ok(0x1234)
        );
        assert_eq!(control.suspension().0, 3);
        // A token's resume takes one stop, legacy or not; `thread_resume`
        // only a legacy one.
        assert_eq!(control.resume_from_token(), KERN_SUCCESS);
        assert_eq!(control.resume(), KERN_SUCCESS);
        assert_eq!(control.resume(), KERN_FAILURE);
        assert_eq!(control.suspension().0, 1);
        // A notification after a newer token rearms it; a current one
        // resumes every token's stop.
        control.tokens_released(0x1234, || false, || true);
        assert_eq!(control.suspension().0, 1);
        control.tokens_released(0x1234, || true, || unreachable!());
        assert_eq!(control.suspension().0, 0);
        assert!(!control.pending());
        // A failed token adds no stop.
        assert_eq!(
            control.suspend_with_token(true, |_| Err::<u32, _>(6)),
            Err(6)
        );
        assert_eq!(control.resume_from_token(), KERN_FAILURE);
    }

    #[test]
    fn a_terminated_thread_never_returns_to_guest_code() {
        // A created thread parked before its first instruction.
        let control = Arc::new(Control::default());
        control.start_suspended();
        assert_eq!(control.suspension(), (1, true));
        let target = control.clone();
        let thread = std::thread::spawn(move || {
            let mut inner = target.lock();
            while inner.stopping() && !inner.closed && !inner.terminated {
                inner.place = Place::Parked;
                target.update(&inner);
                inner = target.wait(inner);
            }
            inner.terminated
        });
        while control.stopped() != Some(Stopped::State) {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(control.active());
        assert_eq!(control.terminate(0), KERN_SUCCESS);
        assert!(thread.join().unwrap());
        // Gone for every other routine, and no host call starts.
        assert!(!control.active());
        assert_eq!(control.terminate(0), KERN_TERMINATED);
        assert_eq!(control.abort(0, false), KERN_TERMINATED);
        assert_eq!(control.suspend(false), KERN_TERMINATED);
        assert_eq!(control.forwarding(|| 1), None);
        // Not forwarding: nothing to interrupt.
        control.interrupt(0);
    }

    #[test]
    fn closing_wakes_a_parked_thread_for_good() {
        let control = Arc::new(Control::default());
        running(&control);
        control.start_suspended();
        let target = control.clone();
        let thread = std::thread::spawn(move || {
            let mut inner = target.lock();
            while inner.stopping() && !inner.closed {
                inner.place = Place::Parked;
                target.update(&inner);
                inner = target.wait(inner);
            }
            inner.closed
        });
        while control.stopped() != Some(Stopped::State) {
            std::thread::sleep(Duration::from_millis(1));
        }
        control.close();
        assert!(thread.join().unwrap());
        // A caller waiting for a thread that never stops returns too.
        let control = Arc::new(Control::default());
        running(&control);
        let waiter = control.clone();
        let thread = std::thread::spawn(move || waiter.with_state(false, |_| ((), None)));
        while !control.pending() {
            std::thread::sleep(Duration::from_millis(1));
        }
        control.close();
        assert_eq!(thread.join().unwrap(), Err(KERN_ABORTED));
    }

    #[test]
    fn a_state_set_during_a_call_keeps_the_calls_results() {
        let entry = state(3);
        let mut now = entry;
        now.x[0] = 0; // The call's return value.
        now.x[1] = 0;
        let mut set = entry;
        set.x[0] = 11;
        set.x[2] = 22;
        set.pc = 0x2000;
        let merged = UserState::merged(&entry, &now, &set);
        assert_eq!(merged.x[0], 0);
        assert_eq!(merged.x[2], 22);
        assert_eq!(merged.pc, 0x2000);
    }

    #[test]
    fn flavors_lay_out_the_state_as_xnu() {
        let mut user = state(5);
        user.x[29] = 0x16f_dff0;
        user.x[30] = 0x1_0000_1234;
        user.sp = 0x16f_dfe0;
        user.cpsr = 0x6000_0000;
        user.v[1] = [0x1111, 0x2222];
        user.fpcr = 0x0300_0000;
        user.far = 0xdead;
        user.esr = 0x5600_0080;
        let words = get_state(&user, ARM_THREAD_STATE64, 68, None)
            .unwrap()
            .unwrap();
        assert_eq!(words.len(), 68);
        assert_eq!(words[0], 5);
        assert_eq!(words[58], 0x16f_dff0);
        assert_eq!(words[62], 0x16f_dfe0);
        assert_eq!((words[64], words[65]), (0x0000_4000, 1));
        assert_eq!((words[66], words[67]), (0x6000_0000, FLAGS_NO_PTRAUTH));
        let unified = get_state(&user, ARM_THREAD_STATE, 70, None)
            .unwrap()
            .unwrap();
        assert_eq!(&unified[..2], &[ARM_THREAD_STATE64, 68]);
        assert_eq!(&unified[2..], &words[..]);
        // A smaller count asks for a 32-bit thread's state.
        assert_eq!(
            get_state(&user, ARM_THREAD_STATE, 17, None).unwrap(),
            Err(KERN_INVALID_ARGUMENT)
        );
        assert_eq!(
            get_state(&user, ARM_THREAD_STATE64, 67, None).unwrap(),
            Err(KERN_INVALID_ARGUMENT)
        );
        assert_eq!(
            get_state(&user, ARM_EXCEPTION_STATE64, 4, None).unwrap(),
            Ok(vec![0xdead, 0, 0x5600_0080, 0])
        );
        let neon = get_state(&user, ARM_NEON_STATE64, 132, None)
            .unwrap()
            .unwrap();
        assert_eq!((neon[4], neon[6]), (0x1111, 0x2222));
        assert_eq!(neon[129], 0x0300_0000);
        assert_eq!(
            get_state(&user, ARM_VFP_STATE, 40, None)
                .unwrap()
                .unwrap()
                .len(),
            33
        );
        assert_eq!(
            get_state(&user, ARM_VFP_STATE, 65, None)
                .unwrap()
                .unwrap()
                .len(),
            65
        );
        assert_eq!(
            get_state(&user, THREAD_STATE_FLAVOR_LIST_10_15, 5, None).unwrap(),
            Ok(vec![1, 2, 7, 15, 27])
        );
        for flavor in [
            ARM_THREAD_STATE32,
            ARM_EXCEPTION_STATE,
            ARM_DEBUG_STATE32,
            ARM_NEON_STATE,
            28,
        ] {
            assert_eq!(
                get_state(&user, flavor, 1296, None).unwrap(),
                Err(KERN_INVALID_ARGUMENT)
            );
        }
        // Setting the thread state round-trips; the CPSR's mode is the
        // apply's to reset.
        let mut changed = words.clone();
        changed[2] = 77;
        let set = set_state(&user, ARM_THREAD_STATE64, &changed, None)
            .unwrap()
            .unwrap();
        assert_eq!(set.x[1], 77);
        assert_eq!(set.v, user.v);
        assert_eq!(
            set_state(&user, ARM_THREAD_STATE64, &changed[..67], None).unwrap(),
            Err(KERN_INVALID_ARGUMENT)
        );
        let mut neon = neon.clone();
        neon[129] = 0x0040_0000;
        let set = set_state(&user, ARM_NEON_STATE64, &neon, None)
            .unwrap()
            .unwrap();
        assert_eq!(set.fpcr, 0x0040_0000);
        assert_eq!(set.x, user.x);
        // A debug state enabling nothing is accepted; a linked breakpoint
        // is refused as XNU does.
        let mut debug = vec![0u32; 130];
        assert_eq!(
            set_state(&user, ARM_DEBUG_STATE64, &debug, None).unwrap(),
            Ok(user)
        );
        debug[32] = 1 << 20;
        assert_eq!(
            set_state(&user, ARM_DEBUG_STATE64, &debug, None).unwrap(),
            Err(KERN_PROTECTION_FAILURE)
        );
        debug[32] = 1;
        assert!(set_state(&user, ARM_DEBUG_STATE64, &debug, None).is_err());
    }
}
