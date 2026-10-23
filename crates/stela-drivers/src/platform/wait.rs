//! Retained native interrupt/deadline waiting, supplied by the platform owner.
//!
//! This boundary does not install a timer, IRQ route, scheduler or execution
//! context. A device must retain the actual provider throughout every pending
//! operation and uncertain retirement. There is no polling fallback or default
//! provider. Cooperative work rescanning does not implement this contract.
use core::sync::atomic::AtomicU64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitError {
    Unavailable,
    WrongCpu,
    InterruptContext,
    InterruptsDisabled,
    ContextChanged,
    TimerUnavailable,
    Busy,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wake {
    /// The actual Acquire-loaded event generation differs from the snapshot.
    /// This is a notification, never device-command or DMA completion evidence.
    Changed(u64),
    /// The provider's actual monotonic clock has reached the absolute deadline.
    Deadline,
}

/// The platform's actual retained process, timer and interrupt-wakeup authority.
/// An `Arc<dyn DeadlineWait>` may be shared, but each call still checks the
/// qualified CPU/context. Device IRQs publish their own event generation only
/// after acknowledging their actual owned causes; this trait invents no wake.
///
/// # Safety
/// The implementation retains the real CPU/root/owned-stack and timer/IRQ
/// resources through every wait and failed retirement. Calls and final release
/// occur in the qualified process/deferred context, never hard IRQ context.
/// `check` refuses a foreign CPU, changed root/stack, interrupt entry, entry
/// IF=0, unavailable timer service, or quarantined context before device effects.
/// Send/Sync permit checked sharing, not migration or arbitrary final release.
///
/// `ticks` is the same advancing monotonic clock used for the caller's absolute
/// deadline; callers use checked addition and refuse deadline overflow. Parking
/// does not consume or reassign another timer owner, discard an expired timer,
/// or manufacture clock progress. The provider arms a genuine deadline wake,
/// then rechecks `generation` with interrupt delivery excluded immediately
/// before the atomic interrupt-enable/park boundary. An already delivered
/// completion must prevent parking. The device and deadline IRQs can wake that
/// same physical CPU; no disabled-IRQ wait, periodic probing, work rescanning or
/// spurious-IRQ assumption supplies progress. All saved interrupt flags and
/// original timer ownership are restored exactly, including on failure.
///
/// No device/command-state lock used by the ISR may span `park`. The borrowed
/// generation and caller context must not escape the call. `Changed` reports a
/// real Acquire observation different from `observed`; `Deadline` requires
/// actual `ticks() >= deadline`. Spurious delivery can repark internally under
/// the same arm/recheck protocol. A wake never certifies command success,
/// semaphore visibility, resource drainage or safe memory reuse.
pub unsafe trait DeadlineWait: Send + Sync {
    fn check(&self) -> Result<(), WaitError>;
    fn ticks(&self) -> u64;
    fn park(&self, generation: &AtomicU64, observed: u64, deadline: u64)
    -> Result<Wake, WaitError>;
}
