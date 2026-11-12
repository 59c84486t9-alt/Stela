//! One device's start budget. The probe arms it as a driver starts on a
//! device; once it has passed, every [`Clock`] wait and [`Deadline`] check
//! that driver makes reports its deadline as passed, and every minimum
//! delay of a [`Bounded`] provider fails after waiting, so a
//! device that never answers ends its own start in bounded time even where
//! a driver's inner timeouts add up to more, or restart one another.
//! Nothing preempts a driver: a single register access that never
//! completes is not bounded here.
//!
//! An unarmed budget costs one relaxed load per check and changes nothing.
//! Minimum delays a device needs ([`Clock::delay`], the qualified
//! provider's waits) are never shortened.
//!
//! [`Deadline`]: crate::Deadline
use crate::{Clock, ClockError, bus::pci::power};
use alloc::rc::Rc;
use core::{marker::PhantomData, panic::Location};

/// When the budget ran out: how long the device had and which wait first
/// saw it gone, the step the device stopped answering at.
#[derive(Clone, Copy, Debug)]
pub struct Expiry {
    pub budget_us: u64,
    pub at: Option<&'static Location<'static>>,
}

#[derive(Clone, Copy)]
struct State {
    start: u64,
    /// Zero while unarmed.
    ticks: u64,
    ticks_per_microsecond: u64,
    at: Option<&'static Location<'static>>,
}

#[cfg(any(test, feature = "test-support"))]
const UNARMED: State = State {
    start: 0,
    ticks: 0,
    ticks_per_microsecond: 0,
    at: None,
};

#[cfg(any(test, feature = "test-support"))]
mod state {
    //! Per thread, as the fixtures' virtual clock is: parallel tests never
    //! see one another's budget.
    extern crate std;
    use super::{State, UNARMED};
    use core::cell::Cell;

    std::thread_local! {
        static STATE: Cell<State> = const { Cell::new(UNARMED) };
    }

    pub(super) fn armed() -> bool {
        STATE.with(|state| state.get().ticks != 0)
    }
    pub(super) fn get() -> State {
        STATE.with(Cell::get)
    }
    pub(super) fn set(value: State) {
        STATE.with(|state| state.set(value));
    }
}

#[cfg(not(any(test, feature = "test-support")))]
mod state {
    //! One budget for the one core that starts devices; every other core
    //! reads it unarmed.
    use super::State;
    use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

    static START: AtomicU64 = AtomicU64::new(0);
    static TICKS: AtomicU64 = AtomicU64::new(0);
    static RATE: AtomicU64 = AtomicU64::new(0);
    static AT: AtomicPtr<core::panic::Location<'static>> = AtomicPtr::new(core::ptr::null_mut());

    pub(super) fn armed() -> bool {
        TICKS.load(Ordering::Relaxed) != 0
    }
    pub(super) fn get() -> State {
        let at = AT.load(Ordering::Relaxed);
        State {
            start: START.load(Ordering::Relaxed),
            ticks: TICKS.load(Ordering::Acquire),
            ticks_per_microsecond: RATE.load(Ordering::Relaxed),
            // SAFETY: AT holds null or a `&'static Location` stored by `set`.
            at: unsafe { at.as_ref() },
        }
    }
    pub(super) fn set(value: State) {
        START.store(value.start, Ordering::Relaxed);
        RATE.store(value.ticks_per_microsecond, Ordering::Relaxed);
        AT.store(
            value.at.map_or(core::ptr::null_mut(), |at| {
                (at as *const core::panic::Location<'static>).cast_mut()
            }),
            Ordering::Relaxed,
        );
        TICKS.store(value.ticks, Ordering::Release);
    }
}

/// An armed budget; dropping it restores the budget it replaced.
#[must_use]
pub struct Budget {
    previous: State,
    _thread: PhantomData<*const ()>,
}

impl Budget {
    /// Arm `microseconds` from now on `clock`.
    pub fn start(clock: Clock, microseconds: u64) -> Result<Self, ClockError> {
        let deadline = clock.try_deadline(microseconds.max(1))?;
        let previous = state::get();
        state::set(State {
            start: deadline.start,
            ticks: deadline.ticks,
            ticks_per_microsecond: clock.ticks_per_microsecond,
            at: None,
        });
        Ok(Self {
            previous,
            _thread: PhantomData,
        })
    }

    /// Whether the budget ran out, and where it was first seen gone.
    pub fn expired(&self) -> Option<Expiry> {
        let current = state::get();
        let elapsed = Clock::ticks().wrapping_sub(current.start) as i64;
        (current.ticks != 0 && elapsed >= 0 && elapsed as u64 >= current.ticks).then(|| Expiry {
            budget_us: current.ticks / current.ticks_per_microsecond.max(1),
            at: current.at,
        })
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        state::set(self.previous);
    }
}

/// Whether an armed budget has passed at `counter`. The first wait to see
/// it passed is kept as the step the device stopped at.
#[inline]
pub(crate) fn passed_at(counter: u64, at: &'static Location<'static>) -> bool {
    if !state::armed() {
        return false;
    }
    let mut current = state::get();
    let elapsed = counter.wrapping_sub(current.start) as i64;
    let passed = current.ticks != 0 && elapsed >= 0 && elapsed as u64 >= current.ticks;
    if passed && current.at.is_none() {
        current.at = Some(at);
        state::set(current);
    }
    passed
}

/// A minimum-delay provider whose waits fail once an armed budget has
/// passed, after waiting in full: a driver's counted polls and fixed
/// delays, each bounded, can together outlast its start budget, and the
/// mount gives every driver its minimum delays through this. Unarmed, it
/// is the provider it wraps.
pub struct Bounded(pub Rc<dyn power::Timer>);

// SAFETY: every wait is the wrapped provider's own, run in full; a passed
// budget only turns a completed wait into a failure.
unsafe impl power::Timer for Bounded {
    fn check(&self) -> Result<(), power::Error> {
        self.0.check()
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), power::Error> {
        self.0.wait_us(microseconds)?;
        if passed_at(Clock::ticks(), Location::caller()) {
            return Err(power::Error::StartBudget);
        }
        Ok(())
    }
    fn begin_interval(
        &self,
        microseconds: u64,
    ) -> Result<Option<alloc::boxed::Box<dyn power::Interval>>, power::Error> {
        self.0.begin_interval(microseconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_clock;

    const CLOCK: Clock = Clock {
        ticks_per_microsecond: 1,
    };

    #[test]
    fn an_unarmed_budget_changes_no_wait() {
        let _virtual = test_clock::virtualize();
        let deadline = CLOCK.deadline(1_000);
        assert!(!deadline.passed());
        let mut polls = 0;
        assert!(!CLOCK.wait(1_000, || {
            polls += 1;
            false
        }));
        // 100 virtual microseconds per counter read: about ten polls.
        assert!(polls >= 5, "{polls}");
    }

    #[test]
    fn a_passed_budget_ends_every_later_wait_and_names_the_first() {
        let _virtual = test_clock::virtualize();
        let budget = Budget::start(CLOCK, 1_000).unwrap();
        assert!(budget.expired().is_none());
        // A wait far longer than the budget ends at the budget.
        let started = Clock::ticks();
        assert!(!CLOCK.wait(60_000_000, || false));
        let took = Clock::ticks() - started;
        assert!(took < 2_000, "{took}");
        let expiry = budget.expired().expect("budget passed");
        assert_eq!(expiry.budget_us, 1_000);
        let first = expiry.at.expect("first wait named");
        assert!(first.file().ends_with("budget.rs"));
        // A fresh deadline is passed at once; the first step stays named.
        assert!(CLOCK.deadline(5_000_000).passed());
        assert_eq!(budget.expired().unwrap().at, Some(first));
        // A ready device is still seen ready.
        assert!(CLOCK.wait(60_000_000, || true));
        drop(budget);
        assert!(!CLOCK.deadline(5_000_000).passed());
    }

    struct Instant;
    // SAFETY: a test peer whose waits return at once on the virtual clock.
    unsafe impl power::Timer for Instant {
        fn check(&self) -> Result<(), power::Error> {
            Ok(())
        }
        fn wait_us(&self, _: u64) -> Result<(), power::Error> {
            Ok(())
        }
    }

    #[test]
    fn a_bounded_minimum_ends_a_start_past_its_budget() {
        use power::Timer;
        let _virtual = test_clock::virtualize();
        let minimum = Bounded(Rc::new(Instant));
        // Unarmed, a wait changes nothing.
        assert_eq!(minimum.wait_us(50_000), Ok(()));
        let budget = Budget::start(CLOCK, 1_000).unwrap();
        // 100 virtual microseconds per counter read: the budget passes in a
        // few waits of a poll whose own count would allow 2000.
        let waits = (0..2000)
            .take_while(|_| minimum.wait_us(50_000).is_ok())
            .count();
        assert!(waits < 20, "{waits}");
        assert_eq!(minimum.wait_us(50_000), Err(power::Error::StartBudget));
        assert!(budget.expired().is_some());
        drop(budget);
        assert_eq!(minimum.wait_us(50_000), Ok(()));
    }

    #[test]
    fn dropping_a_budget_restores_the_one_it_replaced() {
        let _virtual = test_clock::virtualize();
        let outer = Budget::start(CLOCK, 10_000_000).unwrap();
        {
            let _inner = Budget::start(CLOCK, 1).unwrap();
            assert!(CLOCK.deadline(5_000_000).passed());
        }
        assert!(!CLOCK.deadline(5_000_000).passed());
        assert!(outer.expired().is_none());
    }
}
