//! Virtual time-stamp counter for test fixtures with synchronous peers.
//!
//! [`Clock`](crate::Clock) reads the real counter. A fixture calibrated at one
//! tick per microsecond turns a one-second transfer budget into a fraction of a
//! millisecond of real time, which preemption of the test thread between a
//! doorbell and the poll that observes its completion can consume, so a busy
//! host reports device timeouts its peer never caused. While a [`Guard`] lives
//! on a thread, each counter read there advances that thread's time by
//! [`STEP`] ticks instead: deadlines expire after a fixed number of driver
//! observations, independent of the host scheduler and of other test threads.
extern crate std;

use core::{cell::Cell, marker::PhantomData};

/// Ticks each virtual counter read advances: 100 µs at the fixtures' one tick
/// per microsecond, so a one-second budget spans 10 000 observations.
const STEP: u64 = 100;

#[derive(Clone, Copy)]
struct State {
    guards: usize,
    now: u64,
}

std::thread_local! {
    static STATE: Cell<State> = const { Cell::new(State { guards: 0, now: 0 }) };
}

/// Keeps this thread's [`Clock`](crate::Clock) virtual until dropped. Guards
/// nest; time never runs backwards across them.
pub(crate) struct Guard(PhantomData<*const ()>);

/// Make this thread's counter virtual, continuing from the real counter so
/// deadlines taken before the first guard keep their meaning.
pub(crate) fn virtualize() -> Guard {
    STATE.with(|state| {
        let mut current = state.get();
        if current.guards == 0 {
            // SAFETY: RDTSC has no memory effects; x86-64 always has it.
            current.now = current.now.max(unsafe { core::arch::x86_64::_rdtsc() });
        }
        current.guards += 1;
        state.set(current);
    });
    Guard(PhantomData)
}

/// Advance an active fixture clock by a calibrated interval.
pub(crate) fn advance(clock: crate::Clock, microseconds: u64) {
    let ticks = clock
        .duration_ticks(microseconds)
        .expect("fixture interval fits its calibrated clock");
    STATE.with(|state| {
        let mut current = state.get();
        assert!(
            current.guards != 0,
            "advance requires a virtual clock guard"
        );
        current.now = current.now.wrapping_add(ticks);
        state.set(current);
    });
}

impl Drop for Guard {
    fn drop(&mut self) {
        STATE.with(|state| {
            let mut current = state.get();
            current.guards -= 1;
            state.set(current);
        });
    }
}

/// The advanced virtual counter, or `None` when no guard lives on this thread.
pub(crate) fn read() -> Option<u64> {
    STATE.with(|state| {
        let mut current = state.get();
        if current.guards == 0 {
            return None;
        }
        current.now = current.now.wrapping_add(STEP);
        state.set(current);
        Some(current.now)
    })
}
