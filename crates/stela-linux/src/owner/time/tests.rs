// SPDX-License-Identifier: MIT
//! Owned isolated counter controls; no native Installed/current permission.
use super::*;
use alloc::rc::Rc;
use core::cell::Cell;
struct Counter {
    ticks: Cell<u64>,
    closed: Cell<bool>,
    drops: Cell<u32>,
}
struct Model {
    counter: Rc<Counter>,
    target: u64,
}
impl Drop for Model {
    fn drop(&mut self) {
        self.counter.drops.set(self.counter.drops.get() + 1);
    }
}
impl Model {
    fn left(&self) -> Result<u64, WorkError> {
        if self.counter.closed.get() {
            return Err(WorkError::Closed);
        }
        Ok(self.target.saturating_sub(self.counter.ticks.get()))
    }
}
// SAFETY: explicit owned virtual counter and immutable relative target only;
// it cannot qualify a native source, C task/root, dispatcher or hardware grant.
unsafe impl MinimumDeadline for Model {
    fn ready(&self) -> Result<bool, WorkError> {
        Ok(self.left()? == 0)
    }
    fn wake_ns(&self) -> Result<i64, WorkError> {
        self.left()?;
        i64::try_from(
            self.target
                .checked_mul(1000)
                .and_then(|ns| ns.checked_add(1))
                .ok_or(WorkError::Exhausted)?,
        )
        .map_err(|_| WorkError::Exhausted)
    }
    fn remaining_quanta_ceil(&self, quantum_us: u64) -> Result<u64, WorkError> {
        if quantum_us == 0 {
            return Err(WorkError::InvalidTicket);
        }
        Ok(self.left()?.div_ceil(quantum_us))
    }
}
fn counter() -> Rc<Counter> {
    Rc::new(Counter {
        ticks: Cell::new(0),
        closed: Cell::new(false),
        drops: Cell::new(0),
    })
}
#[test]
fn same_owned_target_survives_early_wake_observations() {
    let source = counter();
    let deadline = Model {
        counter: source.clone(),
        target: 100,
    };
    for _ in 0..8 {
        assert!(!deadline.ready().unwrap());
        assert_eq!(deadline.wake_ns(), Ok(100001));
    }
    source.ticks.set(31);
    let remaining = deadline.remaining_quanta_ceil(10).unwrap();
    assert_eq!(remaining, 7);
    assert!(source.ticks.get() + remaining * 10 >= deadline.target);
    source.ticks.set(100);
    assert!(deadline.ready().unwrap());
}
#[test]
fn actual_owned_record_default_drop_keeps_failed_original_source() {
    let source = counter();
    source.closed.set(true);
    let model = Model {
        counter: source.clone(),
        target: 100,
    };
    assert_eq!(model.ready(), Err(WorkError::Closed));
    let value = Owned {
        header: Header {
            ready,
            wake_ns,
            remaining,
            release,
        },
        source: ManuallyDrop::new(Box::new(model)),
        owner: ptr::null(),
        task: ptr::null_mut(),
    };
    drop(value);
    assert_eq!(source.drops.get(), 0);
    // No actual-current C callback was invoked or bypassed by this ownership
    // control; success/cancel/wrong-owner integration requires the real root.
}
#[test]
fn isolated_counter_cancellation_drops_only_its_own_model_subreference() {
    let source = counter();
    let model = Model {
        counter: source.clone(),
        target: 100,
    };
    assert!(!model.ready().unwrap());
    drop(model);
    assert_eq!(source.drops.get(), 1);
    assert_eq!(source.ticks.get(), 0);
}

#[test]
fn complete_minimum_fault_mapping_and_first_cause_are_retained() {
    let errors = [
        WorkError::Unavailable,
        WorkError::WrongCpu,
        WorkError::InterruptContext,
        WorkError::Busy,
        WorkError::Full,
        WorkError::Closed,
        WorkError::Exhausted,
        WorkError::InvalidStack,
        WorkError::InvalidTicket,
        WorkError::WouldDeadlock,
        WorkError::TimedOut,
        WorkError::CorruptContext,
        WorkError::Pending,
    ];
    for first in errors {
        let fault = FirstMinimumFault::new();
        assert_eq!(fault.get(), None);
        fault.record(first);
        assert_eq!(fault.get(), Some(first));
        for later in errors {
            fault.record(later);
            assert_eq!(fault.get(), Some(first));
        }
    }
}
