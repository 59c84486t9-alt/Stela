// SPDX-License-Identifier: MIT
//! Counted native supplier ownership; namespace handles stay in affine receipts.
use super::{Error, Handle};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

const CONNECTED: usize = 1 << (usize::BITS - 1);
const CLOSED: usize = CONNECTED >> 1;
const COUNT: usize = CLOSED - 1;

/// Only category-owned connection/activation ACKs publish this state.
/// There is no public constructor or caller-supplied ready flag.
pub(crate) struct SupplierState {
    // Admission and the active count share one modification order. A successful
    // claim either precedes closure (and is counted) or observes it and refuses.
    state: AtomicUsize,
}
impl SupplierState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicUsize::new(0),
        })
    }
    pub(crate) fn connected(&self) -> Result<(), Error> {
        self.state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & CLOSED == 0).then_some(state | CONNECTED)
            })
            .map(|_| ())
            .map_err(|_| Error::Unassigned)
    }
    pub(crate) fn close_admission(&self) {
        self.state.fetch_or(CLOSED, Ordering::AcqRel);
    }
    pub(crate) fn consumers(&self) -> usize {
        self.state.load(Ordering::Acquire) & COUNT
    }
    fn acquire(self: &Arc<Self>) -> Result<DependencyPin, Error> {
        self.state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current & (CONNECTED | CLOSED) == CONNECTED && current & COUNT != COUNT)
                    .then(|| current + 1)
            })
            .map_err(|current| {
                if current & (CONNECTED | CLOSED) != CONNECTED {
                    Error::Unassigned
                } else {
                    Error::Limit
                }
            })?;
        Ok(DependencyPin(self.clone()))
    }
}
/// Callback-kept ownership contains no namespace handle or interpreter
/// pointer. Cleanup can keep this pin through native hardware uncertainty.
pub(crate) struct DependencyPin(Arc<SupplierState>);
impl Clone for DependencyPin {
    fn clone(&self) -> Self {
        self.0
            .state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count & COUNT != COUNT).then(|| count + 1)
            })
            .expect("native dependency counter overflow");
        Self(self.0.clone())
    }
}
impl Drop for DependencyPin {
    fn drop(&mut self) {
        self.0.state.fetch_sub(1, Ordering::AcqRel);
    }
}

/// An installed EC/GPIO supplier receipt, acquired only after its category
/// reports successful connection and the required native activation phase.
pub struct Dependency<'a> {
    handle: Handle<'a>,
    pin: DependencyPin,
}
impl<'a> Dependency<'a> {
    pub fn handle(&self) -> Handle<'a> {
        self.handle
    }
    pub(crate) fn acquire(handle: Handle<'a>, state: &Arc<SupplierState>) -> Result<Self, Error> {
        Ok(Self {
            handle,
            pin: state.acquire()?,
        })
    }
    pub(crate) fn native_pin(&self) -> DependencyPin {
        self.pin.clone()
    }
}
impl Clone for Dependency<'_> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle,
            pin: self.pin.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{sync::Barrier, thread};

    #[test]
    fn closure_and_claim_share_one_order_and_closed_pins_still_keep_owner() {
        for _ in 0..128 {
            let state = SupplierState::new();
            state.connected().unwrap();
            let start = Barrier::new(2);
            thread::scope(|scope| {
                let claim = scope.spawn(|| {
                    start.wait();
                    state.acquire()
                });
                start.wait();
                state.close_admission();
                let pin = claim.join().unwrap();
                assert!(matches!(state.connected(), Err(Error::Unassigned)));
                assert!(matches!(state.acquire(), Err(Error::Unassigned)));
                match pin {
                    Ok(pin) => {
                        assert_eq!(state.consumers(), 1);
                        let retained = pin.clone();
                        assert_eq!(state.consumers(), 2);
                        drop(pin);
                        assert_eq!(state.consumers(), 1);
                        drop(retained);
                    }
                    Err(Error::Unassigned) => {}
                    Err(error) => panic!("unexpected acquisition failure: {error:?}"),
                }
                assert_eq!(state.consumers(), 0);
            });
        }
    }
}
