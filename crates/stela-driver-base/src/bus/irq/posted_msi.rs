// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Stela contributors
//! Root and route completion for posted MSI/MSI-X, separate from payload DMA.
use super::MsiMessage;
use alloc::boxed::Box;
use core::cell::Cell;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RootUnavailable,
    RootFailed,
    Unbound,
    AlreadyBound {
        original: MsiMessage,
        attempted: MsiMessage,
    },
}
/// The consumed requester/root epoch and its exclusively allocated route.
///
/// # Safety
/// Bind only this owner's original root and the registry's allocated message.
/// Numeric addresses/BDFs alone grant no permission. Keep delivery/remapping
/// resources through completed drain/release or quarantine. `drain_posted_msi`
/// completes every issued MSI/MSI-X on that path independently of payload
/// IOTLB drain, reset, elapsed time and CPU IRR/ISR. Check the original epoch
/// and process context on every operation. Failure/Drop retains uncertain roots.
pub unsafe trait DeliveryOwner {
    fn bind_route(&mut self, message: MsiMessage) -> Result<(), Error>;
    /// # Safety
    /// This original source cannot issue further payload or interrupts:
    /// device stop/reset is acknowledged, every route is masked and translated
    /// payload writes drained. Keep configuration, DMA and root owners.
    unsafe fn drain_posted_msi(&self) -> Result<(), Error>;
}
/// No native producer exists until the common root delivery adapter is supplied
/// (host-driver requirement 9.2). An unavailable capability permits attachment
/// but refuses armed route retirement. Model construction is host-test-only.
pub struct MsiCompletion {
    owner: Option<Box<dyn DeliveryOwner>>,
    message: Option<MsiMessage>,
    binding_error: Option<Error>,
    drained: Cell<bool>,
}
impl MsiCompletion {
    pub fn unavailable() -> Self {
        Self {
            owner: None,
            message: None,
            binding_error: None,
            drained: Cell::new(false),
        }
    }
    #[cfg(all(any(test, feature = "test-support"), unix, target_arch = "x86_64"))]
    pub fn model(owner: Box<dyn DeliveryOwner>) -> Self {
        let mut completion = Self::unavailable();
        completion.owner = Some(owner);
        completion
    }
    /// # Safety
    /// This is the original registry's exclusively allocated route for this
    /// requester/root owner. Keep it through source/CPU/work retirement.
    pub unsafe fn bind_route(&mut self, message: MsiMessage) -> Result<(), Error> {
        if let Some(original) = self.message {
            return Err(Error::AlreadyBound {
                original,
                attempted: message,
            });
        }
        self.message = Some(message);
        if let Some(owner) = &mut self.owner
            && let Err(error) = owner.bind_route(message)
        {
            self.binding_error = Some(error);
            return Err(error);
        }
        Ok(())
    }
    /// # Safety
    /// The bound source cannot resume; all routes are masked, device stop/reset
    /// and translated payload completion are acknowledged. All original owners
    /// remain held through this independent completion and later CPU/work drain.
    pub unsafe fn drain(&self) -> Result<(), Error> {
        if self.message.is_none() {
            return Err(Error::Unbound);
        }
        if let Some(error) = self.binding_error {
            return Err(error);
        }
        let owner = self.owner.as_ref().ok_or(Error::RootUnavailable)?;
        if !self.drained.get() {
            // SAFETY: caller supplies terminal source/payload ownership; this
            // owner independently acknowledges the bound posted-interrupt path.
            unsafe { owner.drain_posted_msi() }?;
            self.drained.set(true);
        }
        Ok(())
    }
}
impl Drop for MsiCompletion {
    fn drop(&mut self) {
        if self.message.is_some() && !self.drained.get() {
            core::mem::forget(self.owner.take());
        }
    }
}

#[cfg(all(test, unix, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const MESSAGE: MsiMessage = MsiMessage {
        address: 0xfee00000,
        data: 0x51,
    };
    #[derive(Default)]
    struct State {
        binds: AtomicUsize,
        drains: AtomicUsize,
        drops: AtomicUsize,
        fail_bind: AtomicBool,
        fail_drain: AtomicBool,
    }
    struct Root(Arc<State>);
    // SAFETY: isolated original-route peer; it has no hardware, IRQ, work or
    // payload users and records independent root completion/refusal events.
    unsafe impl DeliveryOwner for Root {
        fn bind_route(&mut self, message: MsiMessage) -> Result<(), Error> {
            assert_eq!(message, MESSAGE);
            self.0.binds.fetch_add(1, Ordering::Relaxed);
            if self.0.fail_bind.load(Ordering::Relaxed) {
                Err(Error::RootFailed)
            } else {
                Ok(())
            }
        }
        unsafe fn drain_posted_msi(&self) -> Result<(), Error> {
            self.0.drains.fetch_add(1, Ordering::Relaxed);
            if self.0.fail_drain.load(Ordering::Relaxed) {
                Err(Error::RootFailed)
            } else {
                Ok(())
            }
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            self.0.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn bind(completion: &mut MsiCompletion) -> Result<(), Error> {
        // SAFETY: this synchronous peer owns the one symbolic allocated route.
        unsafe { completion.bind_route(MESSAGE) }
    }
    fn drain(completion: &MsiCompletion) -> Result<(), Error> {
        // SAFETY: no model source or asynchronous user can issue traffic; all
        // original symbolic resources remain kept by this completion owner.
        unsafe { completion.drain() }
    }
    #[test]
    fn unavailable_root_refuses_even_a_bound_route() {
        let mut c = MsiCompletion::unavailable();
        assert_eq!(drain(&c), Err(Error::Unbound));
        bind(&mut c).unwrap();
        assert_eq!(drain(&c), Err(Error::RootUnavailable));
        assert_eq!(drain(&c), Err(Error::RootUnavailable));
    }
    #[test]
    fn exact_route_completion_is_one_shot_and_cannot_bind_another_message() {
        let state = Arc::new(State::default());
        let mut c = MsiCompletion::model(Box::new(Root(state.clone())));
        assert_eq!(drain(&c), Err(Error::Unbound));
        bind(&mut c).unwrap();
        let attempted = MsiMessage {
            data: 0x52,
            ..MESSAGE
        };
        assert_eq!(
            // SAFETY: this isolated fixture owns the second symbolic route;
            // the completion must refuse replacing its first bound route.
            unsafe { c.bind_route(attempted) },
            Err(Error::AlreadyBound {
                original: MESSAGE,
                attempted
            })
        );
        drain(&c).unwrap();
        drain(&c).unwrap();
        drop(c);
        assert_eq!(state.binds.load(Ordering::Relaxed), 1);
        assert_eq!(state.drains.load(Ordering::Relaxed), 1);
        assert_eq!(state.drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn failed_binding_is_sticky_and_keeps_the_root_without_drain() {
        let state = Arc::new(State::default());
        state.fail_bind.store(true, Ordering::Relaxed);
        let mut c = MsiCompletion::model(Box::new(Root(state.clone())));
        assert_eq!(bind(&mut c), Err(Error::RootFailed));
        state.fail_bind.store(false, Ordering::Relaxed);
        assert_eq!(drain(&c), Err(Error::RootFailed));
        drop(c);
        assert_eq!(state.drains.load(Ordering::Relaxed), 0);
        assert_eq!(state.drops.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn abandoned_or_failed_completion_keeps_the_original_root() {
        for failed in [false, true] {
            let state = Arc::new(State::default());
            let mut c = MsiCompletion::model(Box::new(Root(state.clone())));
            bind(&mut c).unwrap();
            if failed {
                state.fail_drain.store(true, Ordering::Relaxed);
                assert_eq!(drain(&c), Err(Error::RootFailed));
            }
            drop(c);
            assert_eq!(state.drops.load(Ordering::Relaxed), 0);
        }
    }
}
