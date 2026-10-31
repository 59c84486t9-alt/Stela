//! [`Service`] for every PE at once, as the call gate's [`GateService`].
//!
//! The device is one Vulkan device with one state, so calls take turns under
//! a lock. A PE waiting its turn runs the platform's `relax`, since the call
//! it waits for may need that PE: on the CPU that runs the kernel, waiting
//! without running it would never end. Each call runs through the platform's
//! `run`, as a compile needs more stack than a PE keeps; the lock makes one
//! such stack enough.
//!
//! The gate asks about completed work under the board's lock, where a Vulkan
//! call would hold up every PE, so [`GateService::signaled`] only reads a
//! flag. The platform reports each GPU interrupt ([`SharedService::interrupted`]);
//! whoever next holds the service looks at the device for what completed.
use super::Service;
use crate::metal::{shader::Compiler, vulkan::backend::Backend};
use core::{
    cell::UnsafeCell,
    num::NonZeroU64,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
};
use stela_contracts::gate::{CallerFault, CallerMemory, GateService, MemoryRange};

pub struct SharedService<B: Backend, C: Compiler> {
    service: UnsafeCell<Service<B, C>>,
    locked: AtomicBool,
    /// The GPU interrupted since the device was last asked.
    stale: AtomicBool,
    /// Completed work the gate has not taken.
    completed: AtomicBool,
    host: ServiceHost,
}

/// What the platform does for the shared service.
#[derive(Clone, Copy)]
pub struct ServiceHost {
    /// Waits a moment for the turn's holder.
    pub relax: fn(),
    /// Calls its argument on a stack a compile fits on. Only a turn's holder
    /// comes here.
    pub run: fn(&mut dyn FnMut()),
}

// SAFETY: the lock gives one PE at a time the service, which `Send` lets move
// between them.
unsafe impl<B: Backend + Send, C: Compiler + Send> Sync for SharedService<B, C> {}
// SAFETY: every field is, given the bounds.
unsafe impl<B: Backend + Send, C: Compiler + Send> Send for SharedService<B, C> {}

/// A turn at the service.
pub(super) struct Turn<'a, B: Backend, C: Compiler>(&'a SharedService<B, C>);

impl<B: Backend, C: Compiler> Deref for Turn<'_, B, C> {
    type Target = Service<B, C>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this turn holds the lock.
        unsafe { &*self.0.service.get() }
    }
}

impl<B: Backend, C: Compiler> DerefMut for Turn<'_, B, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this turn holds the lock.
        unsafe { &mut *self.0.service.get() }
    }
}

impl<B: Backend, C: Compiler> Drop for Turn<'_, B, C> {
    fn drop(&mut self) {
        // A failed `try_turn` left the look to this holder, which it sees
        // once `stale` has been raised.
        let completed = self.0.stale.swap(false, Ordering::SeqCst) && (**self).signaled();
        if completed || self.retiring() {
            self.0.completed.store(true, Ordering::Release);
        }
        self.0.locked.store(false, Ordering::SeqCst);
        if self.0.stale.load(Ordering::SeqCst) {
            self.0.interrupted();
        }
    }
}

impl<B: Backend, C: Compiler> SharedService<B, C> {
    pub fn new(service: Service<B, C>, host: ServiceHost) -> Self {
        Self {
            service: UnsafeCell::new(service),
            locked: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            host,
        }
    }

    pub(super) fn try_turn(&self) -> Option<Turn<'_, B, C>> {
        (!self.locked.swap(true, Ordering::SeqCst)).then(|| Turn(self))
    }

    fn turn(&self) -> Turn<'_, B, C> {
        loop {
            if let Some(turn) = self.try_turn() {
                return turn;
            }
            (self.host.relax)();
        }
    }

    /// Runs `call` on the service in a turn of its own.
    fn call<R>(&self, call: impl FnOnce(&mut Service<B, C>) -> R) -> R {
        let mut turn = self.turn();
        let (mut call, mut result) = (Some(call), None);
        (self.host.run)(&mut || {
            if let Some(call) = call.take() {
                result = Some(call(&mut turn));
            }
        });
        result.expect("the platform runs what it is given")
    }

    /// The GPU interrupted: look for what completed now, or leave that to the
    /// call under way.
    pub fn interrupted(&self) {
        self.stale.store(true, Ordering::SeqCst);
        drop(self.try_turn());
    }
}

impl<B: Backend + Send, C: Compiler + Send> GateService for SharedService<B, C> {
    fn connect(&self) -> Result<NonZeroU64, &'static str> {
        self.call(|service| service.connect())
            .map_err(|fault| fault.reason)
    }

    fn disconnect(&self, connection: NonZeroU64) {
        // The gate closes only connections it opened and holds.
        let closed = self.call(|service| service.disconnect(connection));
        debug_assert!(closed.is_ok());
    }

    fn serve(
        &self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> Result<(), CallerFault> {
        self.call(|service| service.serve(connection, record, caller))
    }

    fn import(
        &self,
        connection: NonZeroU64,
        ranges: &[MemoryRange],
        token: NonZeroU64,
    ) -> Result<NonZeroU64, &'static str> {
        self.call(|service| service.import(connection, ranges, token))
            .map_err(|fault| fault.reason)
    }

    fn retired(&self) -> Option<NonZeroU64> {
        self.call(|service| service.retired())
    }

    fn signaled(&self) -> bool {
        self.completed.swap(false, Ordering::Acquire)
    }
}
