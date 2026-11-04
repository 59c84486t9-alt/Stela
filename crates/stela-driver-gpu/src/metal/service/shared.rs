//! [`Service`] for every PE at once, as the call gate's [`GateService`].
//!
//! The device is one Vulkan device with one state, so calls take turns under
//! a lock. A PE waiting its turn runs the platform's `relax`, since the call
//! it waits for may need that PE: on the CPU that runs the kernel, waiting
//! without running it would never end. Each call runs through the platform's
//! `run`, as a compile needs more stack than a PE keeps; the lock makes one
//! such stack enough for a device.
//!
//! The gate asks about completed work under the board's lock, where a Vulkan
//! call would hold up every PE, so [`GateService::signaled`] only reads a
//! flag. The platform reports each GPU interrupt ([`SharedService::interrupted`]);
//! whoever next holds the service looks at the device for what completed.
//!
//! A `Poll` that finds another call holding the service is answered with the
//! newest serial a holder saw completed, rather than waiting out a commit or
//! a compile: the completion interrupt that wakes a frontend's poll is raised
//! only once a holder has seen that serial, so the answer covers it. Only a
//! connection whose poll the service itself answered is answered this way,
//! and never once the device is lost.
use super::{
    Service,
    wire::{self, GateCall, Operation, Status},
};
use crate::metal::{shader::Compiler, vulkan::backend::Backend};
use core::{
    cell::UnsafeCell,
    mem::size_of,
    num::NonZeroU64,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_contracts::gate::{CallerFault, CallerMemory, GateService, MemoryRange};

pub struct SharedService<B: Backend, C: Compiler> {
    service: UnsafeCell<Service<B, C>>,
    locked: AtomicBool,
    /// The GPU interrupted since the device was last asked.
    stale: AtomicBool,
    /// Completed work the gate has not taken.
    completed: AtomicBool,
    /// The newest serial a holder saw completed, or POLL_UNAVAILABLE.
    reached: AtomicU64,
    /// Connections whose `Poll` the service answered, zero for a free slot:
    /// those a busy service answers from `reached`.
    polling: [AtomicU64; POLLING],
    host: ServiceHost,
}

/// More connections than a device's gates open.
const POLLING: usize = 64;
/// A lost device or this serial must use the normal poll path.
const POLL_UNAVAILABLE: u64 = u64::MAX;

/// What the platform does for the shared service.
#[derive(Clone, Copy)]
pub struct ServiceHost {
    /// Waits a moment for the turn's holder.
    pub relax: fn(),
    /// What `run` takes first: this service's stack.
    pub stack: u64,
    /// Calls its argument on a stack a compile fits on. Only a turn's holder
    /// comes here.
    pub run: fn(u64, &mut dyn FnMut()),
    /// Told why the service refused a guest's call.
    pub report: fn(&str),
    /// Told what a guest's call made, such as a render pipeline's stages and
    /// vertex fetch.
    pub note: fn(&str),
    /// The platform's tick counter, which times [`Served`].
    pub ticks: fn() -> u64,
    /// Told of each guest call the gate served.
    pub served: fn(Served),
}

/// A guest call the gate served, in the platform's ticks: the PE that rang
/// for it runs no guest code from the doorbell until the call returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Served {
    /// The call's operation code, zero when its record was out of reach.
    pub operation: u32,
    pub status: Status,
    /// Waiting for the turn another call held.
    pub waited: u64,
    /// Holding the turn, the look at completed work after the call included.
    pub held: u64,
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
        let mut completed = false;
        if self.0.stale.swap(false, Ordering::SeqCst) || self.device().is_lost() {
            // Polling enters Vulkan too. An interrupt can take this path
            // without a guest call's stack switch around it.
            (self.0.host.run)(self.0.host.stack, &mut || completed = (**self).signaled());
        }
        let device = self.device();
        let reached = if device.is_lost() {
            POLL_UNAVAILABLE
        } else {
            device.completed_serial()
        };
        // Publish one snapshot before making the completion observable.
        self.0.reached.store(reached, Ordering::Release);
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
            reached: AtomicU64::new(0),
            polling: [const { AtomicU64::new(0) }; POLLING],
            host,
        }
    }

    fn polls(&self, connection: NonZeroU64) -> bool {
        self.polling
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == connection.get())
    }

    /// Answers `connection`'s `Poll` at `record` from `reached`, or leaves
    /// the call to the service: any other operation or record, a connection
    /// the service never answered a poll for, a lost device, or a span out
    /// of the caller's reach.
    pub(super) fn poll_while_held(
        &self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> bool {
        let mut raw = [0; size_of::<GateCall>()];
        if caller.read(record, &mut raw).is_err() {
            return false;
        }
        let mut call: GateCall = wire::read(&raw).expect("a record of its own size");
        let (request_bytes, response_bytes) = Operation::Poll.sizes();
        if call.operation != Operation::Poll.raw()
            || call.request.length != request_bytes as u64
            || call.response.length != response_bytes as u64
        {
            return false;
        }
        let reached = self.reached.load(Ordering::Acquire);
        // Check membership after acquiring the serial. A close that
        // precedes its publication has already removed that connection.
        if reached == POLL_UNAVAILABLE || !self.polls(connection) {
            return false;
        }
        let value = wire::Value { value: reached };
        let mut response = [0; size_of::<wire::Value>()];
        wire::write(&value, &mut response).expect("a record of its own size");
        if caller.write(call.response.address, &response).is_err() {
            return false;
        }
        call.status = Status::Ok.raw();
        call.reason_length = 0;
        wire::write(&call, &mut raw).expect("a record of its own size");
        caller.write(record, &raw).is_ok()
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
        (self.host.run)(self.host.stack, &mut || {
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

    /// Closes admission while holding the same turn as guest calls, so a
    /// call either precedes closure or observes it.
    pub fn begin_quiesce(&self) {
        self.call(|service| service.begin_quiesce());
    }

    /// Advances the native owner's GPU stop protocol on the service stack.
    /// An idle answer does not disconnect the gate or invalidate DMA maps.
    pub fn quiesce_step(&self) -> crate::metal::device::lifecycle::QuiesceStatus {
        self.call(|service| service.quiesce_step())
    }
}

impl<B: Backend + Send, C: Compiler + Send> GateService for SharedService<B, C> {
    fn connect(&self) -> Result<NonZeroU64, &'static str> {
        self.call(|service| service.connect())
            .map_err(|fault| fault.reason)
    }

    fn disconnect(&self, connection: NonZeroU64) {
        // The gate closes only connections it opened and holds.
        let closed = self.call(|service| {
            for slot in &self.polling {
                let _ =
                    slot.compare_exchange(connection.get(), 0, Ordering::AcqRel, Ordering::Acquire);
            }
            service.disconnect(connection)
        });
        debug_assert!(closed.is_ok());
    }

    fn serve(
        &self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> Result<(), CallerFault> {
        let rang = (self.host.ticks)();
        let mut turn = match self.try_turn() {
            Some(turn) => turn,
            None if self.poll_while_held(connection, record, caller) => {
                let left = (self.host.ticks)();
                (self.host.served)(Served {
                    operation: Operation::Poll.raw(),
                    status: Status::Ok,
                    waited: 0,
                    held: left.wrapping_sub(rang),
                });
                return Ok(());
            }
            None => self.turn(),
        };
        let entered = (self.host.ticks)();
        let mut answer = None;
        (self.host.run)(self.host.stack, &mut || {
            let served = turn.serve(connection, record, caller);
            answer = Some((served, turn.refused.take(), turn.noted.take(), turn.served));
        });
        let (served, refused, noted, (operation, status)) =
            answer.expect("the platform runs what it is given");
        if served.is_ok()
            && operation == Operation::Poll.raw()
            && status == Status::Ok
            && !self.polls(connection)
        {
            // The turn serializes enrollment with other polls and close.
            let _ = self.polling.iter().find(|slot| {
                slot.compare_exchange(0, connection.get(), Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            });
        }
        drop(turn);
        let left = (self.host.ticks)();
        (self.host.served)(Served {
            operation,
            status,
            waited: entered.wrapping_sub(rang),
            held: left.wrapping_sub(entered),
        });
        if let Some(reason) = refused {
            (self.host.report)(&reason);
        }
        if let Some(text) = noted {
            (self.host.note)(&text);
        }
        served
    }

    fn import(
        &self,
        connection: NonZeroU64,
        ranges: &[MemoryRange],
        token: NonZeroU64,
    ) -> Result<NonZeroU64, &'static str> {
        let imported = self
            .call(|service| service.import(connection, ranges, token))
            .map_err(|fault| fault.reason);
        if let Err(reason) = imported {
            (self.host.report)(reason);
        }
        imported
    }

    fn retired(&self) -> Option<NonZeroU64> {
        self.call(|service| service.retired())
    }

    fn quiesced(&self) -> bool {
        self.call(|service| service.quiesced())
    }

    fn signaled(&self) -> bool {
        self.completed.swap(false, Ordering::Acquire)
    }
}
