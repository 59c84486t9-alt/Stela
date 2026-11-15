//! Device models every PE reaches under their own lock instead of the
//! board's ([`OwnLockRegisters`]): a model a driver polls in tight loops,
//! whose register accesses reach no other device. The bus keeps a port
//! ([`Port`]) on the same state for the board's own paths: an access the
//! board routes there, power changes, time advances and the host's reads.
//!
//! Every interrupt line change the model makes, under either path, waits in
//! its queue with the CPU and count of the access that made it until the
//! board hands it on ([`AppleDevices::deliver_own`] at the start of every
//! hold of its lock, and the settlement that ends each board call), so the
//! interrupt controller sees the changes in the order and at the counts
//! they were made. Lock order is the board's, then the model's: the model's
//! path never takes the board's lock while it holds its own.

use super::*;
use core::sync::atomic::{AtomicBool, Ordering};
use stela_contracts::Refusal;
use stela_contracts::bus::{
    Access, AdvancePolicy, Lifecycle, LifecycleState, MmioDevice, MmioError, Width,
};
use stela_contracts::interrupt::{CpuIndex, InterruptSink, Wire};
use stela_engine::machine::engine::{OwnLockAccess, OwnLockRegisters};
use stela_engine::platform::sync::DeviceLock;

/// A line change the model made, not yet handed to the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Queued {
    pub wire: Wire,
    pub level: bool,
    pub cpu: CpuIndex,
    pub now: u64,
}

/// The model and what its accesses left for the board.
pub(super) struct State<T> {
    pub device: T,
    /// Each line's level as the model last drove it, queued changes
    /// included.
    levels: Vec<(Wire, bool)>,
    queued: Vec<Queued>,
    /// A machine transition the model requested, for the board.
    reset: Option<Reset>,
    /// Accesses through [`Handle`], and those that found the lock held.
    pub own_accesses: u64,
    pub own_waits: u64,
    /// Line changes the board took ([`Shared::take_queued`]).
    pub delivered: u64,
}

pub(super) struct Shared<T> {
    state: DeviceLock<State<T>>,
    /// Whether `State::queued` or `State::reset` holds anything, read
    /// without the lock.
    pending: AtomicBool,
    name: &'static str,
    base: u64,
    bytes: u64,
}

/// The model's interrupt output: changes from the level it last drove are
/// queued with the access's CPU and count.
struct Sink<'a> {
    levels: &'a mut Vec<(Wire, bool)>,
    queued: &'a mut Vec<Queued>,
    cpu: CpuIndex,
    now: u64,
}

impl InterruptSink for Sink<'_> {
    fn set_level(&mut self, wire: Wire, asserted: bool) {
        match self.levels.iter_mut().find(|(known, _)| *known == wire) {
            Some((_, level)) if *level == asserted => return,
            Some((_, level)) => *level = asserted,
            // Every line starts low, as the board's latch has it.
            None if !asserted => return,
            None => self.levels.push((wire, asserted)),
        }
        self.queued.push(Queued {
            wire,
            level: asserted,
            cpu: self.cpu,
            now: self.now,
        });
    }
}

impl<T: MmioDevice> Shared<T> {
    pub(super) fn new(device: T, base: u64, bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            name: device.name(),
            state: DeviceLock::new(State {
                device,
                levels: Vec::new(),
                queued: Vec::new(),
                reset: None,
                own_accesses: 0,
                own_waits: 0,
                delivered: 0,
            }),
            pending: AtomicBool::new(false),
            base,
            bytes,
        })
    }

    /// Run `f` on the model with an access of `cpu` at `now` whose line
    /// changes and transition request wait for the board.
    fn access<R>(
        &self,
        state: &mut State<T>,
        cpu: CpuIndex,
        now: u64,
        f: impl FnOnce(&mut T, &mut Access<'_>) -> R,
    ) -> (R, bool) {
        let State {
            device,
            levels,
            queued,
            reset,
            ..
        } = state;
        let before = queued.len();
        let mut sink = Sink {
            levels,
            queued,
            cpu,
            now,
        };
        let mut access = Access::new(cpu, now, &mut sink);
        let result = f(device, &mut access);
        let requested = reset_reason(&access);
        let changed = queued.len() != before || requested.is_some();
        if reset.is_none() {
            *reset = requested;
        }
        if changed {
            self.pending.store(true, Ordering::Release);
        }
        (result, changed)
    }

    /// Run `f` on the model under its lock, from the board.
    pub(super) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.state.lock().device)
    }

    /// The line changes and transition request waiting for the board, in
    /// order; none without taking the lock when nothing waits.
    pub(super) fn take_queued(&self) -> Option<(Vec<Queued>, Option<Reset>)> {
        if !self.pending.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.lock();
        self.pending.store(false, Ordering::Relaxed);
        let queued = core::mem::take(&mut state.queued);
        state.delivered += queued.len() as u64;
        Some((queued, state.reset.take()))
    }

    /// The counts of the accesses under the model's own lock and of the
    /// line changes the board took since the last call.
    pub(super) fn take_counts(&self) -> (u64, u64, u64) {
        let mut state = self.state.lock();
        (
            core::mem::take(&mut state.own_accesses),
            core::mem::take(&mut state.own_waits),
            core::mem::take(&mut state.delivered),
        )
    }

    /// The offset and width of an access at `physical` of `bytes`, as the
    /// bus would route it.
    fn route(&self, physical: u64, bytes: u8) -> Result<(u64, Width), DeviceError> {
        let width = width(bytes)?;
        if !physical.is_multiple_of(width.bytes()) {
            return Err(describe(MmioError::Misaligned {
                address: physical,
                width,
            }));
        }
        let offset = physical - self.base;
        if offset + width.bytes() > self.bytes {
            return Err(describe(MmioError::Unmapped {
                address: physical,
                width,
            }));
        }
        Ok((offset, width))
    }

    fn own<R>(
        &self,
        cpu: CpuIndex,
        now: u64,
        f: impl FnOnce(&mut T, &mut Access<'_>) -> R,
    ) -> (R, bool) {
        let mut state = match self.state.try_lock() {
            Some(state) => state,
            None => {
                let mut state = self.state.lock();
                state.own_waits += 1;
                state
            }
        };
        state.own_accesses += 1;
        self.access(&mut state, cpu, now, f)
    }
}

/// The engine's handle on a model behind its own lock.
pub(super) struct Handle<T>(pub Arc<Shared<T>>);

impl<T: MmioDevice + Send> OwnLockRegisters for Handle<T> {
    fn serves(&self, physical: u64) -> bool {
        physical
            .checked_sub(self.0.base)
            .is_some_and(|offset| offset < self.0.bytes)
    }
    fn read(&self, cpu: usize, physical: u64, bytes: u8, now: u64) -> OwnLockAccess<u64> {
        let (offset, width) = match self.0.route(physical, bytes) {
            Ok(route) => route,
            Err(error) => {
                return OwnLockAccess {
                    result: Err(error),
                    queued: false,
                };
            }
        };
        let (result, queued) = self.0.own(cpu, now, |device, access| {
            device
                .read(offset, width, access)
                .map(|value| value & width.mask())
                .map_err(describe)
        });
        OwnLockAccess { result, queued }
    }
    fn write(
        &self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> OwnLockAccess<()> {
        let (offset, width) = match self.0.route(physical, bytes) {
            Ok(route) => route,
            Err(error) => {
                return OwnLockAccess {
                    result: Err(error),
                    queued: false,
                };
            }
        };
        let (result, queued) = self.0.own(cpu, now, |device, access| {
            device
                .write(offset, width, value & width.mask(), access)
                .map_err(describe)
        });
        OwnLockAccess { result, queued }
    }
}

/// The bus's model at the shared state: every call locks it, and its line
/// changes wait for the board's settlement like the handle's.
pub(super) struct Port<T>(pub Arc<Shared<T>>);

impl<T: MmioDevice> Port<T> {
    fn on<R>(&self, access: &Access<'_>, f: impl FnOnce(&mut T, &mut Access<'_>) -> R) -> R {
        let mut state = self.0.state.lock();
        self.0.access(&mut state, access.cpu, access.now, f).0
    }
}

impl<T: MmioDevice> MmioDevice for Port<T> {
    fn advance_policy(&self) -> AdvancePolicy {
        self.0.state.lock().device.advance_policy()
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        // The port's own hook stands for the model's.
        let hooked = self.0.state.lock().device.lifecycle().is_some();
        hooked.then_some(self as &mut dyn Lifecycle)
    }
    fn name(&self) -> &'static str {
        self.0.name
    }
    fn register_name(&self, offset: u64) -> Option<&'static str> {
        self.0.state.lock().device.register_name(offset)
    }
    // Never plain: the handle changes the model without the bus's epoch.
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        self.on(access, |device, own| device.read(offset, width, own))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.on(access, |device, own| {
            device.write(offset, width, value, own)
        })
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.on(access, |device, own| device.advance(own))
    }
}

impl<T: MmioDevice> Lifecycle for Port<T> {
    fn check_lifecycle(&self, proposed: LifecycleState) -> core::result::Result<(), Refusal> {
        let mut state = self.0.state.lock();
        match state.device.lifecycle() {
            Some(lifecycle) => lifecycle.check_lifecycle(proposed),
            None => Ok(()),
        }
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        self.on(access, |device, own| {
            if let Some(lifecycle) = device.lifecycle() {
                lifecycle.set_lifecycle(proposed, own);
            }
        });
    }
}

impl AppleDevices {
    /// Hand on what the models behind their own locks queued: each line
    /// change into the latch and the service batch as its access's CPU and
    /// count made it, and a transition they requested. `None` when nothing
    /// waited, else the latest change, if any.
    pub(super) fn hand_on_own(&mut self) -> Option<Option<Queued>> {
        let (queued, reset) = self.nor_shared.as_ref()?.take_queued()?;
        self.service.retain_reset(&mut self.reset, reset);
        for change in &queued {
            self.latch.set_level(change.wire, change.level);
            self.capture_inputs(change.cpu, change.now);
        }
        self.nor_touch.set(true);
        Some(queued.last().copied())
    }

    /// [`Devices::deliver_own`]: hand on what waited and apply it as the
    /// latest change's access would have.
    pub(super) fn deliver_own_queued(&mut self) -> Result<bool, DeviceError> {
        match self.hand_on_own() {
            None => Ok(false),
            Some(None) => Ok(true),
            Some(Some(last)) => self.settle(last.cpu, last.now, None).map(|()| true),
        }
    }
}
