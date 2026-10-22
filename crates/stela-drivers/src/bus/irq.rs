//! Owned native interrupt registrations. Device acknowledgement, completion
//! fences and reset algorithms belong to the device handler/source owner.
use alloc::{boxed::Box, sync::Arc};
use core::{
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering},
};

pub const FIRST_VECTOR: u8 = 0x50;
pub const VECTOR_COUNT: usize = 16;
const ARMING: u8 = 0;
const LIVE: u8 = 1;
const CLOSING: u8 = 2;
const QUARANTINED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqError {
    Unavailable,
    WrongCpu,
    Exhausted,
    Unsupported,
    FailedRead,
    Mask,
    Quiesce,
    Route,
    Drain,
    Unregistered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsiMessage {
    pub address: u64,
    pub data: u32,
}

/// Physical fixed-delivery target, qualified by the owning CPU adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Target {
    pub destination: u8,
    pub vector: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Polarity {
    High,
    Low,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trigger {
    Edge,
    Level,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineRoute {
    pub gsi: u32,
    pub polarity: Polarity,
    pub trigger: Trigger,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteRequest {
    Msi,
    Line(LineRoute),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Msi(MsiMessage),
    Line { target: Target, line: LineRoute },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    NotMine,
    Handled,
}

/// Immutable, pre-bound sharing group. Every member remains retained until
/// the entire physical source group is masked, stopped and drained. Joining
/// or removing a member requires complete group retirement and re-registration;
/// dynamic sharing is deliberately unavailable. Dispatch invokes every member
/// without cloning, allocating or releasing references in interrupt context.
pub struct SharedHandlers(Box<[Arc<dyn Handler>]>);
impl SharedHandlers {
    pub fn new(members: alloc::vec::Vec<Arc<dyn Handler>>) -> Result<Self, IrqError> {
        if members.is_empty()
            || members.len() > 32
            || members
                .iter()
                .enumerate()
                .any(|(i, h)| members[..i].iter().any(|old| Arc::ptr_eq(old, h)))
        {
            return Err(IrqError::Unsupported);
        }
        Ok(Self(members.into_boxed_slice()))
    }
}
impl Handler for SharedHandlers {
    fn handle(&self) -> Disposition {
        let mut result = Disposition::NotMine;
        for handler in &self.0 {
            if handler.handle() == Disposition::Handled {
                result = Disposition::Handled;
            }
        }
        result
    }
}

/// A request that did not register. Once the CPU check passes, a refusal
/// before anything is published gives the source and handler back
/// unchanged, so the driver can keep polling its device; after a wrong-CPU
/// check or an uncertain arming failure they stay retained.
pub struct RequestError {
    pub error: IrqError,
    pub returned: Option<(Box<dyn Source>, Arc<dyn Handler>)>,
}

impl core::fmt::Debug for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestError")
            .field("error", &self.error)
            .field("returned", &self.returned.is_some())
            .finish()
    }
}

impl From<IrqError> for RequestError {
    fn from(error: IrqError) -> Self {
        Self {
            error,
            returned: None,
        }
    }
}

/// Object-safe mount service for driver consumers, independent of CPU type.
/// The actual platform initializes and permanently retains the controller.
pub trait IrqController: Sync {
    fn request(
        &'static self,
        source: Box<dyn Source>,
        handler: Arc<dyn Handler>,
    ) -> Result<Box<dyn IrqRegistration>, IrqError>;
    fn quarantine_count(&self) -> u64;
}

/// Process/deferred, CPU-affine owner. This trait intentionally supplies no
/// Send/Sync promise; neither operations nor final Drop are hard-IRQ-safe.
pub trait IrqRegistration {
    fn vector(&self) -> u8;
    fn handled(&self) -> Result<u64, IrqError>;
    fn retire(&mut self) -> Result<(), IrqError>;
}

/// Fast hard-IRQ callback. Acknowledge owned real causes before returning, or
/// actually mask a deferred source under its retained work owner. The platform
/// emits EOI afterwards. A bounded diagnostic may deliberately leave a level
/// asserted once to observe actual EOI/retrigger behavior. No blocking, allocation or final heap/Arc
/// release is permitted. Defer work through the device's retained work owner.
pub trait Handler: Send + Sync {
    fn handle(&self) -> Disposition;
}

/// Exclusive real device/interrupt source retained by its registration.
///
/// # Safety
/// The source initially owns an inactive route, with no old firmware/driver
/// callback or unresolved alias. `mask` actually disables interrupt generation
/// and observes the device's acknowledgement. `quiesce` stops submissions and
/// device DMA/posted interrupt writes, cancels/drains queued workers/timers
/// and acknowledges pending causes. It excludes future device delivery/work
/// until explicit `unmask`; the registry invokes it again after callback drain
/// for work from a formerly in-flight callback. Both calls must retain every
/// callback-reachable context, BO, reservation, pin and CPU/DMA lease until
/// registration retirement finishes; quiescence alone never authorizes their
/// release or skips an actual hardware fence/IOTLB acknowledgement.
/// `program` installs exactly the supplied typed route while masked;
/// `unmask` enables only this route. Errors must never free hardware-reachable
/// state. These process/deferred methods and final Drop are never ISR-safe.
/// A source may be genuinely CPU-affine and !Send. Only its checked owning
/// CPU's process registration accesses or finally releases it; IRQ dispatch
/// sees the separately retained Send+Sync handler only.
pub unsafe trait Source {
    fn mask(&mut self) -> Result<(), IrqError>;
    fn quiesce(&mut self) -> Result<(), IrqError>;
    fn route(&self) -> RouteRequest;
    /// # Safety
    /// The route is owned by the registry on its qualified CPU, matches this
    /// source's request, and its retained callback is published before unmask.
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError>;
    /// # Safety
    /// A live registry retains the programmed route and every callback owner.
    unsafe fn unmask(&mut self) -> Result<(), IrqError>;
    /// Called after source quiescence, CPU IRR/ISR drain and callback EOI.
    /// Check actual route-controller completion (including level Remote IRR)
    /// and drain work queued by any formerly in-flight callback. An error
    /// retains the complete registration; it never authorizes route reuse.
    /// # Safety
    /// The owned source is stopped, CPU IRR/ISR and all in-flight callbacks
    /// have drained. No future callback can begin while synchronization runs.
    unsafe fn synchronize(&mut self) -> Result<(), IrqError>;
}

/// Existing CPU/interrupt controller adapter, never a second IDT/APIC owner.
///
/// # Safety
/// Save/disable and restore operate on this same CPU; their memory clobbers
/// order the critical region. `check_cpu` refuses migration/unavailable state.
/// Routing, pending IRR/ISR reads and EOI have their actual controller effects.
/// `interrupt_window` admits queued IRQs and returns with local IRQs disabled;
/// it is called outside registry locks only. The clock advances during drain.
/// Vector ownership remains exclusive for the registry lifetime; another CPU
/// cannot dispatch a route assigned to this registry's CPU.
pub unsafe trait Platform: Send + Sync {
    fn check_cpu(&self) -> Result<(), IrqError>;
    fn save_and_disable(&self) -> u64;
    /// # Safety
    /// `saved` is this CPU's immediately enclosing save/disable state.
    unsafe fn restore(&self, saved: u64);
    fn target(&self, vector: u8) -> Result<Target, IrqError>;
    fn pending(&self, vector: u8) -> Result<bool, IrqError>;
    fn eoi(&self);
    fn ticks(&self) -> u64;
    fn timeout_ticks(&self) -> u64;
    /// # Safety
    /// No registry lock or non-IRQ-safe resource lock is held; IRQs are off.
    unsafe fn interrupt_window(&self);
}

struct Slot {
    // Release the stopped source while its callback context is still retained.
    source: core::cell::UnsafeCell<Box<dyn Source>>,
    handler: Arc<dyn Handler>,
    state: AtomicU8,
    inflight: AtomicUsize,
    handled: AtomicU64,
}

/// Admission owns these bytes from its first instruction. Every early error
/// retains them observably without allocating or releasing on an unknown CPU.
struct Pending<'a, P: Platform> {
    registry: &'a Registry<P>,
    source: ManuallyDrop<Box<dyn Source>>,
    handler: ManuallyDrop<Arc<dyn Handler>>,
    published: bool,
}
impl<P: Platform> Pending<'_, P> {
    /// The unpublished owners, back to the caller on this checked CPU.
    fn give_back(mut self) -> (Box<dyn Source>, Arc<dyn Handler>) {
        self.published = true;
        // SAFETY: this consumes the unique unpublished owners exactly once.
        unsafe {
            (
                ManuallyDrop::take(&mut self.source),
                ManuallyDrop::take(&mut self.handler),
            )
        }
    }

    fn into_slot(mut self) -> Slot {
        self.published = true;
        // SAFETY: this consumes the unique unpublished owners exactly once.
        Slot {
            // SAFETY: taken exactly once; `published` stops Drop from dropping it again.
            source: core::cell::UnsafeCell::new(unsafe { ManuallyDrop::take(&mut self.source) }),
            // SAFETY: taken exactly once; `published` stops Drop from dropping it again.
            handler: unsafe { ManuallyDrop::take(&mut self.handler) },
            state: AtomicU8::new(ARMING),
            inflight: AtomicUsize::new(0),
            handled: AtomicU64::new(0),
        }
    }
}
impl<P: Platform> Drop for Pending<'_, P> {
    fn drop(&mut self) {
        if !self.published {
            self.registry.count_quarantine();
            // The real Box/Arc allocations remain retained. No source access
            // or final Drop is qualified by a failed admission/CPU check.
        }
    }
}

impl<P: Platform + 'static> IrqController for Registry<P> {
    fn request(
        &'static self,
        source: Box<dyn Source>,
        handler: Arc<dyn Handler>,
    ) -> Result<Box<dyn IrqRegistration>, IrqError> {
        // A refusal's returned owners are released here, on the checked CPU.
        Registry::request(self, source, handler)
            .map(|registration| Box::new(registration) as Box<dyn IrqRegistration>)
            .map_err(|refusal| refusal.error)
    }
    fn quarantine_count(&self) -> u64 {
        Registry::quarantine_count(self)
    }
}

/// One platform-owned vector inventory. Allocations, source operations and
/// **final release**, including callback-owned state, require process/deferred
/// context. Dispatch never clones/drops an Arc or allocates/frees memory.
pub struct Registry<P: Platform> {
    platform: P,
    slots: [AtomicPtr<Slot>; VECTOR_COUNT],
    held: AtomicBool,
    quarantined: AtomicU64,
}

impl<P: Platform> Registry<P> {
    pub const fn new(platform: P) -> Self {
        Self {
            platform,
            slots: [const { AtomicPtr::new(core::ptr::null_mut()) }; VECTOR_COUNT],
            held: AtomicBool::new(false),
            quarantined: AtomicU64::new(0),
        }
    }

    pub fn quarantine_count(&self) -> u64 {
        self.quarantined.load(Ordering::Relaxed)
    }

    fn lock(&self) -> Guard<'_, P> {
        let saved = self.platform.save_and_disable();
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard {
            registry: self,
            saved,
        }
    }

    /// Publish the retained handler before enabling the actual source. Any
    /// uncertain arming failure retains source/handler and quarantines vector,
    /// as does a wrong-CPU check. Vector exhaustion and target or route
    /// refusals give both owners back.
    pub fn request(
        &'static self,
        source: Box<dyn Source>,
        handler: Arc<dyn Handler>,
    ) -> Result<Registration<'static, P>, RequestError> {
        // Retain both actual owners if CPU qualification fails before
        // publication: this consuming API cannot return a failed source to
        // its original CPU, and must never run a !Send source's Drop here.
        let pending = Pending {
            registry: self,
            source: ManuallyDrop::new(source),
            handler: ManuallyDrop::new(handler),
            published: false,
        };
        self.platform.check_cpu()?;
        let guard = self.lock();
        let admitted = self
            .slots
            .iter()
            .position(|slot| slot.load(Ordering::Relaxed).is_null())
            .ok_or(IrqError::Exhausted)
            .and_then(|index| {
                let vector = FIRST_VECTOR + index as u8;
                let target = self.platform.target(vector)?;
                match target.vector == vector && target.destination != 255 {
                    true => Ok((index, vector, target)),
                    false => Err(IrqError::Route),
                }
            });
        let (index, vector, target) = match admitted {
            Ok(admitted) => admitted,
            Err(error) => {
                drop(guard);
                return Err(RequestError {
                    error,
                    returned: Some(pending.give_back()),
                });
            }
        };
        let route = match pending.source.route() {
            RouteRequest::Msi => Route::Msi(MsiMessage {
                address: 0xfee00000 | u64::from(target.destination) << 12,
                data: u32::from(vector),
            }),
            RouteRequest::Line(line) => Route::Line { target, line },
        };
        let slot = NonNull::from(Box::leak(Box::new(pending.into_slot())));
        self.slots[index].store(slot.as_ptr(), Ordering::Release);
        drop(guard);
        // SAFETY: the process owner is unique; dispatch never accesses source.
        let source = unsafe { &mut *slot.as_ref().source.get() };
        let armed = source
            .mask()
            .and_then(|()| source.quiesce())
            .and_then(|()| {
                // SAFETY: qualified target, retained ARMING slot, actual mask and stop.
                unsafe { source.program(route) }
            });
        if let Err(error) = armed {
            self.quarantine(slot);
            return Err(error.into());
        }
        // SAFETY: The slot is already fully retained; a delivery during unmask sees
        // the real handler. No new submission precedes source configuration.
        unsafe { slot.as_ref() }
            .state
            .store(LIVE, Ordering::Release);
        // SAFETY: the complete owned route and LIVE callback are published.
        if let Err(error) = unsafe { source.unmask() } {
            self.quarantine(slot);
            let _ = source.mask();
            return Err(error.into());
        }
        Ok(Registration {
            registry: self,
            slot,
            vector,
            active: true,
            owner_cpu: PhantomData,
        })
    }

    fn quarantine(&self, slot: NonNull<Slot>) {
        // SAFETY: a quarantined slot is never detached or freed.
        let previous = unsafe { slot.as_ref() }
            .state
            .swap(QUARANTINED, Ordering::AcqRel);
        if previous != QUARANTINED {
            self.count_quarantine();
        }
    }

    fn count_quarantine(&self) {
        let _ = self
            .quarantined
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
    }

    /// Called by the existing IDT dispatcher with local IRQs off. Returns
    /// true for a retained route, including closing/quarantined tombstones.
    pub fn dispatch(&self, vector: u8) -> bool {
        let Some(index) = vector
            .checked_sub(FIRST_VECTOR)
            .map(usize::from)
            .filter(|index| *index < VECTOR_COUNT)
        else {
            return false;
        };
        if self.platform.check_cpu().is_err() {
            return false;
        }
        let guard = self.lock();
        let Some(slot) = NonNull::new(self.slots[index].load(Ordering::Acquire)) else {
            return false;
        };
        // SAFETY: lock protects pointer acquisition; inflight prevents release
        // until after EOI, even if removal closes the route meanwhile.
        let slot = unsafe { slot.as_ref() };
        slot.inflight.fetch_add(1, Ordering::AcqRel);
        let live = slot.state.load(Ordering::Acquire) == LIVE;
        drop(guard);
        if live && slot.handler.handle() == Disposition::Handled {
            slot.handled.fetch_add(1, Ordering::Relaxed);
        }
        self.platform.eoi();
        slot.inflight.fetch_sub(1, Ordering::Release);
        true
    }
}

struct Guard<'a, P: Platform> {
    registry: &'a Registry<P>,
    saved: u64,
}
impl<P: Platform> Drop for Guard<'_, P> {
    fn drop(&mut self) {
        self.registry.held.store(false, Ordering::Release);
        // SAFETY: same CPU, exactly this guard's saved interrupt state.
        unsafe { self.registry.platform.restore(self.saved) };
    }
}

/// Unique CPU-affine owner, deliberately neither Send nor Sync. Retains the
/// source/handler until actual mask/quiescence, dispatch and IRR/ISR drain.
/// Drop and every method require process/deferred context; never an ISR.
pub struct Registration<'a, P: Platform> {
    registry: &'a Registry<P>,
    slot: NonNull<Slot>,
    vector: u8,
    active: bool,
    owner_cpu: PhantomData<*mut ()>,
}

impl<P: Platform> Registration<'_, P> {
    pub fn vector(&self) -> u8 {
        self.vector
    }
    pub fn handled(&self) -> Result<u64, IrqError> {
        if !self.active {
            return Err(IrqError::Unregistered);
        }
        // SAFETY: this unique registration retains its slot until retirement.
        Ok(unsafe { self.slot.as_ref() }
            .handled
            .load(Ordering::Relaxed))
    }

    /// A failed stop/drain retains the complete registration for retry; no
    /// vector/context or callback-owned pages can be reused by that failure.
    pub fn retire(&mut self) -> Result<(), IrqError> {
        if !self.active {
            return Err(IrqError::Unregistered);
        }
        self.registry.platform.check_cpu()?;
        let guard = self.registry.lock();
        // SAFETY: unique retained process owner, protected against dispatch
        // pointer acquisition; handler borrow remains guarded by inflight.
        let slot = unsafe { self.slot.as_ref() };
        slot.state.store(CLOSING, Ordering::Release);
        drop(guard);
        // SAFETY: no other process owner accesses this source. ISR does not.
        let source = unsafe { &mut *slot.source.get() };
        source.mask()?;
        source.quiesce()?;
        let saved = self.registry.platform.save_and_disable();
        let start = self.registry.platform.ticks();
        let drained = loop {
            let pending = match self.registry.platform.pending(self.vector) {
                Ok(pending) => pending,
                Err(error) => break Err(error),
            };
            if !pending && slot.inflight.load(Ordering::Acquire) == 0 {
                break Ok(());
            }
            if self.registry.platform.ticks().wrapping_sub(start)
                >= self.registry.platform.timeout_ticks()
            {
                break Err(IrqError::Drain);
            }
            // SAFETY: no registry/resource lock held; source stopped and
            // tombstone retained, so pending delivery only drains/EOIs it.
            unsafe { self.registry.platform.interrupt_window() };
        };
        // SAFETY: restore exactly the immediately enclosing same-CPU state.
        unsafe { self.registry.platform.restore(saved) };
        drained?;
        // A callback that was already in flight when closing began may have
        // queued work before its final EOI. Drain/cancel that work only after
        // the callback lifetime has ended as well as before hardware draining.
        // SAFETY: actual source stop, CPU pending and in-flight callbacks have drained.
        unsafe { source.synchronize() }?;
        self.registry.platform.check_cpu()?;
        let guard = self.registry.lock();
        if slot.inflight.load(Ordering::Acquire) != 0
            || self.registry.platform.pending(self.vector)?
        {
            return Err(IrqError::Drain);
        }
        self.registry.slots[usize::from(self.vector - FIRST_VECTOR)]
            .store(core::ptr::null_mut(), Ordering::Release);
        self.active = false;
        drop(guard);
        // SAFETY: real source quiescence excludes any future delivery/work,
        // and locked final IRR/ISR/inflight checks establish no remaining user.
        unsafe { drop(Box::from_raw(self.slot.as_ptr())) };
        Ok(())
    }
}

impl<P: Platform> Drop for Registration<'_, P> {
    fn drop(&mut self) {
        if self.active && self.retire().is_err() {
            self.registry.quarantine(self.slot);
        }
    }
}

impl<P: Platform> IrqRegistration for Registration<'_, P> {
    fn vector(&self) -> u8 {
        Registration::vector(self)
    }
    fn handled(&self) -> Result<u64, IrqError> {
        Registration::handled(self)
    }
    fn retire(&mut self) -> Result<(), IrqError> {
        Registration::retire(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    struct Model {
        ticks: AtomicU64,
        pending: AtomicBool,
        fail_pending: AtomicBool,
        fail_mask: AtomicBool,
        wrong_cpu: AtomicBool,
        fail_target: AtomicBool,
        invalid_target: AtomicBool,
        migrate_on_sync: AtomicBool,
        admit_irq: AtomicBool,
        callbacks: AtomicUsize,
        eois: AtomicUsize,
        quiesces: AtomicUsize,
        source_drops: AtomicUsize,
        handler_drops: AtomicUsize,
        registry: AtomicPtr<Registry<ModelPlatform>>,
        vector: AtomicU8,
    }
    impl Model {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                ticks: AtomicU64::new(0),
                pending: AtomicBool::new(false),
                fail_pending: AtomicBool::new(false),
                fail_mask: AtomicBool::new(false),
                wrong_cpu: AtomicBool::new(false),
                fail_target: AtomicBool::new(false),
                invalid_target: AtomicBool::new(false),
                migrate_on_sync: AtomicBool::new(false),
                admit_irq: AtomicBool::new(true),
                callbacks: AtomicUsize::new(0),
                eois: AtomicUsize::new(0),
                quiesces: AtomicUsize::new(0),
                source_drops: AtomicUsize::new(0),
                handler_drops: AtomicUsize::new(0),
                registry: AtomicPtr::new(core::ptr::null_mut()),
                vector: AtomicU8::new(0),
            })
        }
    }
    struct ModelPlatform(Arc<Model>, Option<std::thread::ThreadId>);
    // SAFETY: synchronous explicit IRQ/controller model; no physical accesses.
    unsafe impl Platform for ModelPlatform {
        fn check_cpu(&self) -> Result<(), IrqError> {
            if self.0.wrong_cpu.load(Ordering::Relaxed)
                || self.1.is_some_and(|id| id != std::thread::current().id())
            {
                Err(IrqError::WrongCpu)
            } else {
                Ok(())
            }
        }
        fn save_and_disable(&self) -> u64 {
            0
        }
        unsafe fn restore(&self, saved: u64) {
            assert_eq!(saved, 0);
        }
        fn target(&self, vector: u8) -> Result<Target, IrqError> {
            if self.0.fail_target.load(Ordering::Relaxed) {
                return Err(IrqError::Route);
            }
            self.0.vector.store(vector, Ordering::Relaxed);
            Ok(Target {
                destination: if self.0.invalid_target.load(Ordering::Relaxed) {
                    255
                } else {
                    0
                },
                vector,
            })
        }
        fn pending(&self, _: u8) -> Result<bool, IrqError> {
            if self.0.fail_pending.load(Ordering::Relaxed) {
                Err(IrqError::FailedRead)
            } else {
                Ok(self.0.pending.load(Ordering::Relaxed))
            }
        }
        fn eoi(&self) {
            self.0.eois.fetch_add(1, Ordering::Relaxed);
            self.0.pending.store(false, Ordering::Relaxed);
        }
        fn ticks(&self) -> u64 {
            self.0.ticks.fetch_add(1, Ordering::Relaxed)
        }
        fn timeout_ticks(&self) -> u64 {
            8
        }
        unsafe fn interrupt_window(&self) {
            if self.0.admit_irq.load(Ordering::Relaxed) && self.0.pending.load(Ordering::Relaxed) {
                // SAFETY: the model registry is leaked/stable, and closing
                // retains its source/context for this pending delivery.
                let registry = unsafe { &*self.0.registry.load(Ordering::Relaxed) };
                assert!(registry.dispatch(self.0.vector.load(Ordering::Relaxed)));
            }
        }
    }
    struct ModelSource(Arc<Model>);
    // SAFETY: explicit stopped-source model with injected mask failures and
    // controller delivery. Quiesce represents actual device/work completion.
    unsafe impl Source for ModelSource {
        fn mask(&mut self) -> Result<(), IrqError> {
            if self.0.fail_mask.load(Ordering::Relaxed) {
                Err(IrqError::Mask)
            } else {
                Ok(())
            }
        }
        fn quiesce(&mut self) -> Result<(), IrqError> {
            self.0.quiesces.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn route(&self) -> RouteRequest {
            RouteRequest::Msi
        }
        unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
            let Route::Msi(message) = route else {
                return Err(IrqError::Route);
            };
            assert_eq!(message.address, 0xfee00000);
            assert_eq!(
                message.data,
                u32::from(self.0.vector.load(Ordering::Relaxed))
            );
            Ok(())
        }
        unsafe fn unmask(&mut self) -> Result<(), IrqError> {
            Ok(())
        }
        unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
            self.synchronized()
        }
    }
    impl ModelSource {
        fn synchronized(&mut self) -> Result<(), IrqError> {
            self.quiesce()
        }
    }
    impl Drop for ModelSource {
        fn drop(&mut self) {
            self.0.source_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct ModelHandler(Arc<Model>);
    impl Handler for ModelHandler {
        fn handle(&self) -> Disposition {
            self.0.callbacks.fetch_add(1, Ordering::Relaxed);
            Disposition::Handled
        }
    }
    impl Drop for ModelHandler {
        fn drop(&mut self) {
            self.0.handler_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn registry(model: Arc<Model>) -> &'static Registry<ModelPlatform> {
        let registry = Box::leak(Box::new(Registry::new(ModelPlatform(model.clone(), None))));
        model.registry.store(registry, Ordering::Relaxed);
        registry
    }
    fn request(
        registry: &'static Registry<ModelPlatform>,
        model: &Arc<Model>,
    ) -> Registration<'static, ModelPlatform> {
        registry
            .request(
                Box::new(ModelSource(model.clone())),
                Arc::new(ModelHandler(model.clone())),
            )
            .unwrap()
    }

    // Rc/Cell plus a real creating thread identity make this owner genuinely
    // !Send; no unsafe Send/Sync implementation or integer ownership erasure.
    struct LocalSource {
        inner: ModelSource,
        token: std::rc::Rc<core::cell::Cell<usize>>,
        owner: std::thread::ThreadId,
    }
    // SAFETY: explicit same-CPU source model; the registry is the only owner
    // and must retain it on every unqualified admission/retirement path.
    unsafe impl Source for LocalSource {
        fn mask(&mut self) -> Result<(), IrqError> {
            self.inner.mask()
        }
        fn quiesce(&mut self) -> Result<(), IrqError> {
            self.inner.quiesce()
        }
        fn route(&self) -> RouteRequest {
            self.inner.route()
        }
        unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
            unsafe { self.inner.program(route) }
        }
        unsafe fn unmask(&mut self) -> Result<(), IrqError> {
            unsafe { self.inner.unmask() }
        }
        unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
            unsafe { self.inner.synchronize() }?;
            if self.inner.0.migrate_on_sync.load(Ordering::Relaxed) {
                self.inner.0.wrong_cpu.store(true, Ordering::Relaxed);
            }
            Ok(())
        }
    }
    impl Drop for LocalSource {
        fn drop(&mut self) {
            assert_eq!(self.owner, std::thread::current().id());
            assert!(!self.inner.0.wrong_cpu.load(Ordering::Relaxed));
            assert_eq!(
                self.inner.0.handler_drops.load(Ordering::Relaxed),
                0,
                "source must release while its callback owner remains retained"
            );
            self.token.set(self.token.get() + 1);
        }
    }
    fn local_source(
        model: &Arc<Model>,
        token: std::rc::Rc<core::cell::Cell<usize>>,
    ) -> Box<dyn Source> {
        Box::new(LocalSource {
            inner: ModelSource(model.clone()),
            token,
            owner: std::thread::current().id(),
        })
    }
    #[test]
    fn genuinely_local_source_releases_before_handler_only_on_qualified_cpu() {
        let model = Model::new();
        let registry = registry(model.clone());
        let token = std::rc::Rc::new(core::cell::Cell::new(0));
        let mut registration = registry
            .request(
                local_source(&model, token.clone()),
                Arc::new(ModelHandler(model.clone())),
            )
            .unwrap();
        model.migrate_on_sync.store(true, Ordering::Relaxed);
        assert_eq!(registration.retire(), Err(IrqError::WrongCpu));
        assert_eq!(token.get(), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
        model.migrate_on_sync.store(false, Ordering::Relaxed);
        model.wrong_cpu.store(false, Ordering::Relaxed);
        registration.retire().unwrap();
        assert_eq!(token.get(), 1);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn all_early_admission_errors_retain_affine_source_and_callback_owner() {
        for case in 0..4 {
            let model = Model::new();
            let registry = registry(model.clone());
            let mut occupied = alloc::vec::Vec::new();
            if case == 3 {
                for _ in 0..VECTOR_COUNT {
                    occupied.push(request(registry, &model));
                }
            }
            model.wrong_cpu.store(case == 0, Ordering::Relaxed);
            model.fail_target.store(case == 1, Ordering::Relaxed);
            model.invalid_target.store(case == 2, Ordering::Relaxed);
            let token = std::rc::Rc::new(core::cell::Cell::new(0));
            let result = registry.request(
                local_source(&model, token.clone()),
                Arc::new(ModelHandler(model.clone())),
            );
            let Err(refusal) = result else {
                panic!("an inadmissible request registered");
            };
            assert_eq!(
                refusal.error,
                [
                    IrqError::WrongCpu,
                    IrqError::Route,
                    IrqError::Route,
                    IrqError::Exhausted
                ][case]
            );
            assert_eq!(token.get(), 0);
            assert_eq!(std::rc::Rc::strong_count(&token), 2);
            assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
            assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
            // Only a wrong-CPU refusal keeps the owners; the others return
            // them untouched for the driver to keep polling with.
            assert_eq!(refusal.returned.is_some(), case != 0);
            assert_eq!(registry.quarantine_count(), u64::from(case == 0));
            drop(refusal);
            model.wrong_cpu.store(false, Ordering::Relaxed);
            for mut registered in occupied {
                registered.retire().unwrap();
            }
        }
    }
    #[test]
    fn actual_foreign_thread_admission_and_abandoned_migration_never_drop_local_owner() {
        let model = Model::new();
        let registry = Box::leak(Box::new(Registry::new(ModelPlatform(
            model.clone(),
            Some(std::thread::current().id()),
        ))));
        let registry: &'static Registry<ModelPlatform> = registry;
        let other = model.clone();
        std::thread::spawn(move || {
            let token = std::rc::Rc::new(core::cell::Cell::new(0));
            let result = registry.request(
                local_source(&other, token.clone()),
                Arc::new(ModelHandler(other.clone())),
            );
            assert!(matches!(
                result,
                Err(RequestError {
                    error: IrqError::WrongCpu,
                    returned: None
                })
            ));
            assert_eq!(token.get(), 0);
            assert_eq!(std::rc::Rc::strong_count(&token), 2);
        })
        .join()
        .unwrap();
        assert_eq!(registry.quarantine_count(), 1);
        let token = std::rc::Rc::new(core::cell::Cell::new(0));
        let registration = registry
            .request(
                local_source(&model, token.clone()),
                Arc::new(ModelHandler(model.clone())),
            )
            .unwrap();
        model.wrong_cpu.store(true, Ordering::Relaxed);
        drop(registration);
        assert_eq!(registry.quarantine_count(), 2);
        assert_eq!(token.get(), 0);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn immutable_sharing_invokes_all_members_and_preserves_unclaimed_status() {
        struct Member(Arc<AtomicUsize>, Disposition);
        impl Handler for Member {
            fn handle(&self) -> Disposition {
                self.0.fetch_add(1, Ordering::Relaxed);
                self.1
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let a: Arc<dyn Handler> = Arc::new(Member(count.clone(), Disposition::NotMine));
        let b: Arc<dyn Handler> = Arc::new(Member(count.clone(), Disposition::Handled));
        assert!(matches!(
            SharedHandlers::new(alloc::vec![]),
            Err(IrqError::Unsupported)
        ));
        assert!(matches!(
            SharedHandlers::new(alloc::vec![a.clone(), a.clone()]),
            Err(IrqError::Unsupported)
        ));
        let group = SharedHandlers::new(alloc::vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(group.handle(), Disposition::Handled);
        assert_eq!(count.load(Ordering::Relaxed), 2);
        assert_eq!(Arc::strong_count(&a), 2);
        let model = Model::new();
        let r = registry(model.clone());
        let mut registration = r.request(Box::new(ModelSource(model.clone())), a).unwrap();
        assert!(r.dispatch(registration.vector()));
        assert_eq!(registration.handled(), Ok(0));
        assert_eq!(model.eois.load(Ordering::Relaxed), 1);
        registration.retire().unwrap();
    }

    #[test]
    fn real_registration_lifetime_drains_pending_delivery_before_final_release_and_reuse() {
        let model = Model::new();
        let registry = registry(model.clone());
        let mut registration = request(registry, &model);
        let vector = registration.vector();
        assert!(!registry.dispatch(FIRST_VECTOR - 1));
        assert!(registry.dispatch(vector));
        assert_eq!(registration.handled(), Ok(1));
        assert_eq!(model.callbacks.load(Ordering::Relaxed), 1);
        assert_eq!(model.eois.load(Ordering::Relaxed), 1);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
        model.pending.store(true, Ordering::Relaxed);
        registration.retire().unwrap();
        assert!(!registry.dispatch(vector));
        assert_eq!(
            model.callbacks.load(Ordering::Relaxed),
            1,
            "closing IRQ must not enter the detached device callback"
        );
        assert_eq!(model.eois.load(Ordering::Relaxed), 2);
        assert_eq!(
            model.quiesces.load(Ordering::Relaxed),
            3,
            "work created by a formerly in-flight callback is drained after ISR completion"
        );
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
        let mut reused = request(registry, &model);
        assert_eq!(reused.vector(), vector);
        reused.retire().unwrap();
    }

    #[test]
    fn failed_pending_read_and_timeout_retain_for_retry_without_vector_reuse() {
        let model = Model::new();
        let registry = registry(model.clone());
        let mut registration = request(registry, &model);
        model.fail_pending.store(true, Ordering::Relaxed);
        assert_eq!(registration.retire(), Err(IrqError::FailedRead));
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        model.fail_pending.store(false, Ordering::Relaxed);
        model.pending.store(true, Ordering::Relaxed);
        model.admit_irq.store(false, Ordering::Relaxed);
        assert_eq!(registration.retire(), Err(IrqError::Drain));
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
        model.admit_irq.store(true, Ordering::Relaxed);
        registration.retire().unwrap();
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn abandoned_failed_teardown_and_arming_keep_source_handler_and_tombstone() {
        let model = Model::new();
        let registry = registry(model.clone());
        let registration = request(registry, &model);
        let vector = registration.vector();
        model.fail_mask.store(true, Ordering::Relaxed);
        drop(registration);
        assert_eq!(registry.quarantine_count(), 1);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
        assert!(registry.dispatch(vector));
        assert_eq!(model.callbacks.load(Ordering::Relaxed), 0);
        assert!(matches!(
            registry.request(
                Box::new(ModelSource(model.clone())),
                Arc::new(ModelHandler(model.clone()))
            ),
            Err(RequestError {
                error: IrqError::Mask,
                returned: None
            })
        ));
        assert_eq!(registry.quarantine_count(), 2);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn callback_borrow_outlives_failed_removal_without_arc_clone_or_early_release() {
        struct BlockedHandler {
            entered: std::sync::Barrier,
            release: std::sync::Barrier,
            model: Arc<Model>,
        }
        impl Handler for BlockedHandler {
            fn handle(&self) -> Disposition {
                self.entered.wait();
                self.release.wait();
                Disposition::Handled
            }
        }
        impl Drop for BlockedHandler {
            fn drop(&mut self) {
                self.model.handler_drops.fetch_add(1, Ordering::Relaxed);
            }
        }
        let model = Model::new();
        let registry = registry(model.clone());
        let handler = Arc::new(BlockedHandler {
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
            model: model.clone(),
        });
        let mut registration = registry
            .request(Box::new(ModelSource(model.clone())), handler.clone())
            .unwrap();
        let vector = registration.vector();
        // Concurrent model interleaving stresses the reader/remove lifetime;
        // the actual native adapter remains confined to its one owning BSP.
        let irq = std::thread::spawn(move || assert!(registry.dispatch(vector)));
        handler.entered.wait();
        assert_eq!(registration.retire(), Err(IrqError::Drain));
        assert_eq!(
            Arc::strong_count(&handler),
            2,
            "dispatch must not clone the handler Arc"
        );
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 0);
        handler.release.wait();
        irq.join().unwrap();
        registration.retire().unwrap();
        assert_eq!(Arc::strong_count(&handler), 1);
        assert_eq!(model.eois.load(Ordering::Relaxed), 1);
        assert_eq!(model.source_drops.load(Ordering::Relaxed), 1);
        drop(handler);
        assert_eq!(model.handler_drops.load(Ordering::Relaxed), 1);
    }
}
