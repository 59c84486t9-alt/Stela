//! Owned native interrupt registrations. Device acknowledgement, completion
//! fences and reset algorithms belong to the device handler/source owner.
pub mod posted_msi;

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

/// Physical fixed-delivery target, checked by the owning CPU adapter.
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

/// Immutable, pre-bound sharing group. Every member remains held until
/// the entire physical source group is masked, stopped and drained. Joining
/// or removing a member requires complete group retirement and re-registration;
/// dynamic sharing is unavailable. Dispatch invokes every member
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
/// check or an uncertain arming failure they stay held.
pub struct RequestError {
    pub error: IrqError,
    pub returned: Option<(Box<dyn Source>, Arc<dyn Handler>)>,
}

/// Concrete-source refusal from request_owned. Only checked, untouched owners
/// are returned; wrong-CPU or uncertain published ownership stays quarantined.
/// The error itself stays CPU-affine, including when S happens to be Send.
pub struct OwnedRequestError<S: Source> {
    pub error: IrqError,
    pub returned: Option<UnregisteredSource<S>>,
    owner_cpu: PhantomData<*mut ()>,
}
/// Untouched original owners from a checked prepublication refusal. Default
/// Drop preserves source-before-callback release on the creating CPU. This
/// wrapper proves no registry retirement and cannot mint a RetiredRoute.
pub struct UnregisteredSource<S: Source> {
    source: Box<S>,
    handler: Arc<dyn Handler>,
    owner_cpu: PhantomData<*mut ()>,
}
impl<S: Source> UnregisteredSource<S> {
    /// Recover the exact untouched owners for device-specific fallback/retry.
    ///
    /// # Safety
    /// Stay on the original checked process CPU and keep handler until the
    /// source is consumed/released, including independent device/DMA-dependent
    /// lifetime obligations. No stop/drain or retired-route proof is supplied.
    pub unsafe fn into_parts(self) -> (Box<S>, Arc<dyn Handler>) {
        (self.source, self.handler)
    }
}
impl<S: Source> core::fmt::Debug for OwnedRequestError<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedRequestError")
            .field("error", &self.error)
            .field("returned", &self.returned.is_some())
            .finish()
    }
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
/// The platform initializes and permanently keeps the controller.
pub trait IrqController: Sync {
    fn request(
        &'static self,
        source: Box<dyn Source>,
        handler: Arc<dyn Handler>,
    ) -> Result<Box<dyn IrqRegistration>, IrqError>;
    fn quarantine_count(&self) -> u64;
}

/// Process/deferred, CPU-affine owner. This trait supplies no
/// Send/Sync promise; neither operations nor final Drop are hard-IRQ-safe.
pub trait IrqRegistration {
    fn vector(&self) -> u8;
    fn handled(&self) -> Result<u64, IrqError>;
    fn retire(&mut self) -> Result<(), IrqError>;
    /// Complete the same stop/drain sequence and return the original source.
    /// A failure keeps both owners in this registration for retry/quarantine.
    fn retire_source(&mut self) -> Result<RetiredSource<dyn Source>, IrqError>;
}

/// Physical-parent mask capability for a hard-IRQ failure.
/// This endpoint grants no route, callback, device or DMA ownership.
///
/// # Safety
/// Construct only from the owned pin and its nonwrapping claim epoch.
/// `mask` checks the original CPU/epoch, performs IRQ-safe controller
/// mask and readback, and refuses stale endpoints after retirement/reuse. It
/// allocates nothing, never waits for deferred work and never finally releases
/// an owner in the ISR. Keep the endpoint through callback completion; final
/// Drop remains process/deferred context. An error is not successful masking.
pub unsafe trait ParentMask: Send + Sync {
    fn mask(&self) -> Result<(), IrqError>;
}

/// Acknowledged retirement of one registered route. Only the canonical
/// registry constructs this non-cloneable, CPU-affine receipt after hardware,
/// callback and work drain. It proves no device DMA/domain/BM retirement.
pub struct RetiredRoute {
    vector: u8,
    owner_cpu: PhantomData<*mut ()>,
}
impl RetiredRoute {
    pub fn vector(&self) -> u8 {
        self.vector
    }
}

/// The original source and callback owner after acknowledged route retirement.
/// Source field order preserves final release while its callback context is
/// still held. This owner remains process/deferred and CPU-affine.
pub struct RetiredSource<S: Source + ?Sized> {
    source: Box<S>,
    handler: Arc<dyn Handler>,
    route: RetiredRoute,
}
impl<S: Source + ?Sized> RetiredSource<S> {
    pub fn route(&self) -> &RetiredRoute {
        &self.route
    }

    /// Extract the original source, callback and route receipt.
    ///
    /// # Safety
    /// Stay on the checked process CPU. Keep `handler` until `source` has
    /// been consumed/released, including any source-destructor dependency on
    /// callback-owned context, and until all independently required device/DMA
    /// completion for callback-owned resources is acknowledged. Config/root release still
    /// requires its stop and completion proofs; route drain alone does
    /// not grant them. A failed extraction must keep the original owners.
    pub unsafe fn into_parts(self) -> (Box<S>, Arc<dyn Handler>, RetiredRoute) {
        (self.source, self.handler, self.route)
    }
}

/// Fast hard-IRQ callback. Acknowledge owned real causes before returning, or
/// mask a deferred source under its work owner. The platform
/// emits EOI afterwards. A bounded diagnostic may leave a level
/// asserted once to observe EOI/retrigger behavior. No blocking, allocation or final heap/Arc
/// release is permitted. Defer work through the device's work owner.
pub trait Handler: Send + Sync {
    fn handle(&self) -> Disposition;
}

/// Exclusive real device/interrupt source kept by its registration.
///
/// # Safety
/// The source initially owns an inactive route, with no old firmware/driver
/// callback or unresolved alias. `mask` disables interrupt generation
/// and observes the device's acknowledgement. `quiesce` stops submissions and
/// device DMA/posted interrupt writes, cancels/drains queued workers/timers
/// and acknowledges pending causes. It excludes future device delivery/work
/// until explicit `unmask`; the registry invokes it again after callback drain
/// for work from a formerly in-flight callback. Both calls must keep every
/// callback-reachable context, BO, reservation, pin and CPU/DMA lease until
/// registration retirement finishes; quiescence alone never authorizes their
/// release or skips a hardware fence/IOTLB acknowledgement.
/// `program` installs exactly the supplied typed route while masked;
/// `unmask` enables only this route. Errors must never free hardware-reachable
/// state. These process/deferred methods and final Drop are never ISR-safe.
/// A source may be CPU-affine and !Send. Only its checked owning
/// CPU's process registration accesses or finally releases it; IRQ dispatch
/// sees the separately Send+Sync handler only.
pub unsafe trait Source {
    fn mask(&mut self) -> Result<(), IrqError>;
    fn quiesce(&mut self) -> Result<(), IrqError>;
    fn route(&self) -> RouteRequest;
    /// # Safety
    /// The route is owned by the registry on its checked CPU, matches this
    /// source's request, and its callback is published before unmask.
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError>;
    /// # Safety
    /// A live registry keeps the programmed route and every callback owner.
    unsafe fn unmask(&mut self) -> Result<(), IrqError>;
    /// Called after source quiescence, CPU IRR/ISR drain and callback EOI.
    /// Check route-controller completion (including level Remote IRR)
    /// and drain work queued by any formerly in-flight callback. An error
    /// keeps the complete registration; it never authorizes route reuse.
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
/// Routing, pending IRR/ISR reads and EOI have their controller effects.
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
    // Release the stopped source while its callback context is still held.
    source: core::cell::UnsafeCell<Box<dyn Source>>,
    handler: Arc<dyn Handler>,
    state: AtomicU8,
    inflight: AtomicUsize,
    handled: AtomicU64,
}

/// Admission owns these bytes from its first instruction. Every early error
/// keeps them observably without allocating or releasing on an unknown CPU.
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
            // The real Box/Arc allocations remain held. No source access
            // or final Drop is checked by a failed admission/CPU check.
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

    /// Publish the handler before enabling the source. Any
    /// uncertain arming failure keeps source/handler and quarantines vector,
    /// as does a wrong-CPU check. Vector exhaustion and target or route
    /// refusals give both owners back.
    pub fn request(
        &'static self,
        source: Box<dyn Source>,
        handler: Arc<dyn Handler>,
    ) -> Result<Registration<'static, P>, RequestError> {
        // Keep both owners if CPU validation fails before
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
                // SAFETY: checked target, kept ARMING slot, mask and stop.
                unsafe { source.program(route) }
            });
        if let Err(error) = armed {
            self.quarantine(slot);
            return Err(error.into());
        }
        // SAFETY: The slot is already fully kept; a delivery during unmask sees
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

    /// Preserve the concrete source type through canonical IRQ retirement.
    /// This returns the original PCI/config/root owner, never a clone.
    pub fn request_owned<S: Source + 'static>(
        &'static self,
        source: S,
        handler: Arc<dyn Handler>,
    ) -> Result<OwnedRegistration<'static, P, S>, OwnedRequestError<S>> {
        self.request(Box::new(source), handler)
            .map(|registration| OwnedRegistration {
                registration,
                source: PhantomData,
            })
            .map_err(|refusal| OwnedRequestError {
                error: refusal.error,
                returned: refusal.returned.map(|(source, handler)| {
                    // SAFETY: this same private request_owned call erased the
                    // original Box<S>; Registry never replaces its source.
                    let source = unsafe { Box::from_raw(Box::into_raw(source) as *mut S) };
                    UnregisteredSource {
                        source,
                        handler,
                        owner_cpu: PhantomData,
                    }
                }),
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
    /// true for a route, including closing/quarantined tombstones.
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

/// Unique CPU-affine owner, neither Send nor Sync. Keeps the
/// source/handler until mask/quiescence, dispatch and IRR/ISR drain.
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
        // SAFETY: this unique registration keeps its slot until retirement.
        Ok(unsafe { self.slot.as_ref() }
            .handled
            .load(Ordering::Relaxed))
    }

    /// A failed stop/drain keeps the complete registration for retry; no
    /// vector/context or callback-owned pages can be reused by that failure.
    pub fn retire(&mut self) -> Result<(), IrqError> {
        // Slot field order releases source while the callback is held.
        drop(self.detach()?);
        Ok(())
    }

    /// Return the source only after final controller and callback drain.
    pub fn retire_source(&mut self) -> Result<RetiredSource<dyn Source>, IrqError> {
        let retired = self.detach()?;
        let Slot {
            source, handler, ..
        } = *retired;
        let source = source.into_inner();
        Ok(RetiredSource {
            source,
            handler,
            route: RetiredRoute {
                vector: self.vector,
                owner_cpu: PhantomData,
            },
        })
    }

    fn detach(&mut self) -> Result<Box<Slot>, IrqError> {
        if !self.active {
            return Err(IrqError::Unregistered);
        }
        self.registry.platform.check_cpu()?;
        let guard = self.registry.lock();
        // SAFETY: unique process owner, protected against dispatch
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
            // tombstone kept, so pending delivery only drains/EOIs it.
            unsafe { self.registry.platform.interrupt_window() };
        };
        // SAFETY: restore exactly the immediately enclosing same-CPU state.
        unsafe { self.registry.platform.restore(saved) };
        drained?;
        // A callback that was already in flight when closing began may have
        // queued work before its final EOI. Drain/cancel that work only after
        // the callback lifetime has ended as well as before hardware draining.
        // SAFETY: source stop, CPU pending and in-flight callbacks have drained.
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
        Ok(unsafe { Box::from_raw(self.slot.as_ptr()) })
    }
}

/// Concrete-source registration with the same process/CPU affinity. Private
/// construction proves the type of its erased, uniquely kept source.
pub struct OwnedRegistration<'a, P: Platform, S: Source + 'static> {
    registration: Registration<'a, P>,
    source: PhantomData<S>,
}
impl<P: Platform, S: Source + 'static> OwnedRegistration<'_, P, S> {
    pub fn vector(&self) -> u8 {
        self.registration.vector()
    }
    pub fn handled(&self) -> Result<u64, IrqError> {
        self.registration.handled()
    }
    pub fn retire(&mut self) -> Result<RetiredSource<S>, IrqError> {
        let RetiredSource {
            source,
            handler,
            route,
        } = self.registration.retire_source()?;
        Ok(RetiredSource {
            // SAFETY: request_owned alone constructs this wrapper from Box<S>;
            // Registry never replaces it. Retirement uniquely returns that
            // allocation after controller/callback/work drain.
            source: unsafe { Box::from_raw(Box::into_raw(source) as *mut S) },
            handler,
            route,
        })
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
    fn retire_source(&mut self) -> Result<RetiredSource<dyn Source>, IrqError> {
        Registration::retire_source(self)
    }
}

#[cfg(test)]
mod tests;
