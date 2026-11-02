//! Original notification domains and exact CPU/callback/service action joins.
pub mod posted_msi;
use crate::bus::pci::requester::{RequesterId, preparation::DetachedRequester};
use alloc::{boxed::Box, sync::Arc};
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
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
    Config(crate::bus::pci::ConfigError),
    /// A first cause is being published. Observation only, never a new cause.
    FaultPublishing,
    /// Execution unwound or an active registration was abandoned without a join.
    Interrupted,
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
    Delivery(posted_msi::Error),
}
impl From<crate::bus::pci::ConfigError> for IrqError {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsiMessage {
    pub address: u64,
    pub data: u32,
}
impl MsiMessage {
    /// Data-format validation only. No message value grants route authority.
    /// Current remappable programming supports SHV=0 and zero subhandle data;
    /// the CPU vector remains in the checked root route, not in this data word.
    pub(crate) fn valid_pci_format(self) -> bool {
        if self.address & 3 != 0 {
            return false;
        }
        let remapped = self.address & 0xfff0_0010 == 0xfee0_0010;
        !remapped
            || (self.address <= u64::from(u32::MAX) && self.address & 8 == 0 && self.data == 0)
    }
}
/// Programming descriptor only; Registry's private reservation grants ownership.
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
pub enum RouteKind {
    Msi,
    Line,
}
pub enum RouteRequest {
    Msi(posted_msi::MsiRoute),
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

/// Private allocation identity, kept alive across vector reuse by every proof.
#[derive(Clone)]
pub struct RouteId(Arc<RouteIdentity>);
struct RouteIdentity {
    platform: &'static dyn Platform,
    target: Target,
    requester: Option<RequesterId>,
    reserved: AtomicBool,
    registry: RegistryIdentity,
}
impl RouteId {
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn target(&self) -> Target {
        self.0.target
    }
    pub(crate) fn check_process(&self) -> Result<(), IrqError> {
        self.0.platform.check_process()?;
        self.0.registry.fault.failure().map_or(Ok(()), Err)
    }
}
/// Borrowed view of an owned Registry reservation, never native entered authority.
/// Only Registry creates it after checking actual CPU/root and exclusive vector.
pub struct CpuTarget<'a> {
    id: &'a RouteId,
}
impl CpuTarget<'_> {
    /// Join the actual retained Registry allocation, never vector numbers.
    pub fn belongs_to(&self, registry: RegistryIdentity) -> bool {
        self.id.0.registry.same(registry)
    }
    pub fn descriptor(&self) -> Target {
        self.id.target()
    }
    pub fn check_current(&self) -> Result<(), IrqError> {
        self.id.check_process()?;
        if !self.id.0.reserved.load(Ordering::Acquire) {
            return Err(IrqError::Unregistered);
        }
        Ok(())
    }
    pub(crate) fn id(&self) -> &RouteId {
        self.id
    }
    pub(crate) fn matches_requester(&self, requester: &RequesterId) -> bool {
        self.id
            .0
            .requester
            .as_ref()
            .is_some_and(|own| own.same_requester(requester))
    }
}
/// Programming view tied to this exact original route. Copied numbers are data.
pub struct AllocatedRoute<'a> {
    id: Option<&'a RouteId>,
    programming: Route,
}
impl AllocatedRoute<'_> {
    /// Symbolic programming data for isolated source-effect models only.
    /// # Safety
    /// No physical endpoint or native route may be programmed by this view.
    /// It cannot mint a CpuTarget, root grant or any retirement receipt.
    #[cfg(any(test, feature = "test-support"))]
    pub unsafe fn model_programming(programming: Route) -> Self {
        Self {
            id: None,
            programming,
        }
    }
    pub fn programming(&self) -> Route {
        self.programming
    }
    pub fn belongs_to(&self, registry: RegistryIdentity) -> bool {
        self.id.is_some_and(|id| id.0.registry.same(registry))
    }
    pub fn matches_requester(&self, requester: &RequesterId) -> bool {
        self.id
            .and_then(|id| id.0.requester.as_ref())
            .is_some_and(|own| own.same_requester(requester))
    }
    /// # Safety
    /// This is the existing complete VMD source/fanout owner programming only
    /// its owned child ingress. It grants no independent child Registry route,
    /// root capability, detach or interrupt-retirement receipt.
    pub(crate) unsafe fn vmd_child(&self, message: MsiMessage) -> AllocatedRoute<'_> {
        AllocatedRoute {
            id: self.id,
            programming: Route::Msi(message),
        }
    }
}
pub struct Request<S> {
    pub source: S,
    pub handler: Arc<dyn Handler>,
    pub routing: RouteRequest,
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

/// Full untouched owners returned only after a checked prepublication refusal.
/// Default Drop retains; checked extraction permits explicit retry/cancellation.
pub struct UnregisteredSource<S: Source + ?Sized> {
    request: ManuallyDrop<Request<Box<S>>>,
    platform: &'static dyn Platform,
    owner_cpu: PhantomData<*mut ()>,
}
impl<S: Source + ?Sized> UnregisteredSource<S> {
    /// # Safety
    /// Keep handler through source release and honor its independent resource
    /// obligations. No retirement proof is supplied by this untouched request.
    #[expect(
        clippy::type_complexity,
        reason = "explicit source/handler/route transfer preserves the checked extraction contract"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "checked extraction returns the same source, handler and route owner without allocating"
    )]
    pub unsafe fn into_parts(
        mut self,
    ) -> Result<(Box<S>, Arc<dyn Handler>, RouteRequest), ExtractionFailure<Self>> {
        if let Err(error) = self.platform.check_process() {
            return Err(ExtractionFailure {
                error,
                retained: self,
            });
        }
        if let RouteRequest::Msi(msi) = &self.request.routing
            && let Err(error) = msi.check_unpublished()
        {
            return Err(ExtractionFailure {
                error: IrqError::Delivery(error),
                retained: self,
            });
        }
        // SAFETY: unique checked untouched owner, taken once; fields retain on
        // every error/default Drop and no callback runs during extraction.
        let request = unsafe { ManuallyDrop::take(&mut self.request) };
        Ok((request.source, request.handler, request.routing))
    }
}
pub struct ExtractionFailure<T> {
    pub error: IrqError,
    pub retained: T,
}
pub struct RequestError {
    pub error: IrqError,
    pub returned: Option<UnregisteredSource<dyn Source>>,
}
pub struct OwnedRequestError<S: Source> {
    pub error: IrqError,
    pub returned: Option<UnregisteredSource<S>>,
    owner_cpu: PhantomData<*mut ()>,
}
impl core::fmt::Debug for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestError")
            .field("error", &self.error)
            .field("returned", &self.returned.is_some())
            .finish()
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
impl From<IrqError> for RequestError {
    fn from(error: IrqError) -> Self {
        Self {
            error,
            returned: None,
        }
    }
}
pub trait IrqController: Sync {
    #[expect(
        clippy::result_large_err,
        reason = "return original owners inline without allocation after context or publication refusal"
    )]
    fn request(
        &'static self,
        request: Request<Box<dyn Source>>,
    ) -> Result<Box<dyn IrqRegistration>, RequestError>;
    fn quarantine_count(&self) -> u64;
}
pub trait IrqRegistration {
    fn vector(&self) -> u8;
    fn handled(&self) -> Result<u64, IrqError>;
    /// Reversible source mask, not root/action retirement.
    fn mask(&mut self) -> Result<(), IrqError>;
    fn unmask(&mut self) -> Result<(), IrqError>;
    fn retire(&mut self) -> Result<RetiredSource<dyn Source>, IrqError>;
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

/// Exact IRQ-action CPU/EOI/callback/service/thread/work join, not all-issued
/// MSI completion or engine/payload/DMA detach.
pub struct RetiredRoute {
    id: RouteId,
    msi: Option<posted_msi::MsiRoute>,
    line_domain: ManuallyDrop<Option<Arc<dyn posted_msi::NotificationDomain>>>,
    owner_cpu: PhantomData<*mut ()>,
}
impl RetiredRoute {
    pub fn vector(&self) -> u8 {
        self.id.target().vector
    }
    pub(crate) fn id(&self) -> &RouteId {
        &self.id
    }
    pub fn requester(&self) -> Option<&RequesterId> {
        self.id.0.requester.as_ref()
    }
    pub fn validate(&self) -> Result<(), IrqError> {
        self.id.check_process()?;
        if let Some(msi) = &self.msi {
            msi.validate().map_err(IrqError::Delivery)?;
        }
        if let Some(domain) = self.line_domain.as_ref() {
            domain.check().map_err(IrqError::Delivery)?;
        }
        Ok(())
    }
    pub(crate) fn validate_requester(&self, requester: &RequesterId) -> Result<(), IrqError> {
        if !self
            .requester()
            .is_some_and(|own| own.same_requester(requester))
        {
            return Err(IrqError::Route);
        }
        self.validate()
    }
    pub fn release_endpoint(
        &mut self,
        detached: &DetachedRequester,
    ) -> Result<(), posted_msi::Error> {
        self.msi
            .as_mut()
            .ok_or(posted_msi::Error::WrongRequester)?
            .release(&self.id, detached)
    }
    pub(crate) fn join_action(&mut self, requester: &RequesterId) -> Result<(), IrqError> {
        self.validate_requester(requester)?;
        self.msi
            .as_mut()
            .ok_or(IrqError::Route)?
            .join_action(requester, &self.id)
            .map_err(IrqError::Delivery)
    }

    /// Release only the original bounded no-native-pin diagnostic/model route.
    /// A native attached or unavailable route cannot use this transition and
    /// it supplies no DetachedRequester or reset-coordinator proof.
    pub fn release_unattached_fixture(&mut self) -> Result<(), IrqError> {
        self.id.check_process()?;
        #[cfg(any(test, feature = "test-support", feature = "irq-diagnostics"))]
        if let Some(msi) = &mut self.msi {
            return msi.release_fixture(&self.id).map_err(IrqError::Delivery);
        }
        Err(IrqError::Unsupported)
    }
}
impl Drop for RetiredRoute {
    fn drop(&mut self) {
        // The affine MSI provider has its own conservative checked Drop. Line
        // notification metadata likewise cannot end on a foreign CPU/epoch.
        if self.validate().is_ok() {
            // SAFETY: original checked process/domain, no active old action;
            // no controller or source hardware is released by metadata Drop.
            unsafe { ManuallyDrop::drop(&mut self.line_domain) };
        }
    }
}
/// The original source/handler/root owner after canonical route retirement.
/// Default Drop retains every field; extraction is explicit and checked.
#[must_use = "retired owners must be explicitly extracted or intentionally retained"]
pub struct RetiredSource<S: Source + ?Sized> {
    source: ManuallyDrop<Box<S>>,
    handler: ManuallyDrop<Arc<dyn Handler>>,
    route: ManuallyDrop<RetiredRoute>,
}
impl<S: Source + ?Sized> RetiredSource<S> {
    pub fn route(&self) -> &RetiredRoute {
        &self.route
    }
    /// # Safety
    /// Keep handler until source and its independent device/DMA users have
    /// retired. The route alone cannot end native config/root pins.
    #[expect(
        clippy::type_complexity,
        reason = "explicit source/handler/route transfer preserves the checked extraction contract"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "checked retirement extraction returns the same source and route graph without allocating"
    )]
    pub unsafe fn into_parts(
        mut self,
    ) -> Result<(Box<S>, Arc<dyn Handler>, RetiredRoute), ExtractionFailure<Self>> {
        if let Err(error) = self.route.validate() {
            return Err(ExtractionFailure {
                error,
                retained: self,
            });
        }
        // SAFETY: exact checked route and unique fields, each taken once. The
        // ManuallyDrop fields remain untouched on every refusal/abandonment.
        Ok(unsafe {
            (
                ManuallyDrop::take(&mut self.source),
                ManuallyDrop::take(&mut self.handler),
                ManuallyDrop::take(&mut self.route),
            )
        })
    }
}
/// An original immutable IRQ-chip EOI endpoint, never the affine Source.
/// # Safety
/// Prepared from the same real controller/pin/epoch and checked CpuTarget;
/// IRQ-safe, no allocation/blocking/foreign !Send access. Revalidate original
/// mode/route on every call, preserve mask state, and contain failures through
/// the actual parent. Slot inflight keeps it through local and chip EOI. Drop
/// cannot tear down a live pin or release native custody in a foreign context;
/// refused prepublication/unwind paths retain any unresolved physical owner.
pub unsafe trait ChipEoi: Send + Sync {
    fn after_local_eoi(&self, observed: Trigger) -> Result<(), IrqError>;
}

/// An ordinary notification is a hint, never a device completion receipt.
/// Check this action's current status/rings before reporting or freeing payload.
/// The original Source/domain must retain every physical resource reachable by
/// this handler; CPU callback ownership alone is not a device DMA exclusion.
pub trait Handler: Send + Sync {
    fn handle(&self) -> Disposition;
}
/// Exclusive device stop/program/work owner, separate from root route fencing.
///
/// # Safety
/// Own the inactive original source/config/reset epoch and complete admitted
/// route/alias set. mask observes real device acknowledgement; quiesce stops
/// this owned IRQ action's producers and accounts for its old pending causes
/// without freeing reachable state. Other endpoint DMA may remain active when
/// the actual source protocol permits it; engine/payload/unmap/detach proof is
/// separate terminal endpoint ownership. The original notification domain remains retained independently. program
/// verifies the exact allocated requester and programs only its admitted data
/// while masked; unmask cannot enable alternatives. synchronize completes real
/// controller/post-callback work after CPU drain. Failure/panic/Drop retains
/// uncertain resources; all calls/final release require original process CPU.
pub unsafe trait Source {
    fn route_kind(&self) -> RouteKind;
    fn requester(&self) -> Option<&RequesterId>;
    /// Line routes require an actual original controller/root notification
    /// domain; a missing witness is explicit unavailable admission.
    fn notification_domain(&self) -> Result<Arc<dyn posted_msi::NotificationDomain>, IrqError> {
        Err(IrqError::Unsupported)
    }
    /// Process-only immutable endpoint capture, before native publication.
    /// None is valid only where no chip-specific level EOI is needed.
    fn eoi_endpoint(
        &mut self,
        _target: &CpuTarget<'_>,
    ) -> Result<Option<Arc<dyn ChipEoi>>, IrqError> {
        Ok(None)
    }
    fn mask(&mut self) -> Result<(), IrqError>;
    fn quiesce(&mut self) -> Result<(), IrqError>;
    /// # Safety
    /// Registry retains this exact route/CPU/source/callback while masked.
    unsafe fn program(&mut self, route: &AllocatedRoute<'_>) -> Result<(), IrqError>;
    /// # Safety
    /// Exact route and LIVE callback are retained by Registry.
    unsafe fn unmask(&mut self) -> Result<(), IrqError>;
    /// # Safety
    /// This old action is CLOSING; its callback cannot begin again and CPU
    /// IRR/ISR/inflight/EOI have joined. Join every captured service/thread/work
    /// producer before releasing old reachable state. This is not fabric or DMA
    /// completion; a later ordinary notification may reach a new valid action.
    unsafe fn synchronize(&mut self) -> Result<(), IrqError>;
}
/// Existing checked CPU/controller adapter, never a second vector/root owner.
///
/// # Safety
/// Actual CPU, IRQ save/restore, pending, target and EOI effects belong to the
/// retained canonical controller. check_process additionally refuses ISR,
/// foreign root and unavailable native execution scope. compatibility_message
/// interrupt_window admits queued delivery only outside Registry/resource locks.
pub unsafe trait Platform: Send + Sync {
    fn check_cpu(&self) -> Result<(), IrqError>;
    fn check_process(&self) -> Result<(), IrqError>;
    fn save_and_disable(&self) -> u64;
    /// # Safety
    /// saved is the immediately enclosing same-CPU disable state.
    unsafe fn restore(&self, saved: u64);
    fn target(&self, vector: u8) -> Result<Target, IrqError>;
    fn pending(&self, vector: u8) -> Result<bool, IrqError>;
    /// Snapshot this vector's actual TMR BEFORE local EOI, then acknowledge it.
    fn eoi(&self, vector: u8) -> Result<Trigger, IrqError>;
    fn ticks(&self) -> u64;
    fn timeout_ticks(&self) -> u64;
    /// # Safety
    /// IRQs are disabled; no Registry/resource lock is held.
    unsafe fn interrupt_window(&self);
}
const FAULT_CLEAR: u8 = 0;
const FAULT_WRITING: u8 = 1;
const FAULT_READY: u8 = 2;
/// Immutable first-cause publication. A preempted writer never makes an IRQ
/// wait or read an unfinished payload; pending observations remain distinct.
struct FirstFault {
    phase: AtomicU8,
    cause: UnsafeCell<MaybeUninit<IrqError>>,
}
// SAFETY: exactly one successful CLEAR→WRITING CAS owns the only payload write.
// READY is release-published and never reset; acquire readers only copy this
// immutable Copy/Send/Sync error after READY. No payload access occurs pending.
unsafe impl Sync for FirstFault {}
impl FirstFault {
    const fn new() -> Self {
        Self {
            phase: AtomicU8::new(FAULT_CLEAR),
            cause: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
    /// Pending is an observation of another publication, never its cause.
    fn latch(&self, cause: IrqError) -> bool {
        if cause == IrqError::FaultPublishing
            || self
                .phase
                .compare_exchange(
                    FAULT_CLEAR,
                    FAULT_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return false;
        }
        // No callback, allocation, formatting, panic or wait is permitted
        // between the claim and publication; the payload is a plain Copy.
        // SAFETY: this successful CAS uniquely owns the only write. Readers
        // cannot touch cause until the following release-published READY.
        unsafe { (*self.cause.get()).write(cause) };
        self.phase.store(FAULT_READY, Ordering::Release);
        true
    }
    fn failure(&self) -> Option<IrqError> {
        match self.phase.load(Ordering::Acquire) {
            FAULT_CLEAR => None,
            FAULT_READY => {
                // SAFETY: READY acquired the unique completed payload write;
                // it never changes again, and IrqError is Copy.
                Some(unsafe { (*self.cause.get()).assume_init_read() })
            }
            _ => Some(IrqError::FaultPublishing),
        }
    }
}
struct Slot {
    source: core::cell::UnsafeCell<Box<dyn Source>>,
    handler: Arc<dyn Handler>,
    domain: Option<Arc<dyn posted_msi::NotificationDomain>>,
    chip: Option<Arc<dyn ChipEoi>>,
    fault: FirstFault,
    routing: core::cell::UnsafeCell<RouteRequest>,
    id: RouteId,
    programming: Option<Route>,
    state: AtomicU8,
    inflight: AtomicUsize,
    handled: AtomicU64,
}
struct Pending<'a, P: Platform> {
    registry: &'a Registry<P>,
    request: ManuallyDrop<Request<Box<dyn Source>>>,
    transferred: bool,
}
impl<P: Platform + 'static> Pending<'static, P> {
    fn returned(mut self) -> UnregisteredSource<dyn Source> {
        self.transferred = true;
        // SAFETY: unique untouched request after checked prepublication refusal.
        let request = unsafe { ManuallyDrop::take(&mut self.request) };
        UnregisteredSource {
            request: ManuallyDrop::new(request),
            platform: &self.registry.platform,
            owner_cpu: PhantomData,
        }
    }
    fn slot(
        mut self,
        id: RouteId,
        programming: Option<Route>,
        domain: Option<Arc<dyn posted_msi::NotificationDomain>>,
        chip: Option<Arc<dyn ChipEoi>>,
    ) -> Slot {
        self.transferred = true;
        // SAFETY: all original fields move once; Pending no longer retains them.
        let request = unsafe { ManuallyDrop::take(&mut self.request) };
        Slot {
            source: core::cell::UnsafeCell::new(request.source),
            handler: request.handler,
            domain,
            chip,
            fault: FirstFault::new(),
            routing: core::cell::UnsafeCell::new(request.routing),
            id,
            programming,
            state: AtomicU8::new(ARMING),
            inflight: AtomicUsize::new(0),
            handled: AtomicU64::new(0),
        }
    }
}
impl<P: Platform> Drop for Pending<'_, P> {
    fn drop(&mut self) {
        if !self.transferred {
            self.registry.count_quarantine();
        }
    }
}
struct Reservation<'a, P: Platform> {
    registry: &'a Registry<P>,
    index: usize,
    id: RouteId,
    transferred: bool,
}
impl<P: Platform> Reservation<'_, P> {
    fn release(mut self) -> Result<(), IrqError> {
        self.registry.platform.check_process()?;
        let guard = self.registry.lock();
        self.registry
            .reserved
            .fetch_and(!(1usize << self.index), Ordering::Release);
        self.id.0.reserved.store(false, Ordering::Release);
        self.transferred = true;
        drop(guard);
        Ok(())
    }
}
impl<P: Platform> Drop for Reservation<'_, P> {
    fn drop(&mut self) {
        if !self.transferred {
            self.registry.count_quarantine();
        }
    }
}
impl<P: Platform + 'static> IrqController for Registry<P> {
    fn request(
        &'static self,
        request: Request<Box<dyn Source>>,
    ) -> Result<Box<dyn IrqRegistration>, RequestError> {
        Registry::request(self, request).map(|r| Box::new(r) as Box<dyn IrqRegistration>)
    }
    fn quarantine_count(&self) -> u64 {
        Registry::quarantine_count(self)
    }
}
/// Opaque provenance of the actual permanently retained Registry allocation.
/// This is metadata only, never a CPU reservation or a native root grant. The
/// private non-zero-sized lock address cannot alias a replacement: issuing this
/// token requires a static Registry that is never reclaimed or reconstructed.
#[derive(Clone, Copy)]
pub struct RegistryIdentity {
    held: &'static AtomicBool,
    fault: &'static FirstFault,
}
impl RegistryIdentity {
    pub fn same(self, other: Self) -> bool {
        core::ptr::eq(self.held, other.held)
    }
}
/// The one permanently retained CPU-vector/dispatch inventory.
pub struct Registry<P: Platform> {
    platform: P,
    slots: [AtomicPtr<Slot>; VECTOR_COUNT],
    reserved: AtomicUsize,
    held: AtomicBool,
    quarantined: AtomicU64,
    controller_fault: FirstFault,
}
impl<P: Platform> Registry<P> {
    pub const fn new(platform: P) -> Self {
        Self {
            platform,
            slots: [const { AtomicPtr::new(core::ptr::null_mut()) }; VECTOR_COUNT],
            reserved: AtomicUsize::new(0),
            held: AtomicBool::new(false),
            quarantined: AtomicU64::new(0),
            controller_fault: FirstFault::new(),
        }
    }
    pub fn identity(&'static self) -> RegistryIdentity {
        RegistryIdentity {
            held: &self.held,
            fault: &self.controller_fault,
        }
    }
    /// Latched original controller acknowledgement failure. A true dispatch
    /// return means vector ownership only; it never certifies successful EOI.
    pub fn controller_failure(&self) -> Option<IrqError> {
        self.controller_fault.failure()
    }
    fn check_controller(&self) -> Result<(), IrqError> {
        self.controller_failure().map_or(Ok(()), Err)
    }
    pub fn quarantine_count(&self) -> u64 {
        self.quarantined.load(Ordering::Relaxed)
    }
    fn count_quarantine(&self) {
        let _ = self
            .quarantined
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });
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
    fn quarantine(&self, slot: NonNull<Slot>, cause: IrqError) {
        // SAFETY: every exposed slot is retained until its checked final join;
        // quarantine never releases its allocation, even on a foreign CPU.
        let cause = if cause == IrqError::Interrupted {
            // Drop diagnostics cannot replace an actual or unfinished original
            // controller cause. Pending is still never stored as a new cause.
            self.controller_failure().unwrap_or(cause)
        } else {
            cause
        };
        // SAFETY: the same retained original allocation as above.
        unsafe { slot.as_ref() }.fault.latch(cause);
        // SAFETY: every exposed slot is permanently kept until successful
        // detach; quarantine only touches its CPU-independent atomic state.
        if unsafe { slot.as_ref() }
            .state
            .swap(QUARANTINED, Ordering::AcqRel)
            != QUARANTINED
        {
            self.count_quarantine();
        }
    }
    fn slot_failure(&self, slot: &Slot) -> IrqError {
        // A controller's pending observation is never relatched locally.
        // Its actual retained cell supplies the original cause after READY.
        let local = slot.fault.failure();
        match local {
            Some(error) if error != IrqError::Interrupted => error,
            // A Drop diagnostic is not a replacement for an eventual physical
            // controller cause, including its still-unfinished publication.
            _ => self
                .controller_failure()
                .or(local)
                .unwrap_or(IrqError::Interrupted),
        }
    }
    pub fn dispatch(&self, vector: u8) -> bool {
        let Some(index) = vector
            .checked_sub(FIRST_VECTOR)
            .map(usize::from)
            .filter(|i| *i < VECTOR_COUNT)
        else {
            return false;
        };
        if self.platform.check_cpu().is_err() {
            return false;
        }
        let guard = self.lock();
        let slot = NonNull::new(self.slots[index].load(Ordering::Acquire));
        let pointer = slot;
        // SAFETY: lock protects acquisition; inflight includes handler + all EOI.
        let slot = slot.map(|slot| unsafe { slot.as_ref() });
        if let Some(slot) = slot {
            slot.inflight.fetch_add(1, Ordering::AcqRel);
        }
        let mut unwind = DispatchUnwind {
            registry: self,
            slot: pointer,
            completed: false,
        };
        let controller_error = self.controller_failure();
        let state = slot.map(|slot| slot.state.load(Ordering::Acquire));
        let slot_error = slot.and_then(|slot| slot.fault.failure());
        let live = controller_error.is_none() && slot_error.is_none() && state == Some(LIVE);
        drop(guard);
        let mut error = controller_error.or(slot_error);
        if let Some(slot) = slot
            && live
        {
            let valid = slot
                .domain
                .as_ref()
                .ok_or(posted_msi::Error::RootUnavailable)
                .and_then(|domain| domain.check());
            match valid {
                Ok(()) => {
                    if slot.handler.handle() == Disposition::Handled {
                        slot.handled.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(cause) => error = Some(IrqError::Delivery(cause)),
            }
        }
        // The entire reserved range belongs to this original controller.
        // An ordinary late/unbound notification still needs local EOI.
        match self.platform.eoi(vector) {
            Ok(observed) => {
                // An old ordinary edge packet may reach the reserved vector
                // before the masked Source is programmed. No new owned level
                // source is enabled in ARMING, so only local EOI is needed;
                // the captured chip endpoint is not a programmed pin yet.
                if let Some(slot) = slot.filter(|_| state != Some(ARMING))
                    && let Some(chip) = &slot.chip
                    && let Err(cause) = chip.after_local_eoi(observed)
                {
                    error.get_or_insert(cause);
                }
            }
            Err(cause) => {
                // No Slot may exist for a delayed notification. Preserve the
                // actual controller failure canonically before allowing any
                // replacement admission or callback, rather than losing it.
                self.controller_fault.latch(cause);
                error.get_or_insert(cause);
            }
        }
        if let Some(slot) = slot {
            if let Some(error) = error {
                slot.fault.latch(error);
                if slot.state.swap(QUARANTINED, Ordering::AcqRel) != QUARANTINED {
                    self.count_quarantine();
                }
            }
            slot.inflight.fetch_sub(1, Ordering::Release);
        }
        unwind.completed = true;
        true
    }
}
impl<P: Platform + 'static> Registry<P> {
    fn reserve(
        &'static self,
        requester: Option<RequesterId>,
    ) -> Result<Reservation<'static, P>, IrqError> {
        self.platform.check_process()?;
        let guard = self.lock();
        let used = self.reserved.load(Ordering::Relaxed);
        let index = (0..VECTOR_COUNT)
            .find(|i| used & (1usize << i) == 0)
            .ok_or(IrqError::Exhausted)?;
        let vector = FIRST_VECTOR + index as u8;
        let target = self.platform.target(vector)?;
        if target.vector != vector || target.destination == 255 {
            return Err(IrqError::Route);
        }
        self.reserved.fetch_or(1usize << index, Ordering::Release);
        drop(guard);
        // Heap allocation is outside IF-disabled Registry exclusion.
        let id = RouteId(Arc::new(RouteIdentity {
            platform: &self.platform,
            target,
            requester,
            reserved: AtomicBool::new(true),
            registry: self.identity(),
        }));
        Ok(Reservation {
            registry: self,
            index,
            id,
            transferred: false,
        })
    }
    #[expect(
        clippy::result_large_err,
        reason = "return original owners inline without allocation after context or publication refusal"
    )]
    pub fn request(
        &'static self,
        request: Request<Box<dyn Source>>,
    ) -> Result<Registration<'static, P>, RequestError> {
        let mut pending = Pending {
            registry: self,
            request: ManuallyDrop::new(request),
            transferred: false,
        };
        self.platform.check_process()?;
        if let Err(error) = self.check_controller() {
            return Err(RequestError {
                error,
                returned: Some(pending.returned()),
            });
        }
        let kind = pending.request.source.route_kind();
        if !matches!(
            (&pending.request.routing, kind),
            (RouteRequest::Msi(_), RouteKind::Msi) | (RouteRequest::Line(_), RouteKind::Line)
        ) {
            return Err(RequestError {
                error: IrqError::Route,
                returned: Some(pending.returned()),
            });
        }
        let requester = pending.request.source.requester().cloned();
        if let RouteRequest::Msi(route) = &pending.request.routing {
            let matches = match (route.requester(), requester.as_ref()) {
                (None, None) => true,
                (Some(a), Some(b)) => a.same_requester(b),
                _ => false,
            };
            if !matches {
                return Err(RequestError {
                    error: IrqError::Route,
                    returned: Some(pending.returned()),
                });
            }
        }
        let mut reservation = match self.reserve(requester) {
            Ok(value) => value,
            Err(error) => {
                let returned = if self.platform.check_process().is_ok() {
                    Some(pending.returned())
                } else {
                    None
                };
                return Err(RequestError { error, returned });
            }
        };
        let target = CpuTarget {
            id: &reservation.id,
        };
        let chip = match pending.request.source.eoi_endpoint(&target) {
            Ok(chip) => chip,
            Err(error) => {
                reservation.release()?;
                return Err(RequestError {
                    error,
                    returned: Some(pending.returned()),
                });
            }
        };
        if matches!(
            &pending.request.routing,
            RouteRequest::Line(LineRoute {
                trigger: Trigger::Level,
                ..
            })
        ) && chip.is_none()
        {
            reservation.release()?;
            return Err(RequestError {
                error: IrqError::Unsupported,
                returned: Some(pending.returned()),
            });
        }
        let line_domain = if matches!(&pending.request.routing, RouteRequest::Line(_)) {
            match pending.request.source.notification_domain() {
                Ok(domain) => {
                    if let Err(error) = domain.check() {
                        reservation.release()?;
                        return Err(RequestError {
                            error: IrqError::Delivery(error),
                            returned: Some(pending.returned()),
                        });
                    }
                    Some(domain)
                }
                Err(error) => {
                    reservation.release()?;
                    return Err(RequestError {
                        error,
                        returned: Some(pending.returned()),
                    });
                }
            }
        } else {
            None
        };
        let allocated = match &mut pending.request.routing {
            RouteRequest::Msi(route) => route.allocation(&target).map(Route::Msi),
            RouteRequest::Line(line) => Ok(Route::Line {
                target: target.descriptor(),
                line: *line,
            }),
        };
        let programming = match allocated {
            Ok(data) => Some(data),
            Err(error) if error.untouched() && self.platform.check_process().is_ok() => {
                reservation.release()?;
                return Err(RequestError {
                    error: IrqError::Delivery(error.error()),
                    returned: Some(pending.returned()),
                });
            }
            Err(error) => {
                let slot = NonNull::from(Box::leak(Box::new(pending.slot(
                    reservation.id.clone(),
                    None,
                    None,
                    chip,
                ))));
                self.slots[reservation.index].store(slot.as_ptr(), Ordering::Release);
                reservation.transferred = true;
                self.quarantine(slot, IrqError::Delivery(error.error()));
                return Err(IrqError::Delivery(error.error()).into());
            }
        };
        let domain = match &pending.request.routing {
            RouteRequest::Msi(route) => match route.domain() {
                Ok(domain) => Some(domain),
                Err(error) => {
                    let slot = NonNull::from(Box::leak(Box::new(pending.slot(
                        reservation.id.clone(),
                        programming,
                        None,
                        chip,
                    ))));
                    self.slots[reservation.index].store(slot.as_ptr(), Ordering::Release);
                    reservation.transferred = true;
                    self.quarantine(slot, IrqError::Delivery(error));
                    return Err(IrqError::Delivery(error).into());
                }
            },
            RouteRequest::Line(_) => line_domain,
        };
        let slot = NonNull::from(Box::leak(Box::new(pending.slot(
            reservation.id.clone(),
            programming,
            domain,
            chip,
        ))));
        self.slots[reservation.index].store(slot.as_ptr(), Ordering::Release);
        reservation.transferred = true;
        let vector = reservation.id.target().vector;
        // SAFETY: this process owner alone accesses affine source and route;
        // dispatch sees only separately retained immutable handler/atomics.
        let stored = unsafe { slot.as_ref() };
        // After publication Drop performs only atomic quarantine, including
        // an unwinding source callback; no hardware retry runs during Drop.
        let registration = Registration {
            registry: self,
            slot,
            vector,
            active: true,
            owner_cpu: PhantomData,
        };
        // SAFETY: unique checked process owner as above.
        let source = unsafe { &mut *stored.source.get() };
        let armed = self
            .check_controller()
            .and_then(|()| source.mask())
            .and_then(|()| source.quiesce())
            .and_then(|()| {
                self.platform.check_process()?;
                self.check_controller()?;
                stored
                    .domain
                    .as_ref()
                    .ok_or(IrqError::Delivery(posted_msi::Error::RootUnavailable))?
                    .check()
                    .map_err(IrqError::Delivery)?;
                // SAFETY: exclusive same-process route ownership, never ISR access.
                if let RouteRequest::Msi(route) = unsafe { &mut *stored.routing.get() } {
                    route.programming().map_err(IrqError::Delivery)?;
                }
                let route = AllocatedRoute {
                    id: Some(&stored.id),
                    programming: stored.programming.ok_or(IrqError::Route)?,
                };
                // SAFETY: exact target/root/source, kept ARMING handler and real mask/stop.
                unsafe { source.program(&route) }?;
                self.platform.check_process()?;
                self.check_controller()?;
                stored
                    .domain
                    .as_ref()
                    .ok_or(IrqError::Delivery(posted_msi::Error::RootUnavailable))?
                    .check()
                    .map_err(IrqError::Delivery)
            });
        if let Err(error) = armed {
            self.quarantine(slot, error);
            return Err(error.into());
        }
        if stored.fault.failure().is_some()
            || stored
                .state
                .compare_exchange(ARMING, LIVE, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(self.slot_failure(stored).into());
        }
        // SAFETY: published LIVE callback and exact original route stay retained.
        if let Err(error) = unsafe { source.unmask() } {
            self.quarantine(slot, error);
            // No further source effect follows a failed post-LIVE operation.
            // Quarantine retains the uncertain enabled/masked state and owners.
            return Err(error.into());
        }
        if let Err(error) = self.check_controller() {
            self.quarantine(slot, error);
            return Err(error.into());
        }
        if stored.state.load(Ordering::Acquire) != LIVE {
            return Err(self.slot_failure(stored).into());
        }
        Ok(registration)
    }
    #[expect(
        clippy::result_large_err,
        reason = "return original owners inline without allocation after context or publication refusal"
    )]
    pub fn request_owned<S: Source + 'static>(
        &'static self,
        request: Request<S>,
    ) -> Result<OwnedRegistration<'static, P, S>, OwnedRequestError<S>> {
        let Request {
            source,
            handler,
            routing,
        } = request;
        self.request(Request {
            source: Box::new(source),
            handler,
            routing,
        })
        .map(|registration| OwnedRegistration {
            registration,
            source: PhantomData,
        })
        .map_err(|refusal| OwnedRequestError {
            error: refusal.error,
            owner_cpu: PhantomData,
            returned: refusal.returned.map(|mut untouched| {
                // SAFETY: only this request erased Box<S>; no source can be
                // replaced before clean prepublication return. No callback.
                let erased = unsafe { ManuallyDrop::take(&mut untouched.request) };
                UnregisteredSource {
                    request: ManuallyDrop::new(Request {
                        // SAFETY: unique original allocation/type, as above.
                        source: unsafe { Box::from_raw(Box::into_raw(erased.source) as *mut S) },
                        handler: erased.handler,
                        routing: erased.routing,
                    }),
                    platform: untouched.platform,
                    owner_cpu: PhantomData,
                }
            }),
        })
    }
}
struct Guard<'a, P: Platform> {
    registry: &'a Registry<P>,
    saved: u64,
}
impl<P: Platform> Drop for Guard<'_, P> {
    fn drop(&mut self) {
        self.registry.held.store(false, Ordering::Release);
        // SAFETY: exact immediately enclosing same-CPU interrupt state.
        unsafe { self.registry.platform.restore(self.saved) };
    }
}
/// Restores the immediately enclosing original CPU state even if a pending,
/// clock, or delivery-window callback unwinds. It owns no device/root lock.
struct SavedInterrupts<'a, P: Platform> {
    platform: &'a P,
    saved: u64,
}
impl<'a, P: Platform> SavedInterrupts<'a, P> {
    fn new(platform: &'a P) -> Self {
        Self {
            platform,
            saved: platform.save_and_disable(),
        }
    }
}
impl<P: Platform> Drop for SavedInterrupts<'_, P> {
    fn drop(&mut self) {
        // SAFETY: Platform's exact same-CPU window contract forbids migration;
        // this guard uniquely owns this immediately enclosing saved IRQ state.
        unsafe { self.platform.restore(self.saved) };
    }
}
/// Callback/EOI unwind cannot leave an apparently LIVE action or admit a
/// replacement after an unacknowledged interrupt. Drop is atomic-only and
/// retains the inflight claim; it does not invent CPU/EOI completion.
struct DispatchUnwind<'a, P: Platform> {
    registry: &'a Registry<P>,
    slot: Option<NonNull<Slot>>,
    completed: bool,
}
impl<P: Platform> Drop for DispatchUnwind<'_, P> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.registry.controller_fault.latch(IrqError::Interrupted);
        if let Some(slot) = self.slot {
            self.registry.quarantine(slot, IrqError::Interrupted);
        }
    }
}
struct RetirementUnwind<'a, P: Platform> {
    registry: &'a Registry<P>,
    slot: NonNull<Slot>,
    completed: bool,
}
impl<P: Platform> Drop for RetirementUnwind<'_, P> {
    fn drop(&mut self) {
        if !self.completed {
            self.registry.quarantine(self.slot, IrqError::Interrupted);
        }
    }
}
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
        // SAFETY: this unique registration retains its exact slot.
        Ok(unsafe { self.slot.as_ref() }
            .handled
            .load(Ordering::Relaxed))
    }
    pub fn mask(&mut self) -> Result<(), IrqError> {
        self.registry.platform.check_process()?;
        self.registry.check_controller()?;
        if !self.active {
            return Err(IrqError::Unregistered);
        }
        // SAFETY: this registration keeps its exact live source allocation.
        let slot = unsafe { self.slot.as_ref() };
        if let Some(error) = slot.fault.failure() {
            return Err(error);
        }
        if slot.state.load(Ordering::Acquire) != LIVE {
            return Err(IrqError::Drain);
        }
        // SAFETY: only this original process owner touches the affine source.
        let result = unsafe { &mut *slot.source.get() }.mask();
        if let Err(error @ IrqError::Config(_)) = result {
            self.registry.quarantine(self.slot, error);
        }
        result
    }
    pub fn unmask(&mut self) -> Result<(), IrqError> {
        self.registry.platform.check_process()?;
        self.registry.check_controller()?;
        if !self.active {
            return Err(IrqError::Unregistered);
        }
        // SAFETY: same retained live registration; no ISR touches source/route.
        let slot = unsafe { self.slot.as_ref() };
        if let Some(error) = slot.fault.failure() {
            return Err(error);
        }
        if slot.state.load(Ordering::Acquire) != LIVE {
            return Err(IrqError::Drain);
        }
        // SAFETY: same unique original process owner as above.
        if let RouteRequest::Msi(route) = unsafe { &*slot.routing.get() } {
            route.check_rearm().map_err(IrqError::Delivery)?;
        }
        slot.domain
            .as_ref()
            .ok_or(IrqError::Delivery(posted_msi::Error::RootUnavailable))?
            .check()
            .map_err(IrqError::Delivery)?;
        // SAFETY: the same exact LIVE callback and checked root route remain.
        let result = unsafe { (&mut *slot.source.get()).unmask() };
        if let Err(error @ IrqError::Config(_)) = result {
            self.registry.quarantine(self.slot, error);
        }
        result
    }
    pub fn retire(&mut self) -> Result<RetiredSource<dyn Source>, IrqError> {
        if !self.active {
            return Err(IrqError::Unregistered);
        }
        // SAFETY: this active registration retains its exact live Slot;
        // atomic-only inspection is valid even if original context is refused.
        let slot = unsafe { self.slot.as_ref() };
        if slot.state.load(Ordering::Acquire) == QUARANTINED {
            return Err(self.registry.slot_failure(slot));
        }
        let mut poison = RetirementUnwind {
            registry: self.registry,
            slot: self.slot,
            completed: false,
        };
        let result = (|| {
            self.registry.platform.check_process()?;
            self.registry.check_controller()?;
            let guard = self.registry.lock();
            // SAFETY: registration keeps the slot, while lock excludes acquisition.
            let slot = unsafe { self.slot.as_ref() };
            slot.state.store(CLOSING, Ordering::Release);
            drop(guard);
            // SAFETY: only this unique checked process owner touches source/route.
            let source = unsafe { &mut *slot.source.get() };
            source.mask()?;
            source.quiesce()?;
            // Notification-domain validation is not fabric completion. The
            // source action is closed; old ordinary packets may notify a valid
            // current handler after exact CPU/service/thread/work retirement.
            if let Some(domain) = &slot.domain {
                domain.check().map_err(IrqError::Delivery)?;
            } else {
                return Err(IrqError::Delivery(posted_msi::Error::RootUnavailable));
            }
            let saved = SavedInterrupts::new(&self.registry.platform);
            let start = self.registry.platform.ticks();
            let drained = loop {
                let pending = match self.registry.platform.pending(self.vector) {
                    Ok(p) => p,
                    Err(e) => break Err(e),
                };
                if !pending && slot.inflight.load(Ordering::Acquire) == 0 {
                    break Ok(());
                }
                if self.registry.platform.ticks().wrapping_sub(start)
                    >= self.registry.platform.timeout_ticks()
                {
                    break Err(IrqError::Drain);
                }
                // SAFETY: no Registry/resource lock; retained CLOSING slot
                // acknowledges pending delivery/EOI without entering old callbacks.
                unsafe { self.registry.platform.interrupt_window() };
            };
            drop(saved);
            drained?;
            // SAFETY: CLOSING excludes old callbacks after CPU/EOI drain. Keep
            // all source memory through actual captured work/controller joins.
            unsafe { source.synchronize() }?;
            self.registry.platform.check_process()?;
            self.registry.check_controller()?;
            slot.domain
                .as_ref()
                .ok_or(IrqError::Delivery(posted_msi::Error::RootUnavailable))?
                .check()
                .map_err(IrqError::Delivery)?;
            // SAFETY: same exclusive process route access after work synchronization.
            if let RouteRequest::Msi(route) = unsafe { &mut *slot.routing.get() } {
                route.cpu_retired().map_err(IrqError::Delivery)?;
            }
            let guard = self.registry.lock();
            self.registry.check_controller()?;
            if slot.state.load(Ordering::Acquire) != CLOSING {
                return Err(self.registry.slot_failure(slot));
            }
            if slot.inflight.load(Ordering::Acquire) != 0
                || self.registry.platform.pending(self.vector)?
            {
                return Err(IrqError::Drain);
            }
            let index = usize::from(self.vector - FIRST_VECTOR);
            self.registry.slots[index].store(core::ptr::null_mut(), Ordering::Release);
            self.registry
                .reserved
                .fetch_and(!(1usize << index), Ordering::Release);
            slot.id.0.reserved.store(false, Ordering::Release);
            self.active = false;
            drop(guard);
            poison.completed = true;
            // SAFETY: source/CPU/work and locked final check excluded old action users;
            // this unique owner reclaims the original slot allocation exactly once.
            let retired_slot = unsafe { Box::from_raw(self.slot.as_ptr()) };
            let Slot {
                source,
                handler,
                routing,
                id,
                domain,
                ..
            } = *retired_slot;
            let (msi, line_domain) = match routing.into_inner() {
                RouteRequest::Msi(msi) => (Some(msi), None),
                RouteRequest::Line(_) => (None, domain),
            };
            Ok(RetiredSource {
                source: ManuallyDrop::new(source.into_inner()),
                handler: ManuallyDrop::new(handler),
                route: ManuallyDrop::new(RetiredRoute {
                    id,
                    msi,
                    line_domain: ManuallyDrop::new(line_domain),
                    owner_cpu: PhantomData,
                }),
            })
        })();
        if let Err(error @ IrqError::Config(_)) = &result
            && self.active
        {
            // SAFETY: an unsuccessful retirement retains this exact slot.
            let slot = unsafe { self.slot.as_ref() };
            if slot.state.load(Ordering::Acquire) != LIVE {
                // Once close began, the full config effect is sticky; no retry
                // may repeat uncertain hardware work. Pure CPU-drain retries
                // keep their existing independent timeout/read semantics.
                self.registry.quarantine(self.slot, *error);
            }
        }
        poison.completed = true;
        result
    }
}
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
        let mut erased = self.registration.retire()?;
        // SAFETY: request_owned alone erased this unique Box<S>; Registry never
        // replaces it. Move all retained fields, without foreign callbacks.
        let (source, handler, route) = unsafe {
            (
                ManuallyDrop::take(&mut erased.source),
                ManuallyDrop::take(&mut erased.handler),
                ManuallyDrop::take(&mut erased.route),
            )
        };
        Ok(RetiredSource {
            // SAFETY: exact allocation/type established by request_owned.
            source: ManuallyDrop::new(unsafe { Box::from_raw(Box::into_raw(source) as *mut S) }),
            handler: ManuallyDrop::new(handler),
            route: ManuallyDrop::new(route),
        })
    }
}
impl<P: Platform> Drop for Registration<'_, P> {
    fn drop(&mut self) {
        if self.active {
            self.registry.quarantine(self.slot, IrqError::Interrupted);
        }
    }
}
impl<P: Platform> IrqRegistration for Registration<'_, P> {
    fn vector(&self) -> u8 {
        self.vector()
    }
    fn handled(&self) -> Result<u64, IrqError> {
        self.handled()
    }
    fn mask(&mut self) -> Result<(), IrqError> {
        self.mask()
    }
    fn unmask(&mut self) -> Result<(), IrqError> {
        self.unmask()
    }
    fn retire(&mut self) -> Result<RetiredSource<dyn Source>, IrqError> {
        self.retire()
    }
}
#[cfg(test)]
mod tests;
