//! Context-backed native memory execution, with one physical writer domain.
//!
//! Families submit reached elements and retain their own register staging. This
//! owner resolves each actually reached atomic part, checks tags and publishes
//! writes through the shared reservation domain. It does not interpret opcodes.

#[path = "domain/scalar.rs"]
mod scalar;
pub use scalar::{MemoryFault, MemoryReader};

#[path = "domain/publication.rs"]
mod publication;
pub use publication::PublicationFault;
#[path = "domain/profile.rs"]
mod profile;
#[path = "domain/tag_transfer.rs"]
mod tag_transfer;
pub use profile::{CheckedMemoryEntry, MemoryProfile};
#[path = "domain/lifecycle.rs"]
mod lifecycle;
pub(in crate::memory) use lifecycle::MemoryServiceLoan;
use lifecycle::{DomainSnapshot, DomainState};
pub use lifecycle::{MemoryExecutionLoan, MemoryObservationLoan};

#[path = "domain/exclusive.rs"]
mod exclusive;
#[path = "domain/m0_read.rs"]
pub(crate) mod m0_read;
pub(crate) mod m0_write;
#[path = "domain/physical.rs"]
pub(crate) mod physical;

use crate::system::events::{EventEndpoint, EventProducer};
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

use stela_compiler::{
    TargetCpu,
    context::memory::{
        MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView,
        MemoryImplementationProfile, MemoryOperationClass, MemoryRequest, MemoryRequirements,
        MemoryStatus, SpAlignmentRequirement, flags, profile_requirements,
    },
};

use super::{
    access,
    backing::{AccessKind, MappingId, MemoryBacking, MemoryView, ResolvedAccess},
    monitor,
};

const SCA_BYTES: usize = 16;
const HALF_SCA_BYTES: usize = SCA_BYTES / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingAttributes {
    pub tagged: bool,
    pub shareable: bool,
}

/// Effective CPU controls belong to the per-thread policy, not each ISA family.
/// Policy callbacks must not reenter or retire this domain while an access is active.
pub trait DataPolicy {
    /// Typed service classes require actual CPU-owner admission.
    fn validate_operation_execution(
        &self,
        _class: MemoryOperationClass,
    ) -> Result<(), MemoryStatus> {
        Err(MemoryStatus::Unsupported)
    }
    /// Reject unavailable effective-control profiles before any guest effect.
    fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus>;
    /// Check the body's original-SP specialization against authoritative
    /// effective controls. An arbitrary policy cannot silently prove a control.
    fn validate_sp_alignment(&self, required: SpAlignmentRequirement) -> Result<(), MemoryStatus> {
        if required == SpAlignmentRequirement::Any {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    /// Validate emitted CPA address specialization against the actual CPU owner.
    /// Arbitrary policies cannot silently adopt a specialized native body.
    fn validate_address_checks(
        &self,
        required: stela_compiler::context::memory::address::AddressCheckRequirements,
    ) -> Result<(), MemoryStatus> {
        if required.is_empty() {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    /// CPA arithmetic requires actual same-CPU feature/mode qualification even
    /// when a discarded result emits no visible register or memory effect.
    fn validate_pointer_arithmetic(
        &self,
        required: Option<stela_compiler::context::pointer::PointerArithmeticRequirement>,
    ) -> Result<(), MemoryStatus> {
        if required.is_none() {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    /// Check the source-bound implementation identity selected by the body.
    /// An unproven CPU implementation must decline rather than assume a choice.
    fn validate_implementation_profile(
        &self,
        _required: MemoryImplementationProfile,
    ) -> Result<(), MemoryStatus> {
        Err(MemoryStatus::Unsupported)
    }
    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus>;
    fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus>;
}

/// Effective dedicated allocation-tag access policy for the current privilege.
/// The result includes effective allocation-tag enable and mapping attributes.
/// False still requires the dedicated instruction's translation/rights checks.
pub trait AllocationTagPolicy: DataPolicy {
    fn validate_privilege(&self, privileged: bool) -> Result<(), MemoryStatus>;
    fn allocation_tag_access(
        &self,
        attributes: MappingAttributes,
        privileged: bool,
    ) -> Result<bool, MemoryStatus>;
}

pub struct DataAccess<'a> {
    pub raw_address: u64,
    pub translated_address: u64,
    pub backing: &'a MemoryBacking,
    pub backing_offset: usize,
    pub bytes: usize,
    pub attributes: MappingAttributes,
    pub flags: u32,
}

type ReservationDomain = monitor::MonitorDomain<MemoryBacking, MemoryView, MappingAttributes>;
type ReservationThread = monitor::ThreadMonitor<MemoryBacking, MemoryView, MappingAttributes>;
type ReservationMapping = monitor::Mapping<MemoryView, MappingAttributes>;
type MappingRegistry = HashMap<MappingId, Weak<ReservationMapping>>;

#[derive(Clone)]
pub(super) struct RegisteredView {
    pub(super) view: Arc<MemoryView>,
    pub(super) monitor: Arc<ReservationMapping>,
}

/// One guest machine's physical coherence and reservation owner. Shared backing
/// across address spaces must bind to this same owner; COW creates new backing.
pub struct MemorySystem {
    identity: Arc<()>,
    reservations: Arc<ReservationDomain>,
    mappings: Mutex<MappingRegistry>,
    failed: AtomicBool,
    // Serialize qualified DeviceRAM transactions in this same machine. This
    // gate alone grants no source attributes, physical interpretation or PE.
    device_ram_order: Mutex<()>,
}

impl MemorySystem {
    pub fn new(erg_bytes: u64, stripe_count: usize) -> Result<Arc<Self>, MemoryStatus> {
        let reservations = monitor::MonitorDomain::new(erg_bytes, stripe_count)
            .map_err(|_| MemoryStatus::InvalidRequest)?;
        Ok(Arc::new(Self {
            identity: Arc::new(()),
            reservations,
            mappings: Mutex::new(HashMap::new()),
            failed: AtomicBool::new(false),
            device_ram_order: Mutex::new(()),
        }))
    }

    fn register_view(
        &self,
        view: &Arc<MemoryView>,
        attributes: MappingAttributes,
    ) -> Result<Arc<ReservationMapping>, MemoryStatus> {
        view.backing()
            .bind_coherence(&self.identity)
            .map_err(|_| MemoryStatus::Domain)?;
        let mut mappings = self.mappings.lock().map_err(|_| MemoryStatus::Domain)?;
        // Keep registry work/space bounded by live generations, not map history.
        mappings.retain(|_, mapping| mapping.strong_count() != 0);
        if let Some(mapping) = mappings.get(&view.id()).and_then(Weak::upgrade) {
            if *mapping.attributes() != attributes {
                return Err(MemoryStatus::InvalidRequest);
            }
            return Ok(mapping);
        }
        let mapping = monitor::Mapping::new(Arc::clone(view), attributes);
        mappings.insert(view.id(), Arc::downgrade(&mapping));
        Ok(mapping)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DomainRole {
    NormalWb,
    SourcePhysicalRam,
}

/// Canonical current mappings and invocation/service exclusion. The immutable
/// role survives every snapshot publication; physical RAM never acquires the
/// generic Normal-WB callback contract from its host layout.
pub struct MemoryDomain {
    role: DomainRole,
    state: Mutex<DomainState>,
    #[cfg(test)]
    admission_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
    target: TargetCpu,
    system: Arc<MemorySystem>,
    address_space: Option<u64>,
}

impl MemoryDomain {
    pub fn new(
        system: Arc<MemorySystem>,
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
    ) -> Result<Arc<Self>, MemoryStatus> {
        Self::construct(None, system, views, target, DomainRole::NormalWb)
    }

    /// Bind this snapshot to its real process address-space identity.
    pub fn new_for_address_space(
        address_space: u64,
        system: Arc<MemorySystem>,
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
    ) -> Result<Arc<Self>, MemoryStatus> {
        Self::construct(
            Some(address_space),
            system,
            views,
            target,
            DomainRole::NormalWb,
        )
    }

    pub(in crate::memory) fn new_source_physical_ram(
        address_space: u64,
        system: Arc<MemorySystem>,
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
    ) -> Result<Arc<Self>, MemoryStatus> {
        Self::construct(
            Some(address_space),
            system,
            views,
            target,
            DomainRole::SourcePhysicalRam,
        )
    }

    pub(in crate::memory) fn is_source_physical_ram(&self) -> bool {
        self.role == DomainRole::SourcePhysicalRam
    }

    fn check_data_execution(&self) -> Result<(), MemoryStatus> {
        self.check_execution()?;
        if self.is_source_physical_ram() {
            return Err(MemoryStatus::Unsupported);
        }
        Ok(())
    }

    fn construct(
        address_space: Option<u64>,
        system: Arc<MemorySystem>,
        mut views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
        role: DomainRole,
    ) -> Result<Arc<Self>, MemoryStatus> {
        if !target.supported() {
            return Err(MemoryStatus::Unsupported);
        }
        views.sort_unstable_by_key(|(view, _)| view.guest_base());
        for pair in views.windows(2) {
            let end = pair[0].0.guest_base() + pair[0].0.bytes() as u64;
            if end > pair[1].0.guest_base() {
                return Err(MemoryStatus::InvalidRequest);
            }
        }
        let profile = MemoryProfile::inspect(&views);
        let views = views
            .into_iter()
            .map(|(view, attributes)| {
                Ok(RegisteredView {
                    monitor: system.register_view(&view, attributes)?,
                    view,
                })
            })
            .collect::<Result<_, MemoryStatus>>()?;
        Ok(Arc::new(Self {
            role,
            state: Mutex::new(DomainState {
                snapshot: DomainSnapshot {
                    views,
                    profile,
                    generation: 0,
                },
                native_loans: 0,
                servicing: false,
            }),
            #[cfg(test)]
            admission_barrier: Mutex::new(None),
            target,
            system,
            address_space,
        }))
    }

    #[cfg(test)]
    pub(super) fn registered_views(&self) -> Vec<RegisteredView> {
        self.state.lock().unwrap().snapshot.views.clone()
    }

    pub fn address_space(&self) -> Option<u64> {
        self.address_space
    }

    pub fn profile(&self) -> Result<MemoryProfile, MemoryStatus> {
        self.check_data_execution()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| MemoryStatus::Domain)?
            .snapshot
            .profile
            .clone())
    }

    pub fn thread<P: DataPolicy>(self: &Arc<Self>, policy: P) -> MemoryThread<P> {
        MemoryThread {
            domain: Arc::clone(self),
            reservation: self.system.reservations.thread(),
            policy,
            #[cfg(test)]
            post_body_failure_once: false,
        }
    }

    pub fn check_execution(&self) -> Result<(), MemoryStatus> {
        if self.system.failed.load(Ordering::Acquire) {
            return Err(MemoryStatus::Domain);
        }
        self.system
            .reservations
            .check_execution()
            .map_err(|_| MemoryStatus::Domain)
    }

    /// Retire all matching generations before releasing/changing native rights.
    /// The lifecycle owner serializes this shared mapping generation across all
    /// snapshots/address spaces retaining its Arc and excludes in-flight native
    /// accesses before native rights changes or unmapping.
    pub fn retire(self: &Arc<Self>, view: &Arc<MemoryView>) -> Result<(), MemoryStatus> {
        let _loan = self.service_loan()?;
        // Exhausted generations must decline before invalidating any mapping or
        // reservation. The exclusive service loan pins this preflight value.
        let next_generation = self
            .generation()?
            .checked_add(1)
            .ok_or(MemoryStatus::Domain)?;
        self.retire_view(view)?;
        let mut state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()?;
        state.snapshot.generation = next_generation;
        Ok(())
    }

    fn retire_view(&self, view: &Arc<MemoryView>) -> Result<(), MemoryStatus> {
        let state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        let registered = state
            .snapshot
            .views
            .iter()
            .find(|registered| Arc::ptr_eq(&registered.view, view))
            .ok_or(MemoryStatus::InvalidRequest)?;
        // Lifecycle transitions for this shared generation are serialized by its owner.
        // Repeating a retired generation must not clear fresh alias reservations.
        if !registered.view.is_current() {
            return Err(MemoryStatus::InvalidRequest);
        }
        let range = monitor::WriteRange::new(
            Arc::clone(registered.view.backing()),
            registered.view.backing_offset() as u64,
            registered.view.bytes() as u64,
        )
        .map_err(|_| MemoryStatus::Domain)?;
        self.system
            .reservations
            .revoke_mapping(&registered.monitor)
            .map_err(|_| MemoryStatus::Domain)?;
        registered.view.retire();
        // Finite lifecycle invalidation, not a committed byte store. It also
        // reaches reservations whose first mapping is another joined view.
        self.system
            .reservations
            .with_writer(&range, monitor::Invalidation::BeforeAttempt, || {
                Ok::<_, MemoryStatus>(())
            })
            .map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()
    }

    fn resolve(
        &self,
        address: u64,
        bytes: usize,
        kind: AccessKind,
    ) -> Result<PhysicalAccess, MemoryStatus> {
        self.check_data_execution()?;
        self.resolve_spans(address, bytes, kind)
    }

    fn resolve_source_physical(
        self: &Arc<Self>,
        execution: &MemoryExecutionLoan,
        address: u64,
        bytes: usize,
        kind: AccessKind,
    ) -> Result<PhysicalAccess, MemoryStatus> {
        execution.check_domain(self)?;
        if !self.is_source_physical_ram() {
            return Err(MemoryStatus::Unsupported);
        }
        self.resolve_spans(address, bytes, kind)
    }

    fn resolve_spans(
        &self,
        address: u64,
        bytes: usize,
        kind: AccessKind,
    ) -> Result<PhysicalAccess, MemoryStatus> {
        let state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        let views = &state.snapshot.views;
        let mut first_span: Option<ResolvedAccess> = None;
        let mut remaining_spans = Vec::new();
        let mut current = address;
        let mut remaining = bytes;
        let mut attributes = None;
        while remaining != 0 {
            let index = views.partition_point(|view| view.view.guest_base() <= current);
            let registered = index
                .checked_sub(1)
                .and_then(|index| views.get(index))
                .ok_or(MemoryStatus::Translation)?;
            let offset = current
                .checked_sub(registered.view.guest_base())
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|offset| *offset < registered.view.bytes())
                .ok_or(MemoryStatus::Translation)?;
            let reached = remaining.min(registered.view.bytes() - offset);
            let span =
                registered
                    .view
                    .resolve(current, reached, kind)
                    .map_err(|error| match error {
                        super::backing::AccessError::PermissionDenied(_) => {
                            MemoryStatus::Permission
                        }
                        _ => MemoryStatus::Translation,
                    })?;
            let next_attributes = *registered.monitor.attributes();
            if attributes.is_some_and(|attributes| attributes != next_attributes) {
                return Err(MemoryStatus::Unsupported);
            }
            attributes = Some(next_attributes);
            if let Some(first) = &first_span {
                let progressed = bytes - remaining;
                if !Arc::ptr_eq(first.view().backing(), span.view().backing())
                    || first.backing_offset() + progressed != span.backing_offset()
                {
                    return Err(MemoryStatus::Unsupported);
                }
            }
            if first_span.is_none() {
                first_span = Some(span);
            } else {
                remaining_spans.push(span);
            }
            remaining -= reached;
            current = current.wrapping_add(reached as u64);
        }
        Ok(PhysicalAccess {
            first: first_span.ok_or(MemoryStatus::InvalidRequest)?,
            _remaining: remaining_spans,
            attributes: attributes.ok_or(MemoryStatus::InvalidRequest)?,
        })
    }
}

struct PhysicalAccess {
    // Retain every generation intersecting one atomic quantity.
    first: ResolvedAccess,
    _remaining: Vec<ResolvedAccess>,
    attributes: MappingAttributes,
}

impl PhysicalAccess {
    fn first(&self) -> &ResolvedAccess {
        &self.first
    }

    /// Invoked under the real monitor gate before reserved native access.
    fn check_current(&self) -> Result<(), MemoryStatus> {
        if self.first.view().is_current()
            && self._remaining.iter().all(|span| span.view().is_current())
        {
            Ok(())
        } else {
            Err(MemoryStatus::Domain)
        }
    }

    fn data(&self, raw_address: u64, bytes: usize, flags: u32) -> DataAccess<'_> {
        let first = self.first();
        DataAccess {
            raw_address,
            translated_address: first.guest_address(),
            backing: first.view().backing(),
            backing_offset: first.backing_offset(),
            bytes,
            attributes: self.attributes,
            flags,
        }
    }
}

/// One executing guest thread; the reservation survives ordinary block exits.
pub struct MemoryThread<P> {
    domain: Arc<MemoryDomain>,
    reservation: ReservationThread,
    policy: P,
    #[cfg(test)]
    post_body_failure_once: bool,
}

impl<P: DataPolicy> MemoryThread<P> {
    /// Match the exact immutable snapshot retained by a source attribute witness.
    /// Identity alone does not establish effective ARM memory attributes.
    pub(crate) fn has_domain(&self, domain: &Arc<MemoryDomain>) -> bool {
        Arc::ptr_eq(&self.domain, domain)
    }

    pub fn address_space(&self) -> Option<u64> {
        self.domain.address_space()
    }

    pub fn profile(&self) -> Result<MemoryProfile, MemoryStatus> {
        self.domain.profile()
    }

    pub fn execution_loan(&self) -> Result<MemoryExecutionLoan, MemoryStatus> {
        self.domain.execution_loan()
    }

    /// Observe this actual domain under an exclusive read-only service loan.
    /// The caller retains its source/PE observation boundary; this loan supplies
    /// physical serialization, current views and private diagnostic staging.
    pub fn observation_loan(&self) -> Result<MemoryObservationLoan, MemoryStatus> {
        self.domain.observation_loan()
    }

    /// Admit the complete body's platform requirements before any guest effect.
    pub fn prepare(
        &mut self,
        requirements: MemoryRequirements,
    ) -> Result<CheckedMemoryEntry<'_, P>, MemoryStatus> {
        self.prepare_with(|owner| {
            owner.domain.check_execution()?;
            owner
                .domain
                .profile()?
                .validate(requirements, owner.domain.target)?;
            owner.validate_execution(requirements.required_flags)?;
            owner
                .policy
                .validate_sp_alignment(requirements.required_sp_alignment)?;
            owner
                .policy
                .validate_address_checks(requirements.required_address_checks)?;
            owner
                .policy
                .validate_pointer_arithmetic(requirements.required_pointer_arithmetic)?;
            if requirements.required_profile & profile_requirements::SCALABLE_TAG_CHECKS != 0 {
                owner.policy.validate_implementation_profile(
                    MemoryImplementationProfile::ScalableTagChecks,
                )?;
            }
            Ok(())
        })
    }
    /// Native entry must validate effective controls before executing an instruction.
    pub fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus> {
        self.domain.check_data_execution()?;
        self.policy.validate_execution(required_flags)?;
        for (flag, class) in [
            (flags::ATOMIC, MemoryOperationClass::Atomic),
            (flags::ORDERED, MemoryOperationClass::Ordered),
            (flags::EXCLUSIVE, MemoryOperationClass::Exclusive),
        ] {
            if required_flags & flag != 0 {
                self.policy.validate_operation_execution(class)?;
            }
        }
        Ok(())
    }

    /// Test-only injection at the provider's real post-body finalization boundary.
    /// The next returned body consumes the flag and fails the actual shared
    /// MemorySystem; callers must retain fault/native-execution provenance.
    #[cfg(test)]
    pub(crate) fn inject_post_body_failure_once_for_test(&mut self) {
        self.post_body_failure_once = true;
    }

    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.policy
    }

    /// Bind this actual reservation context to one real PE before any mark.
    /// Binding is fixed until context teardown; live marks cannot be reassigned.
    pub fn bind_events(&mut self, producer: &EventProducer) -> Result<(), MemoryStatus> {
        self.domain.check_execution()?;
        self.domain
            .system
            .reservations
            .bind_events(&mut self.reservation, producer)
            .map_err(|_| MemoryStatus::Domain)
    }

    /// Check the retained monitor binding against a borrowed live PE owner.
    /// Perform this preflight before architectural effects and retain both
    /// borrows for the complete entry. This check never changes a reservation.
    pub fn check_event_endpoint(&self, endpoint: &EventEndpoint) -> Result<(), MemoryStatus> {
        self.domain.check_execution()?;
        self.domain
            .system
            .reservations
            .check_event_endpoint(&self.reservation, &endpoint.producer())
            .map_err(|_| MemoryStatus::Domain)
    }

    /// Clear only the local reservation. The independent global mark survives.
    /// ERET separately signals its prechecked borrowed endpoint in source order.
    pub fn clear_reservation(&mut self) -> Result<(), MemoryStatus> {
        self.domain.check_execution()?;
        self.domain
            .system
            .reservations
            .clear(&mut self.reservation)
            .map_err(|_| MemoryStatus::Domain)?;
        // Cleanup can wait behind another PE. A terminal failure while waiting
        // must remain an explicit backend failure, never guest ERET success.
        self.domain.check_execution()
    }

    /// Selected implementation policy after a genuine architectural memory
    /// fault. Platform/ABI declines preserve the existing local reservation.
    /// This does not alter the fault's source location or completed prefix.
    pub fn settle_fault(&mut self, status: MemoryStatus) -> Result<(), MemoryStatus> {
        if is_guest_fault(status as u32) {
            self.domain
                .system
                .reservations
                .clear(&mut self.reservation)
                .map_err(|_| MemoryStatus::Domain)?;
        }
        Ok(())
    }

    /// Borrow a service view for one synchronous context-backed invocation.
    /// This legacy API returns R even when finalization fails; owned checked
    /// execution must use with_checked_view and observe its outer Result.
    ///
    /// # Safety
    /// Native code may call only the supplied callback with valid requests and
    /// disjoint private staging buffers of the declared size. It must preserve
    /// the header, opaque pointer and callback, retain no pointers, not reenter
    /// this owner, and honor the mapping/staging lifetime and separation contracts.
    /// Guest and native physical addresses must have congruent low four bits
    /// for the declared SCA16 profile; unsupported native footprints fail explicitly.
    pub unsafe fn with_view<R>(&mut self, callback: impl FnOnce(&mut MemoryContextView) -> R) -> R {
        // Legacy low-level contract: callers cannot infer successful finalization
        // from R. Owned checked execution must use with_checked_view instead.
        self.domain
            .check_data_execution()
            .expect("supported legacy memory role");
        let _loan = self
            .execution_loan()
            .expect("serialized legacy memory invocation");
        let (result, _finalization) = unsafe { self.invoke_memory_view(callback) };
        result
    }

    /// Invoke and finalize one checked memory body before returning its result.
    /// A finalization failure discards R even when native code already returned.
    /// Callers retaining fault provenance must copy it during the callback.
    ///
    /// # Safety
    /// Inherits with_view's complete synchronous native/staging contract. The
    /// caller retains the actual policy and storage loan throughout.
    pub unsafe fn with_checked_view<R>(
        &mut self,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        // SAFETY: the caller retains the same owner and native invocation loan.
        self.domain.check_data_execution()?;
        let _loan = self.execution_loan()?;
        let (result, finalization) = unsafe { self.invoke_memory_view(callback) };
        finalization.map(|()| result)
    }

    /// One common finalization for callback faults and locally emitted alignment faults.
    unsafe fn invoke_memory_view<R>(
        &mut self,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> (R, Result<(), MemoryStatus>) {
        let mut view = MemoryContextView {
            version: MEMORY_CONTEXT_VERSION,
            bytes: MEMORY_CONTEXT_BYTES,
            callback: dispatch::<P>,
            opaque: std::ptr::from_mut(self).cast(),
            fault_kind: MemoryStatus::Success as u32,
            reserved: 0,
            fault_address: 0,
            fault_pc: 0,
            completed_bytes: 0,
            reserved_tail: 0,
        };
        let result = callback(&mut view);
        #[cfg(test)]
        if std::mem::take(&mut self.post_body_failure_once) {
            self.domain.system.failed.store(true, Ordering::Release);
        }
        let finalization = MemoryStatus::from_code(view.fault_kind)
            .ok_or(MemoryStatus::Domain)
            .and_then(|status| self.settle_fault(status))
            .and_then(|()| self.domain.check_execution());
        (result, finalization)
    }

    unsafe fn transfer(
        &mut self,
        view: &mut MemoryContextView,
        request: &MemoryRequest,
    ) -> Result<(), (MemoryStatus, u64)> {
        if request.flags & flags::EXCLUSIVE != 0 {
            // SAFETY: category-specific staging contract is inherited from dispatch.
            return unsafe { self.transfer_exclusive(view, request) };
        }
        self.validate_execution(request.flags)
            .map_err(|status| (status, request.address))?;
        if request.data.is_null() || !request.has_supported_ordinary_shape() {
            return Err((MemoryStatus::InvalidRequest, request.address));
        }
        let translated = self
            .policy
            .translate(request.address)
            .map_err(|status| (status, request.address))?;
        for part in AccessParts::new(translated, request.bytes as usize, request.flags) {
            let raw = request.address.wrapping_add(part.offset as u64);
            let address = self.policy.translate(raw).map_err(|status| (status, raw))?;
            // Translation of an earlier part does not authorize this part, or
            // bytes beyond a translation regime's address limit. Check only the
            // reached atomic part before its mapping permissions.
            for offset in 1..part.bytes {
                let raw_byte = raw.wrapping_add(offset as u64);
                let translated_byte = self
                    .policy
                    .translate(raw_byte)
                    .map_err(|status| (status, raw_byte))?;
                if address.checked_add(offset as u64) != Some(translated_byte) {
                    return Err((MemoryStatus::Translation, raw_byte));
                }
            }
            let write = request.flags & flags::WRITE != 0;
            let kind = if write {
                AccessKind::Write
            } else {
                AccessKind::Read
            };
            let physical = self
                .domain
                .resolve(address, part.bytes, kind)
                .map_err(|status| (status, raw))?;
            let first = physical.first();
            let pointer = first.host_ptr().as_ptr();
            let completed = view
                .completed_bytes
                .checked_add(part.bytes as u64)
                .ok_or((MemoryStatus::InvalidRequest, raw))?;
            if write {
                if part.bytes == SCA_BYTES && !self.domain.target.supports(TargetCpu::Cx16) {
                    return Err((MemoryStatus::Unsupported, raw));
                }
                first
                    .view()
                    .backing()
                    .host_pointer(first.backing_offset(), part.bytes, AccessKind::Read)
                    .map_err(|_| (MemoryStatus::Unsupported, raw))?;
                // Native staging is private and belongs exclusively to this call.
                let mut bytes = [0_u8; SCA_BYTES];
                // SAFETY: the invocation contract grants exact private staging.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        request.data.add(part.offset),
                        bytes.as_mut_ptr(),
                        part.bytes,
                    );
                }
                let value = u128::from_le_bytes(bytes);
                let range = monitor::WriteRange::new(
                    Arc::clone(first.view().backing()),
                    first.backing_offset() as u64,
                    part.bytes as u64,
                )
                .map_err(|_| (MemoryStatus::Domain, raw))?;
                let policy = if physical.attributes.shareable {
                    monitor::Invalidation::BeforeAttempt
                } else {
                    monitor::Invalidation::OnCommit
                };
                let target = self.domain.target;
                self.domain
                    .system
                    .reservations
                    .with_writer(&range, policy, || {
                        self.policy
                            .check(physical.data(raw, part.bytes, part.flags))?;
                        // SAFETY: exact resolved spans pin stable rights/lifetime;
                        // staging never aliases guest bytes; checked target is owned.
                        unsafe { access::write_part(pointer, part.bytes, value, target) }
                            .map_err(|_| MemoryStatus::Unsupported)
                    })
                    .map_err(|error| {
                        (
                            match error {
                                monitor::AccessError::Monitor(_) => MemoryStatus::Domain,
                                monitor::AccessError::Memory(status) => status,
                            },
                            raw,
                        )
                    })?;
            } else {
                self.policy
                    .check(physical.data(raw, part.bytes, part.flags))
                    .map_err(|status| (status, raw))?;
                let (host_address, footprint) =
                    access::read_footprint(pointer as usize, part.bytes, self.domain.target)
                        .map_err(|_| (MemoryStatus::Unsupported, raw))?;
                let delta = pointer as usize - host_address;
                let envelope_offset = first
                    .backing_offset()
                    .checked_sub(delta)
                    .ok_or((MemoryStatus::Unsupported, raw))?;
                // Extra snapshot bytes are a host requirement, not another
                // guest access. Failure must not manufacture a guest abort.
                first
                    .view()
                    .backing()
                    .host_pointer(envelope_offset, footprint, AccessKind::Read)
                    .map_err(|_| (MemoryStatus::Unsupported, raw))?;
                // SAFETY: the requested parts and any read envelope are checked;
                // backing construction supplies live stable coherent native RAM.
                let value = unsafe { access::read_part(pointer, part.bytes, self.domain.target) }
                    .map_err(|_| (MemoryStatus::Unsupported, raw))?;
                let bytes = value.to_le_bytes();
                // SAFETY: destination is private staging, not architectural RAM.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        request.data.add(part.offset),
                        part.bytes,
                    );
                }
            }
            view.completed_bytes = completed;
        }
        Ok(())
    }
}

fn is_guest_fault(status: u32) -> bool {
    [
        MemoryStatus::Translation,
        MemoryStatus::Permission,
        MemoryStatus::Alignment,
        MemoryStatus::StackAlignment,
        MemoryStatus::TagCheck,
    ]
    .into_iter()
    .any(|fault| status == fault as u32)
}

unsafe extern "C" fn dispatch<P: DataPolicy>(
    view: *mut MemoryContextView,
    request: *const MemoryRequest,
) -> u32 {
    if view.is_null() || request.is_null() {
        return MemoryStatus::InvalidRequest as u32;
    }
    // SAFETY: the native invocation grants valid, disjoint ABI objects.
    let (view, request) = unsafe { (&mut *view, &*request) };
    if !view.has_supported_header() || view.opaque.is_null() {
        return MemoryStatus::InvalidRequest as u32;
    }
    // SAFETY: with_view binds this exact monomorphized owner for the invocation.
    let owner = unsafe { &mut *view.opaque.cast::<MemoryThread<P>>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: dispatch inherits the valid private staging contract.
        unsafe { owner.transfer(view, request) }
    }));
    match result {
        Ok(Ok(())) => MemoryStatus::Success as u32,
        Ok(Err((status, address))) => {
            // Architectural fault cleanup is common at with_view return; a
            // platform/ABI decline must preserve the existing local mark.
            view.record(status, address, request.pc, view.completed_bytes);
            status as u32
        }
        Err(_) => {
            owner.domain.system.failed.store(true, Ordering::Release);
            let _ = owner
                .domain
                .system
                .reservations
                .clear(&mut owner.reservation);
            view.record(
                MemoryStatus::Domain,
                request.address,
                request.pc,
                view.completed_bytes,
            );
            MemoryStatus::Domain as u32
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AccessPart {
    address: u64,
    offset: usize,
    bytes: usize,
    flags: u32,
}

struct AccessParts {
    address: u64,
    bytes: usize,
    offset: usize,
    part_bytes: usize,
    flags: u32,
}

impl AccessParts {
    fn new(address: u64, bytes: usize, descriptor: u32) -> Self {
        let residue = address as usize & (SCA_BYTES - 1);
        let asimd = descriptor & flags::ASIMD != 0 && descriptor & flags::SME == 0;
        let pair = descriptor & flags::PAIR != 0;
        let half = bytes / 2;
        // Exact Mem order for Normal-WB/LSE2/SCA16, LS64WB disabled and no
        // highest-address-first access. ASIMD wide cases precede LSE2; the
        // SVE-predicated 16B case follows it. Pair alignment uses half-width.
        let (part_bytes, clear_pair) = if asimd
            && bytes == SCA_BYTES
            && address.is_multiple_of(HALF_SCA_BYTES as u64)
        {
            (HALF_SCA_BYTES, false)
        } else if asimd && bytes == SCA_BYTES * 2 && address.is_multiple_of(HALF_SCA_BYTES as u64) {
            (HALF_SCA_BYTES, true)
        } else if residue + bytes <= SCA_BYTES {
            (bytes, false)
        } else if pair && half != 0 && address.is_multiple_of(half as u64)
            || descriptor & flags::SME == 0
                && descriptor & flags::SVE_PREDICATED != 0
                && bytes == SCA_BYTES
                && address.is_multiple_of(HALF_SCA_BYTES as u64)
        {
            (half, true)
        } else {
            (1, false)
        };
        let flags = if clear_pair {
            descriptor & !flags::PAIR
        } else {
            descriptor
        };
        Self {
            address,
            bytes,
            offset: 0,
            part_bytes,
            flags,
        }
    }
}

impl Iterator for AccessParts {
    type Item = AccessPart;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes {
            return None;
        }
        let part = AccessPart {
            address: self.address.wrapping_add(self.offset as u64),
            offset: self.offset,
            bytes: self.part_bytes,
            flags: self.flags,
        };
        self.offset += self.part_bytes;
        Some(part)
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "domain/tests.rs"]
mod tests;
