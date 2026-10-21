//! The memory service behind context-backed native code.
//!
//! Instruction families submit each reached element; the domain resolves its
//! atomic parts, checks tags and publishes writes through the shared reservation
//! domain.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
mod scalar;
pub use scalar::{MemoryFault, MemoryReader};

mod publication;
pub use publication::PublicationFault;
pub(in crate::memory) mod source_mutation;
pub(crate) use source_mutation::SourceWriteReceipt;
mod profile;
mod tag_transfer;
pub use profile::{CheckedMemoryEntry, MemoryProfile};
mod lifecycle;
pub(in crate::memory) use lifecycle::MemoryServiceLoan;
pub(in crate::memory) use lifecycle::ServiceLoanAttempt;
use lifecycle::{DomainSnapshot, DomainState};
pub use lifecycle::{ExecutionLoanAttempt, MemoryExecutionLoan, MemoryObservationLoan};

mod exclusive;
pub(crate) mod m0_read;
mod m0_scalar;
pub(crate) mod m0_write;
pub(crate) mod physical;
mod read;
mod shared;

use crate::platform::sync::Mutex;
use crate::system::events::{EventEndpoint, EventProducer};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::collections::HashMap;

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

/// Architectural service category, retained even when typed staging is adapted
/// to the ordinary all-writer transfer path. This is not a native wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataOperation {
    Ordinary,
    Exclusive,
    Atomic,
    Ordered,
    AllocationTag,
}

/// Original reached request. Dynamic source policies need its full quantity
/// and source PC before checking a smaller atomic part's translation/rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataRequest {
    pub address: u64,
    pub bytes: usize,
    pub flags: u32,
    pub pc: Option<u64>,
    pub operation: DataOperation,
}

impl DataRequest {
    fn native(request: &MemoryRequest, operation: DataOperation) -> Self {
        Self {
            address: request.address,
            bytes: request.bytes as usize,
            flags: request.flags,
            pc: Some(request.pc),
            operation,
        }
    }
}

/// One reached physical atomic quantity; no later part is authorized by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPart {
    pub address: u64,
    pub bytes: usize,
    pub kind: AccessKind,
}

/// Effective CPU controls belong to the per-thread policy, not each ISA family.
/// Policy callbacks must not reenter or retire this domain while an access is active.
pub trait DataPolicy {
    fn validate_instructions(
        &self,
        required: stela_compiler::context::memory::InstructionRequirements,
    ) -> Result<(), MemoryStatus> {
        if required.is_empty() {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    /// Typed service classes must be admitted by the CPU owner.
    fn validate_operation_execution(
        &self,
        _class: MemoryOperationClass,
    ) -> Result<(), MemoryStatus> {
        Err(MemoryStatus::Unsupported)
    }
    /// Reject unavailable effective-control profiles before any guest effect.
    fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus>;
    /// Check the body's SP specialization against the effective controls.
    fn validate_sp_alignment(&self, required: SpAlignmentRequirement) -> Result<(), MemoryStatus> {
        if required == SpAlignmentRequirement::Any {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    /// Check the emitted FEAT_CPA address specialization against the CPU owner.
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
    /// FEAT_CPA arithmetic must be admitted by the CPU even when its result is
    /// discarded.
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
    /// Address normalization for access decomposition only. Dynamic policies
    /// must not perform table walks, permission checks or descriptor updates here.
    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus>;
    /// Check original-access constraints before any reached translation/effect.
    /// The legacy fixed policy has no additional request-dependent controls.
    fn validate_data_request(&mut self, _request: DataRequest) -> Result<(), MemoryStatus> {
        Ok(())
    }
    /// Translate precisely this reached part with its actual read/write intent.
    /// A dynamic policy may walk once when the entire part is inside the same
    /// source leaf; it must establish every byte's rights and physical identity.
    /// The default preserves legacy per-byte translation and exact fault address.
    fn translate_part(
        &mut self,
        _request: DataRequest,
        part: DataPart,
    ) -> Result<u64, (MemoryStatus, u64)> {
        let address = self
            .translate(part.address)
            .map_err(|status| (status, part.address))?;
        for offset in 1..part.bytes {
            let raw = part.address.wrapping_add(offset as u64);
            let translated = self.translate(raw).map_err(|status| (status, raw))?;
            if address.checked_add(offset as u64) != Some(translated) {
                return Err((MemoryStatus::Translation, raw));
            }
        }
        Ok(address)
    }
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
    // Serializes Device RAM transactions on this machine.
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
        // Keep the registry bounded by live generations rather than mapping
        // history.
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
    /// Only actual-CPL0 registration constructs this role. Native entry must
    /// retain an actual per-worker target proof through checked finalization.
    NativeSystemRam,
}

/// Canonical current mappings and invocation/service exclusion. The immutable
/// role survives every snapshot publication; physical RAM never acquires the
/// generic Normal-WB callback contract from its host layout.
pub struct MemoryDomain {
    role: DomainRole,
    state: Mutex<DomainState>,
    /// Snapshot generation; written only under `state` by an exclusive service.
    generation: core::sync::atomic::AtomicU64,
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
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
        role: DomainRole,
    ) -> Result<Arc<Self>, MemoryStatus> {
        if !crate::platform::cpu::admitted(target) {
            return Err(MemoryStatus::Unsupported);
        }
        Self::construct_admitted(address_space, system, views, target, role)
    }

    /// Reserved system RAM has an actual-current-CPL0 target authority and
    /// retained mapping owner, rather than the legacy identity-frame allocator.
    pub(in crate::memory) fn new_native_system_ram(
        system: Arc<MemorySystem>,
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        authority: &crate::platform::cpu::system::NativeSystemTarget,
    ) -> Result<Arc<Self>, MemoryStatus> {
        authority
            .revalidate()
            .map_err(|_| MemoryStatus::Unsupported)?;
        Self::construct_admitted(
            None,
            system,
            views,
            authority.target(),
            DomainRole::NativeSystemRam,
        )
    }

    fn construct_admitted(
        address_space: Option<u64>,
        system: Arc<MemorySystem>,
        mut views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
        role: DomainRole,
    ) -> Result<Arc<Self>, MemoryStatus> {
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
            generation: core::sync::atomic::AtomicU64::new(0),
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
        }
    }

    pub fn check_execution(&self) -> Result<(), MemoryStatus> {
        if self.role != DomainRole::NativeSystemRam && !crate::platform::cpu::admitted(self.target)
        {
            return Err(MemoryStatus::Unsupported);
        }
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
        // Refuse on generation exhaustion before invalidating any mapping or
        // reservation; the exclusive service borrow keeps this value stable.
        let next_generation = self
            .generation()?
            .checked_add(1)
            .ok_or(MemoryStatus::Domain)?;
        self.retire_view(view)?;
        let mut state = self.state.lock().map_err(|_| MemoryStatus::Domain)?;
        self.check_execution()?;
        state.snapshot.generation = next_generation;
        self.generation.store(next_generation, Ordering::Release);
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
}

/// The real local monitor plus its mapping/service exclusion loan, retained
/// through the final infallible CPU/controller settlement.
pub(crate) struct PreparedLocalClear<'a> {
    clear: monitor::PreparedClear<'a, MemoryBacking, MemoryView, MappingAttributes>,
    _loan: MemoryExecutionLoan,
}
impl PreparedLocalClear<'_> {
    pub(crate) fn commit(self) {
        self.clear.commit();
    }
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

    /// Like `execution_loan`, but report a busy host service instead of failing.
    pub fn try_execution_loan(&self) -> Result<ExecutionLoanAttempt, MemoryStatus> {
        self.domain.try_execution_loan()
    }

    /// Observe the domain under an exclusive read-only service borrow, which
    /// provides physical serialization, the current views and private staging.
    pub fn observation_loan(&self) -> Result<MemoryObservationLoan, MemoryStatus> {
        self.domain.observation_loan()
    }

    /// Admit the complete body's platform requirements before any guest effect.
    pub fn prepare(
        &mut self,
        requirements: MemoryRequirements,
    ) -> Result<CheckedMemoryEntry<'_, P>, MemoryStatus> {
        if self.domain.role == DomainRole::NativeSystemRam {
            return Err(MemoryStatus::Unsupported);
        }
        self.prepare_body(requirements)
    }

    /// The engine must borrow actual current-owner admission, rather than
    /// laundering a system domain through the legacy identity-frame mount.
    pub(crate) fn prepare_native_system<'a>(
        &'a mut self,
        requirements: MemoryRequirements,
        authority: &'a crate::platform::cpu::system::NativeSystemTarget,
    ) -> Result<CheckedMemoryEntry<'a, P>, MemoryStatus> {
        if self.domain.role != DomainRole::NativeSystemRam
            || !authority.target().supports(self.domain.target)
        {
            return Err(MemoryStatus::Unsupported);
        }
        authority
            .revalidate()
            .map_err(|_| MemoryStatus::Unsupported)?;
        let mut entry = self.prepare_body(requirements)?;
        entry.native_system = Some(authority);
        Ok(entry)
    }

    fn prepare_body(
        &mut self,
        requirements: MemoryRequirements,
    ) -> Result<CheckedMemoryEntry<'_, P>, MemoryStatus> {
        self.prepare_with(|owner| {
            owner.domain.check_execution()?;
            if requirements.required_profile & profile_requirements::SYSTEM_ATOMIC_READ_WRITEBACK
                != 0
                && owner.domain.role != DomainRole::NativeSystemRam
            {
                return Err(MemoryStatus::Unsupported);
            }
            owner
                .domain
                .profile()?
                .validate(requirements, owner.domain.target)?;
            owner.validate_execution(requirements.required_flags)?;
            owner
                .policy
                .validate_instructions(requirements.required_instructions)?;
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

    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.policy
    }

    /// Bind this reservation context to one PE before any mark. The binding
    /// lasts until the context is torn down.
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

    pub(crate) fn prepare_clear_reservation(
        &mut self,
    ) -> Result<PreparedLocalClear<'_>, MemoryStatus> {
        let loan = self.domain.execution_loan()?;
        let clear = self
            .domain
            .system
            .reservations
            .prepare_clear(&mut self.reservation)
            .map_err(|_| MemoryStatus::Domain)?;
        Ok(PreparedLocalClear { clear, _loan: loan })
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
        // Cleanup can wait behind another PE; a failure while waiting is a
        // backend failure, never a successful ERET.
        self.domain.check_execution()
    }

    /// Apply the implementation's policy after an architectural memory fault.
    /// Platform and ABI declines keep the local reservation. The fault's
    /// location and completed prefix are unchanged.
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

    /// Borrow a service view for one synchronous context-backed call. This
    /// older API returns `R` even when finalization fails; checked execution
    /// uses `with_checked_view`.
    ///
    /// # Safety
    /// Native code may call only the supplied callback, with valid requests and
    /// disjoint private staging of the declared size. It must keep the header,
    /// opaque pointer and callback intact, keep no pointers, not re-enter this
    /// owner, and respect the mapping and staging lifetimes. Guest and native
    /// addresses must agree in their low four bits for 16-byte single-copy
    /// atomicity; unsupported footprints fail.
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

    /// Run and finalize one checked memory body. A finalization failure
    /// discards `R` even when native code returned; callers needing the fault
    /// details must copy them during the callback.
    ///
    /// # Safety
    /// As for `with_view`. The caller keeps the policy and storage borrows
    /// throughout.
    pub unsafe fn with_checked_view<R>(
        &mut self,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        // SAFETY: the caller keeps the owner and the native invocation borrow.
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
            opaque: core::ptr::from_mut(self).cast(),
            fault_kind: MemoryStatus::Success as u32,
            fault_access: 0,
            fault_address: 0,
            fault_pc: 0,
            completed_bytes: 0,
            reserved_tail: 0,
        };
        let result = callback(&mut view);
        let finalization = view
            .has_supported_header()
            .then_some(())
            .ok_or(MemoryStatus::Domain)
            .and_then(|()| MemoryStatus::from_code(view.fault_kind).ok_or(MemoryStatus::Domain))
            .and_then(|status| self.settle_fault(status))
            .and_then(|()| self.domain.check_execution());
        if finalization == Err(MemoryStatus::Domain) {
            self.domain.system.failed.store(true, Ordering::Release);
        }
        (result, finalization)
    }

    unsafe fn transfer(
        &mut self,
        view: &mut MemoryContextView,
        request: &MemoryRequest,
    ) -> Result<(), (MemoryStatus, u64)> {
        if request.flags & (flags::ATOMIC | flags::ORDERED) != 0 {
            // SAFETY: dedicated typed payload staging is inherited from dispatch.
            return unsafe { self.transfer_shared(view, request) };
        }
        if request.flags & flags::EXCLUSIVE != 0 {
            // SAFETY: category-specific staging contract is inherited from dispatch.
            return unsafe { self.transfer_exclusive(view, request) };
        }
        // Preserve the source category through ordered payload adaptation.
        unsafe { self.transfer_ordinary(view, request, DataOperation::Ordinary) }
    }

    /// # Safety
    /// Same private ordinary staging and retained invocation as `transfer`.
    pub(super) unsafe fn transfer_ordinary(
        &mut self,
        view: &mut MemoryContextView,
        request: &MemoryRequest,
        operation: DataOperation,
    ) -> Result<(), (MemoryStatus, u64)> {
        self.validate_execution(request.flags)
            .map_err(|status| (status, request.address))?;
        if request.data.is_null() || !request.has_supported_ordinary_shape() {
            return Err((MemoryStatus::InvalidRequest, request.address));
        }
        let intent = DataRequest::native(request, operation);
        self.policy
            .validate_data_request(intent)
            .map_err(|status| (status, request.address))?;
        let translated = self
            .policy
            .translate(request.address)
            .map_err(|status| (status, request.address))?;
        for part in AccessParts::new(translated, request.bytes as usize, request.flags) {
            let raw = request.address.wrapping_add(part.offset as u64);
            let write = request.flags & flags::WRITE != 0;
            let kind = if write {
                AccessKind::Write
            } else {
                AccessKind::Read
            };
            let address = self.policy.translate_part(
                intent,
                DataPart {
                    address: raw,
                    bytes: part.bytes,
                    kind,
                },
            )?;
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
                    core::ptr::copy_nonoverlapping(
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
                let mut mutation = self
                    .domain
                    .system
                    .prepare_source_write(
                        first.view().backing(),
                        first.backing_offset(),
                        part.bytes,
                    )
                    .map_err(|status| (status, raw))?;
                self.domain
                    .system
                    .reservations
                    .with_writer(&range, policy, || {
                        self.policy
                            .check(physical.data(raw, part.bytes, part.flags))?;
                        // SAFETY: the resolved spans pin stable rights and
                        // lifetime, staging never aliases guest bytes, and the
                        // target is owned.
                        mutation.attempting();
                        unsafe { access::write_part(pointer, part.bytes, value, target) }
                            .map_err(|_| MemoryStatus::Unsupported)?;
                        let _receipt = mutation.complete();
                        Ok::<_, MemoryStatus>(())
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
                let value = self
                    .domain
                    .read_part(first, part.bytes)
                    .map_err(|status| (status, raw))?;
                let bytes = value.to_le_bytes();
                // SAFETY: destination is private staging, not architectural RAM.
                unsafe {
                    core::ptr::copy_nonoverlapping(
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

unsafe extern "sysv64" fn dispatch<P: DataPolicy>(
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
    let result = crate::platform::unwind::invoke(core::panic::AssertUnwindSafe(|| {
        // SAFETY: dispatch inherits the valid private staging contract.
        unsafe { owner.transfer(view, request) }
    }));
    match result {
        Ok(Ok(())) => {
            if stela_compiler::context::memory::FaultAccess::from_code(view.fault_access).is_none()
            {
                owner.domain.system.failed.store(true, Ordering::Release);
                view.fault_kind = MemoryStatus::Domain as u32;
                return MemoryStatus::Domain as u32;
            }
            view.fault_access = 0;
            MemoryStatus::Success as u32
        }
        Ok(Err((status, address))) => {
            // Architectural fault cleanup is common at with_view return; a
            // platform/ABI decline must preserve the existing local mark.
            let status =
                if stela_compiler::context::memory::FaultAccess::from_code(view.fault_access)
                    .is_some()
                {
                    status
                } else {
                    owner.domain.system.failed.store(true, Ordering::Release);
                    MemoryStatus::Domain
                };
            // Keep the raw access code even on an ABI violation. Native-call
            // diagnostics must not normalize an unknown direction into success.
            view.fault_kind = status as u32;
            view.fault_address = address;
            view.fault_pc = request.pc;
            status as u32
        }
        Err(_) => {
            owner.domain.system.failed.store(true, Ordering::Release);
            let _ = owner
                .domain
                .system
                .reservations
                .clear(&mut owner.reservation);
            view.fault_kind = MemoryStatus::Domain as u32;
            view.fault_address = request.address;
            view.fault_pc = request.pc;
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
mod tests {
    use super::super::backing::AccessPermissions;
    use super::*;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::ptr::NonNull;

    mod callbacks {
        use super::*;

        #[test]
        fn unqualified_policy_refuses_both_checked_and_disabled_cpa_specializations_before_entry() {
            use stela_compiler::context::memory::address::{
                AccessEl, AddressAddChecks, AddressCheckRequirements, IncrementChoice,
            };
            let domain = domain(Vec::new());
            let mut thread = domain.thread(Policy::default());
            assert!(thread.prepare(MemoryRequirements::default()).is_ok());
            for access_el in [AccessEl::El0, AccessEl::El1] {
                for checks in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
                    let required = MemoryRequirements {
                        required_address_checks: AddressCheckRequirements::for_access(
                            access_el, checks,
                        )
                        .with_increment_choice(IncrementChoice::Unchecked),
                        ..Default::default()
                    };
                    assert_eq!(
                        thread.prepare(required).err(),
                        Some(MemoryStatus::Unsupported)
                    );
                    assert!(thread.policy.checked.is_empty());
                }
            }
        }

        #[test]
        fn access_parts_match_all_sca_residues_and_architectural_widths() {
            for residue in 0..SCA_BYTES {
                for bytes in [1, 2, 4, 8, SCA_BYTES] {
                    let actual: Vec<_> =
                        AccessParts::new(GUEST_BASE + residue as u64, bytes, flags::SVE_PREDICATED)
                            .collect();
                    let expected_widths = if residue + bytes <= SCA_BYTES {
                        vec![bytes]
                    } else if bytes == SCA_BYTES && residue == HALF_SCA_BYTES {
                        vec![HALF_SCA_BYTES; 2]
                    } else {
                        vec![1; bytes]
                    };
                    assert_eq!(
                        actual.iter().map(|part| part.bytes).collect::<Vec<_>>(),
                        expected_widths,
                        "residue={residue} width={bytes}"
                    );
                    let mut offset = 0;
                    for part in actual {
                        assert_eq!(part.offset, offset);
                        assert_eq!(part.address, GUEST_BASE + residue as u64 + offset as u64);
                        assert!(
                            (part.address as usize & (SCA_BYTES - 1)) + part.bytes <= SCA_BYTES
                        );
                        offset += part.bytes;
                    }
                    assert_eq!(offset, bytes);
                }
            }
        }

        #[test]
        fn synchronous_callbacks_write_read_and_preserve_neighbors() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Policy::default());
            for bytes in [1, 2, 4, 8, SCA_BYTES] {
                if bytes == SCA_BYTES && !TargetCpu::detect().supports(TargetCpu::Cx16) {
                    continue;
                }
                let mut expected = (1..=bytes).map(|byte| byte as u8).collect::<Vec<_>>();
                let written = invoke(
                    &mut thread,
                    GUEST_BASE + SCA_BYTES as u64,
                    &mut expected,
                    flags::WRITE,
                );
                assert_eq!(written.status, MemoryStatus::Success as u32);
                assert_eq!(written.completed, bytes as u64);
                let mut actual = vec![0xa5; bytes];
                let read = invoke(&mut thread, GUEST_BASE + SCA_BYTES as u64, &mut actual, 0);
                if bytes == SCA_BYTES && !TargetCpu::detect().supports(TargetCpu::AtomicLoad16) {
                    assert_eq!(read.status, MemoryStatus::Unsupported as u32);
                    assert_eq!(actual, vec![0xa5; bytes]);
                    continue;
                }
                assert_eq!(read.status, MemoryStatus::Success as u32);
                assert_eq!(actual, expected);
                assert!(snapshot(&backing, SCA_BYTES).iter().all(|byte| *byte == 0));
            }
        }

        #[test]
        fn actual_native_callbacks_cover_every_admitted_residue_and_width() {
            let target = TargetCpu::detect();
            let mut admitted = 0;
            let mut capability_declined = 0;
            for residue in 0..SCA_BYTES {
                for bytes in [1, 2, 4, 8, SCA_BYTES] {
                    let address = GUEST_BASE + SCA_BYTES as u64 + residue as u64;
                    let physical = backing();
                    let pointer = physical
                        .host_pointer(SCA_BYTES + residue, bytes, AccessKind::Read)
                        .unwrap();
                    let supported = AccessParts::new(address, bytes, 0).all(|part| {
                        (part.bytes != SCA_BYTES || target.supports(TargetCpu::Cx16))
                            && access::read_footprint(
                                pointer.as_ptr() as usize + part.offset,
                                part.bytes,
                                target,
                            )
                            .is_ok()
                    });
                    if !supported {
                        capability_declined += 1;
                        continue;
                    }
                    admitted += 1;
                    let domain = domain(vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
                    let mut thread = domain.thread(Policy::default());
                    let mut expected = (1..=bytes).map(|byte| byte as u8).collect::<Vec<_>>();
                    let written = invoke(&mut thread, address, &mut expected, flags::WRITE);
                    assert_eq!(
                        written.status,
                        MemoryStatus::Success as u32,
                        "residue={residue} width={bytes}"
                    );
                    assert_eq!(written.completed, bytes as u64);
                    let mut actual = vec![0xa5; bytes];
                    assert_eq!(
                        invoke(&mut thread, address, &mut actual, 0).status,
                        MemoryStatus::Success as u32
                    );
                    assert_eq!(actual, expected);
                    let mut full_expected = vec![0; STORAGE_BYTES];
                    full_expected[SCA_BYTES + residue..SCA_BYTES + residue + bytes]
                        .copy_from_slice(&expected);
                    assert_eq!(snapshot(&physical, STORAGE_BYTES), full_expected);
                }
            }
            assert_eq!(admitted + capability_declined, SCA_BYTES * 5);
            eprintln!(
                "native callback matrix: {admitted} admitted, {capability_declined} capability-declined"
            );
        }

        #[test]
        fn wide_read_and_write_host_capabilities_are_independent() {
            for target in [
                TargetCpu::Baseline,
                TargetCpu::Cx16,
                TargetCpu::AtomicLoad16,
            ] {
                if !target.supported() {
                    continue;
                }
                let physical = backing();
                let domain = MemoryDomain::new(
                    MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
                    vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
                    target,
                )
                .unwrap();
                let mut thread = domain.thread(Policy::default());
                let mut expected = [0x5a; SCA_BYTES];
                let written = invoke(&mut thread, GUEST_BASE, &mut expected, flags::WRITE);
                let expected_write = if target.supports(TargetCpu::Cx16) {
                    MemoryStatus::Success
                } else {
                    MemoryStatus::Unsupported
                };
                assert_eq!(written.status, expected_write as u32);
                let mut actual = [0xa5; SCA_BYTES];
                let read = invoke(&mut thread, GUEST_BASE, &mut actual, 0);
                if target.supports(TargetCpu::AtomicLoad16) {
                    assert_eq!(read.status, MemoryStatus::Success as u32);
                    assert_eq!(actual, [0; SCA_BYTES]);
                } else {
                    assert_eq!(read.status, MemoryStatus::Unsupported as u32);
                    assert_eq!(actual, [0xa5; SCA_BYTES]);
                }
            }
        }

        #[test]
        fn adjacent_views_resolve_one_atomic_quantity_before_writing() {
            let backing = backing();
            let readonly = AccessPermissions {
                writable: false,
                ..RIGHTS
            };
            let domain = domain(vec![
                view(&backing, 0, 4, RIGHTS),
                view(&backing, 4, 12, readonly),
            ]);
            let mut thread = domain.thread(Policy::default());
            let mut bytes = [0x5a; 8];
            let denied = invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE);
            assert_eq!(denied.status, MemoryStatus::Permission as u32);
            assert_eq!(denied.completed, 0);
            assert_eq!(snapshot(&backing, 8), [0; 8]);
            assert!(thread.policy.checked.is_empty());
            let mut read = [0xff; 8];
            assert_eq!(
                invoke(&mut thread, GUEST_BASE, &mut read, 0).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(read, [0; 8]);
        }

        #[test]
        fn contiguous_alias_views_share_one_native_atomic_quantity() {
            let backing = backing();
            let domain = domain(vec![
                view(&backing, 0, 4, RIGHTS),
                view(&backing, 4, 12, RIGHTS),
            ]);
            let mut thread = domain.thread(Policy::default());
            let mut bytes = [1, 2, 3, 4, 5, 6, 7, 8];
            assert_eq!(
                invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(thread.policy.checked, [(GUEST_BASE, 8)]);
            assert_eq!(snapshot(&backing, 8), bytes);
        }

        #[test]
        fn later_byte_permission_failure_preserves_completed_store_prefix() {
            let backing = backing();
            let readonly = AccessPermissions {
                writable: false,
                ..RIGHTS
            };
            let domain = domain(vec![
                view(&backing, 0, SCA_BYTES, RIGHTS),
                view(&backing, SCA_BYTES, SCA_BYTES, readonly),
            ]);
            let mut thread = domain.thread(Policy::default());
            let mut bytes = [0x36, 0x79];
            let result = invoke(
                &mut thread,
                GUEST_BASE + (SCA_BYTES - 1) as u64,
                &mut bytes,
                flags::WRITE,
            );
            assert_eq!(result.status, MemoryStatus::Permission as u32);
            assert_eq!(result.fault_kind, result.status);
            assert_eq!(result.fault_address, GUEST_BASE + SCA_BYTES as u64);
            assert_eq!(result.fault_pc, TEST_PC);
            assert_eq!(result.completed, 1);
            let actual = snapshot(&backing, SCA_BYTES + 1);
            assert_eq!(actual[SCA_BYTES - 1], 0x36);
            assert_eq!(actual[SCA_BYTES], 0);
            assert_eq!(
                thread.policy.checked,
                [(GUEST_BASE + (SCA_BYTES - 1) as u64, 1)]
            );
        }

        #[test]
        fn denied_later_read_only_changes_private_staging_prefix() {
            let backing = backing();
            let noaccess = AccessPermissions {
                readable: false,
                writable: false,
                executable: false,
            };
            let domain = domain(vec![
                view(&backing, 0, SCA_BYTES, RIGHTS),
                view(&backing, SCA_BYTES, SCA_BYTES, noaccess),
            ]);
            let mut thread = domain.thread(Policy::default());
            let mut bytes = [0xa5; 2];
            let result = invoke(
                &mut thread,
                GUEST_BASE + (SCA_BYTES - 1) as u64,
                &mut bytes,
                0,
            );
            assert_eq!(result.status, MemoryStatus::Permission as u32);
            assert_eq!(result.completed, 1);
            assert_eq!(bytes, [0, 0xa5]);
        }

        #[test]
        fn generic_data_and_tag_entries_refuse_every_separately_owned_m0_identity() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let controls = crate::memory::policy::MemoryControls::new(
                crate::memory::policy::LowerAddressProfile::new(48, false).unwrap(),
                false,
                false,
                false,
                crate::memory::policy::TagCheckFaultMode::Ignore,
                false,
            );
            let mut thread = domain.thread(controls);
            let ordinary = MemoryRequirements {
                required_profile: profile_requirements::NATIVE_ACCESS,
                ..Default::default()
            };
            assert!(thread.prepare(ordinary).is_ok());
            assert!(thread.prepare_tag(ordinary, false).is_ok());
            let before = snapshot(&backing, STORAGE_BYTES);
            for dedicated in [
                profile_requirements::M0_DEVICE_RAM_READ64,
                profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR,
                profile_requirements::M0_DEVICE_RAM_READ64_PAIR_NO_LSE2,
                profile_requirements::M0_DEVICE_RAM_SCALAR_LOAD,
                profile_requirements::M0_DEVICE_RAM_SCALAR_STORE,
            ] {
                for generic in [0, profile_requirements::NATIVE_ACCESS] {
                    let requirements = MemoryRequirements {
                        required_profile: dedicated | generic,
                        ..Default::default()
                    };
                    assert_eq!(
                        thread.prepare(requirements).err(),
                        Some(MemoryStatus::Unsupported)
                    );
                    assert_eq!(
                        thread.prepare_tag(requirements, false).err(),
                        Some(MemoryStatus::Unsupported)
                    );
                }
            }
            assert_eq!(snapshot(&backing, STORAGE_BYTES), before);
            assert!(thread.prepare(ordinary).is_ok());
            assert!(thread.prepare_tag(ordinary, false).is_ok());
        }
    }
    mod checked_finalization {
        use super::*;

        fn reserve(
            thread: &mut MemoryThread<Policy>,
        ) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
            let access = reservation_access(&thread.domain, 0);
            thread
                .domain
                .system
                .reservations
                .load(&mut thread.reservation, &access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            access
        }

        fn fixture() -> (Arc<MemoryBacking>, Arc<MemoryDomain>, MemoryThread<Policy>) {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let thread = domain.thread(Policy::default());
            (backing, domain, thread)
        }

        #[test]
        fn checked_entry_returns_healthy_body_result() {
            let (_, _, mut thread) = fixture();
            let entry = thread.prepare(MemoryRequirements::default()).unwrap();
            // SAFETY: no native pointer is retained or accessed by this body.
            assert_eq!(unsafe { entry.with_checked_view(|_| 37) }, Ok(37));
        }

        #[test]
        fn callback_fault_clears_actual_reservation_and_preserves_fault() {
            let (backing, domain, mut thread) = fixture();
            let access = reserve(&mut thread);
            thread.policy.reject = Some(GUEST_BASE);
            let mut data = [0x7c];
            let request = MemoryRequest {
                address: GUEST_BASE,
                data: data.as_mut_ptr(),
                bytes: 1,
                flags: 0,
                pc: TEST_PC,
            };
            // SAFETY: valid synchronous ABI request and disjoint private staging.
            let result = unsafe {
                thread.with_checked_view(|context| {
                    let status = (context.callback)(context, &request);
                    (
                        status,
                        context.fault_address,
                        context.fault_pc,
                        context.completed_bytes,
                    )
                })
            };
            assert_eq!(
                result,
                Ok((MemoryStatus::TagCheck as u32, GUEST_BASE, TEST_PC, 0))
            );
            assert_eq!(data, [0x7c]);
            assert_eq!(snapshot(&backing, 1), [0]);
            assert_eq!(
                domain.system.reservations.store(
                    &mut thread.reservation,
                    &access,
                    || -> Result<(), MemoryStatus> { panic!("cleared reservation invoked store") }
                ),
                Ok(monitor::ConditionalWrite::<()>::Failed)
            );
        }

        #[test]
        fn local_alignment_fault_clears_actual_reservation() {
            let (_, domain, mut thread) = fixture();
            let access = reserve(&mut thread);
            // SAFETY: this body records a local fault without exposing ABI pointers.
            let result = unsafe {
                thread.with_checked_view(|context| {
                    context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 3);
                    (
                        context.fault_kind,
                        context.fault_address,
                        context.fault_pc,
                        context.completed_bytes,
                    )
                })
            };
            assert_eq!(
                result,
                Ok((MemoryStatus::Alignment as u32, GUEST_BASE + 1, TEST_PC, 3))
            );
            assert_eq!(
                domain.system.reservations.store(
                    &mut thread.reservation,
                    &access,
                    || -> Result<(), MemoryStatus> { panic!("local fault did not clear") }
                ),
                Ok(monitor::ConditionalWrite::<()>::Failed)
            );
        }

        #[test]
        fn post_body_health_failure_discards_result_without_rolling_back_write() {
            let (backing, domain, mut thread) = fixture();
            let mut data = [0x6b];
            let request = MemoryRequest {
                address: GUEST_BASE,
                data: data.as_mut_ptr(),
                bytes: 1,
                flags: flags::WRITE,
                pc: TEST_PC,
            };
            let mut prefix = None;
            // SAFETY: valid synchronous ABI request and disjoint private staging.
            let result = unsafe {
                thread.with_checked_view(|context| {
                    let status = (context.callback)(context, &request);
                    prefix = Some((status, context.completed_bytes));
                    domain.system.failed.store(true, Ordering::Release);
                    91
                })
            };
            assert_eq!(result, Err(MemoryStatus::Domain));
            assert_eq!(prefix, Some((MemoryStatus::Success as u32, 1)));
            assert_eq!(snapshot(&backing, 1), [0x6b]);
            assert_eq!(
                thread.prepare(MemoryRequirements::default()).err(),
                Some(MemoryStatus::Domain)
            );
        }

        #[test]
        fn local_alignment_late_failure_preserves_external_provenance() {
            let (_, domain, mut thread) = fixture();
            let mut fault = None;
            // SAFETY: this body records a local fault; it retains only copied scalars.
            let result = unsafe {
                thread.with_checked_view(|context| {
                    context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 5);
                    fault = Some((
                        context.fault_kind,
                        context.fault_address,
                        context.fault_pc,
                        context.completed_bytes,
                    ));
                    domain.system.failed.store(true, Ordering::Release);
                    72
                })
            };
            assert_eq!(result, Err(MemoryStatus::Domain));
            assert_eq!(
                fault,
                Some((MemoryStatus::Alignment as u32, GUEST_BASE + 1, TEST_PC, 5))
            );
        }

        #[test]
        fn actual_monitor_failure_during_body_is_reported_by_post_body_health() {
            let (backing, domain, mut thread) = fixture();
            reserve(&mut thread);
            let range = monitor::WriteRange::new(backing, 0, 1).unwrap();
            // SAFETY: the body uses the real writer gate, catches its deliberate panic,
            // and records a local fault; no pointers or owner borrows escape.
            let result = unsafe {
                thread.with_checked_view(|context| {
                    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _ = domain.system.reservations.with_writer(
                            &range,
                            monitor::Invalidation::OnCommit,
                            || -> Result<(), MemoryStatus> {
                                panic!("deliberate real monitor failure")
                            },
                        );
                    }));
                    assert!(failure.is_err());
                    context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 0);
                    84
                })
            };
            assert_eq!(result, Err(MemoryStatus::Domain));
            assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
        }

        #[test]
        fn malformed_fault_status_fails_finalization() {
            let (_, _, mut thread) = fixture();
            // SAFETY: deliberate invalid fault-sidecar input tests defensive handling;
            // header, callback and owner fields remain intact and no pointers escape.
            assert_eq!(
                unsafe {
                    thread.with_checked_view(|context| {
                        context.fault_kind = u32::MAX;
                        19
                    })
                },
                Err(MemoryStatus::Domain)
            );
        }

        #[test]
        fn legacy_result_does_not_assert_successful_finalization() {
            let (_, domain, mut thread) = fixture();
            // SAFETY: no pointer access or escape; this tests the documented legacy API.
            assert_eq!(
                unsafe {
                    thread.with_view(|_| {
                        domain.system.failed.store(true, Ordering::Release);
                        26
                    })
                },
                26
            );
            assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
        }
    }
    mod exclusive {
        use super::*;

        use stela_compiler::context::memory::{
            MemoryOperationClass, MemoryOrder,
            exclusive::{EXCLUSIVE_FAILED, ExclusiveData, ExclusiveOperation, ExclusiveShape},
        };

        #[derive(Default)]
        struct ExclusivePolicy {
            unavailable: bool,
            reject_tag: bool,
            checked: usize,
            validated: Option<std::sync::mpsc::Sender<()>>,
            block: Option<(std::sync::mpsc::Sender<()>, Arc<std::sync::Barrier>)>,
        }

        impl DataPolicy for ExclusivePolicy {
            fn validate_operation_execution(
                &self,
                class: MemoryOperationClass,
            ) -> Result<(), MemoryStatus> {
                if !self.unavailable && class == MemoryOperationClass::Exclusive {
                    Ok(())
                } else {
                    Err(MemoryStatus::Unsupported)
                }
            }
            fn validate_execution(&self, required: u32) -> Result<(), MemoryStatus> {
                if let Some(validated) = &self.validated {
                    validated.send(()).unwrap();
                }
                if required & !flags::KNOWN == 0 {
                    Ok(())
                } else {
                    Err(MemoryStatus::InvalidRequest)
                }
            }
            fn translate(&self, raw: u64) -> Result<u64, MemoryStatus> {
                Ok(raw)
            }
            fn check(&mut self, _access: DataAccess<'_>) -> Result<(), MemoryStatus> {
                self.checked += 1;
                if let Some((entered, release)) = self.block.take() {
                    entered.send(()).unwrap();
                    release.wait();
                }
                if self.reject_tag {
                    Err(MemoryStatus::TagCheck)
                } else {
                    Ok(())
                }
            }
        }

        fn exclusive_bound(
            domain: &Arc<MemoryDomain>,
        ) -> (
            MemoryThread<ExclusivePolicy>,
            crate::system::events::EventEndpoint,
            crate::system::events::EventDomain,
        ) {
            let events = crate::system::events::EventDomain::new();
            let endpoint = events.register(false, None).unwrap();
            let mut thread = domain.thread(ExclusivePolicy::default());
            thread.bind_events(&endpoint.producer()).unwrap();
            thread.check_event_endpoint(&endpoint).unwrap();
            (thread, endpoint, events)
        }

        fn exclusive_data(
            op: ExclusiveOperation,
            shape: ExclusiveShape,
            value: u128,
        ) -> ExclusiveData {
            ExclusiveData {
                operation: op as u32,
                order: MemoryOrder::Relaxed as u32,
                shape: shape as u32,
                status: 0,
                value: [value as u64, (value >> u64::BITS) as u64],
            }
        }

        fn exclusive_invoke(
            thread: &mut MemoryThread<ExclusivePolicy>,
            address: u64,
            bytes: u32,
            data: &mut ExclusiveData,
            extra: u32,
        ) -> (MemoryStatus, u64, u64, u64) {
            let request = MemoryRequest {
                address,
                data: std::ptr::from_mut(data).cast(),
                bytes,
                flags: flags::EXCLUSIVE | extra,
                pc: TEST_PC,
            };
            let mut observed = (MemoryStatus::Success, 0, address, TEST_PC);
            // SAFETY: an aligned private payload and valid disjoint ABI objects; the
            // fixture keeps stable coherent storage and the bound PE.
            let finalized = unsafe {
                thread.with_checked_view(|view| {
                    let status = (view.callback)(view, &request);
                    observed = (
                        MemoryStatus::from_code(status).unwrap(),
                        view.completed_bytes,
                        view.fault_address,
                        view.fault_pc,
                    );
                    observed
                })
            };
            match finalized {
                Ok(result) => result,
                Err(status) => (status, observed.1, observed.2, observed.3),
            }
        }

        fn exclusive_wait(
            endpoint: &mut crate::system::events::EventEndpoint,
            events: &crate::system::events::EventDomain,
        ) -> bool {
            use crate::system::access::{ExceptionLevel, Profile, SecurityState};
            use crate::system::events::{Context, EventInstruction, Outcome, RetireReason};
            let context = Context::new(
                Profile {
                    current_el: ExceptionLevel::El0,
                    security: SecurityState::NonSecure,
                    el2_enabled: false,
                    el3_present: false,
                },
                true,  // wfxt
                false, // twed
                false, // halted
                false, // n_twe
                false, // n_twi
            )
            .unwrap();
            let instruction = EventInstruction::decode(
                0xd503_205f,
                TEST_PC,
                &stela_compiler::GuestState::default(),
            )
            .unwrap();
            match endpoint
                .complete(
                    events,
                    instruction,
                    context,
                    false,
                    || -> Result<u64, ()> { panic!("untimed WFE") },
                )
                .unwrap()
            {
                Outcome::Retired {
                    reason: RetireReason::EventConsumed,
                    ..
                } => true,
                Outcome::Trap(_) => false,
                other => panic!("unexpected WFE {other:?}"),
            }
        }

        #[test]
        fn exclusive_service_layout_and_complete_25_matrix_reject_malformed_payloads() {
            use std::mem::{align_of, offset_of, size_of};
            use stela_compiler::context::memory::exclusive::*;
            assert_eq!(size_of::<ExclusiveData>(), EXCLUSIVE_DATA_BYTES);
            assert_eq!(align_of::<ExclusiveData>(), EXCLUSIVE_DATA_ALIGNMENT);
            assert_eq!(
                [
                    offset_of!(ExclusiveData, operation),
                    offset_of!(ExclusiveData, order),
                    offset_of!(ExclusiveData, shape),
                    offset_of!(ExclusiveData, status),
                    offset_of!(ExclusiveData, value)
                ],
                [0, 4, 8, 12, 16]
            );
            let mut count = 0;
            for op in [
                ExclusiveOperation::Load,
                ExclusiveOperation::Store,
                ExclusiveOperation::Clear,
            ] {
                for shape in [ExclusiveShape::Scalar, ExclusiveShape::Pair] {
                    for bytes in [0, 1, 2, 4, 8, 16, 32] {
                        for order in [
                            MemoryOrder::Relaxed,
                            MemoryOrder::AcquireRcpc,
                            MemoryOrder::AcquireRcsc,
                            MemoryOrder::Release,
                            MemoryOrder::AcquireRelease,
                        ] {
                            let mut data = exclusive_data(op, shape, 0);
                            data.order = order as u32;
                            let expected = if op == ExclusiveOperation::Clear {
                                bytes == 0
                                    && shape == ExclusiveShape::Scalar
                                    && order == MemoryOrder::Relaxed
                            } else {
                                shape.supports_width(bytes)
                                    && match op {
                                        ExclusiveOperation::Load => {
                                            matches!(
                                                order,
                                                MemoryOrder::Relaxed | MemoryOrder::AcquireRcsc
                                            )
                                        }
                                        ExclusiveOperation::Store => {
                                            matches!(
                                                order,
                                                MemoryOrder::Relaxed | MemoryOrder::Release
                                            )
                                        }
                                        _ => false,
                                    }
                            };
                            assert_eq!(data.validate(bytes).is_some(), expected);
                            count += usize::from(expected);
                        }
                    }
                }
            }
            assert_eq!(count, 25);
            for field in 0..6 {
                let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
                match field {
                    0 => data.operation = u32::MAX,
                    1 => data.order = u32::MAX,
                    2 => data.shape = u32::MAX,
                    3 => data.status = 1,
                    4 => data.value[0] = 1,
                    _ => data.value[1] = 1,
                }
                assert!(data.validate(4).is_none());
            }
            let mut store = exclusive_data(
                ExclusiveOperation::Store,
                ExclusiveShape::Scalar,
                1_u128 << 32,
            );
            assert!(store.validate(4).is_none());
            store.value = [0, 1];
            assert!(store.validate(8).is_none());
        }

        #[test]
        fn exclusive_service_width4_load_store_clear_and_failed_store_are_real() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let (mut thread, mut endpoint, events) = exclusive_bound(&domain);
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            let mut store = exclusive_data(
                ExclusiveOperation::Store,
                ExclusiveShape::Scalar,
                0xaabbccdd,
            );
            store.order = MemoryOrder::Release as u32;
            let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
            assert_eq!(
                (result.0, result.1, store.status),
                (MemoryStatus::Success, 4, 0)
            );
            assert_eq!(&snapshot(&backing, 4), &0xaabbccdd_u32.to_le_bytes());
            assert!(exclusive_wait(&mut endpoint, &events));
            assert!(!exclusive_wait(&mut endpoint, &events));
            load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            load.order = MemoryOrder::AcquireRcsc as u32;
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            assert_eq!(load.value, [0xaabbccdd, 0]);
            let mut clear = exclusive_data(ExclusiveOperation::Clear, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, 0, 0, &mut clear, 0).0,
                MemoryStatus::Success
            );
            assert!(!endpoint.is_set()); // local-only clear preserves the independent global mark.
            let checks = thread.policy.checked;
            store = exclusive_data(
                ExclusiveOperation::Store,
                ExclusiveShape::Scalar,
                0x12345678,
            );
            let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
            assert_eq!(
                (result.0, result.1, store.status),
                (MemoryStatus::Success, 0, EXCLUSIVE_FAILED)
            );
            assert_eq!(thread.policy.checked, checks);
            assert!(endpoint.is_set());
            assert_eq!(&snapshot(&backing, 4), &0xaabbccdd_u32.to_le_bytes());
        }

        #[test]
        fn exclusive_service_shared_same_value_aba_publication_invalidates_without_extra_owner() {
            let backing = backing();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let first = MemoryDomain::new(
                system.clone(),
                vec![(view(&backing, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
                TargetCpu::detect(),
            )
            .unwrap();
            let alias = MemoryView::new(
                backing.clone(),
                GUEST_BASE + 0x1000,
                0,
                STORAGE_BYTES,
                RIGHTS,
            )
            .unwrap();
            let second = MemoryDomain::new(
                system.clone(),
                vec![(alias, ATTRIBUTES)],
                TargetCpu::detect(),
            )
            .unwrap();
            let (mut thread, mut endpoint, events) = exclusive_bound(&first);
            for values in [&[0_u8; 4][..], &[1_u8; 4][..], &[0_u8; 4][..]] {
                let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
                assert_eq!(
                    exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                    MemoryStatus::Success
                );
                // SAFETY: source is disjoint private bytes and the shared system owns the retained raw backing.
                unsafe { system.publish(&backing, 0, values) }.unwrap();
                assert!(exclusive_wait(&mut endpoint, &events));
                let mut store =
                    exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 9);
                let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
                assert_eq!(
                    (result.0, result.1, store.status),
                    (MemoryStatus::Success, 0, 1)
                );
            }
            let mut ordinary = second.thread(Policy::default());
            let mut data = [0x73; 4];
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            assert_eq!(
                invoke(&mut ordinary, GUEST_BASE + 0x1000, &mut data, flags::WRITE).status,
                MemoryStatus::Success as u32
            );
            let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE).0,
                MemoryStatus::Success
            );
            assert_eq!(store.status, 1);
        }

        #[test]
        fn exclusive_service_pair8_packed_and_store_guest_write_only_are_supported() {
            let backing = backing();
            let alias = MemoryView::new(
                backing.clone(),
                GUEST_BASE + 0x1000,
                0,
                STORAGE_BYTES,
                AccessPermissions {
                    readable: false,
                    ..RIGHTS
                },
            )
            .unwrap();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS), alias]);
            let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Pair, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 8, &mut load, 0).0,
                MemoryStatus::Success
            );
            let value = 0x89abcdef01234567_u64;
            let mut store = exclusive_data(
                ExclusiveOperation::Store,
                ExclusiveShape::Pair,
                u128::from(value),
            );
            assert_eq!(
                exclusive_invoke(
                    &mut thread,
                    GUEST_BASE + 0x1000,
                    8,
                    &mut store,
                    flags::WRITE
                )
                .0,
                MemoryStatus::Success
            );
            assert_eq!(store.status, 0);
            assert_eq!(&snapshot(&backing, 8), &value.to_le_bytes());
            load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Pair, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 8, &mut load, 0).0,
                MemoryStatus::Success
            );
            assert_eq!(load.value, [value, 0]);
        }

        #[test]
        fn exclusive_service_faults_and_declines_preserve_all_payload_bytes() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
            for (address, flags, expected) in [
                (GUEST_BASE + 15, 0, MemoryStatus::Alignment),
                (GUEST_BASE + 0x4000, 0, MemoryStatus::Translation),
                (GUEST_BASE, flags::PAIR, MemoryStatus::InvalidRequest),
                (GUEST_BASE, flags::ATOMIC, MemoryStatus::InvalidRequest),
                (GUEST_BASE, flags::ORDERED, MemoryStatus::InvalidRequest),
            ] {
                let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
                let before = data;
                let result = exclusive_invoke(&mut thread, address, 4, &mut data, flags);
                assert_eq!(
                    (result.0, result.1, result.2, result.3),
                    (expected, 0, address, TEST_PC)
                );
                assert_eq!(data, before);
            }
            thread.policy.unavailable = true;
            let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            let before = data;
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
                MemoryStatus::Unsupported
            );
            assert_eq!(data, before);
            let req = MemoryRequirements {
                required_pointer_arithmetic: None,
                required_address_checks: Default::default(),
                required_flags: flags::EXCLUSIVE,
                required_host_caps: 0,
                required_profile:
                    stela_compiler::context::memory::profile_requirements::NATIVE_ACCESS,
                required_sp_alignment: SpAlignmentRequirement::Any,
                ..MemoryRequirements::default()
            };
            assert!(thread.prepare(req).is_err());
            thread.policy.unavailable = false;
            thread.policy.reject_tag = true;
            let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            let before = data;
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, flags::TAG_CHECKED).0,
                MemoryStatus::TagCheck
            );
            assert_eq!(data, before);
            thread.policy.reject_tag = false;
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            thread.policy.reject_tag = true;
            let mut store = exclusive_data(
                ExclusiveOperation::Store,
                ExclusiveShape::Scalar,
                0xdeadbeef,
            );
            let before = store;
            assert_eq!(
                exclusive_invoke(
                    &mut thread,
                    GUEST_BASE,
                    4,
                    &mut store,
                    flags::WRITE | flags::TAG_CHECKED
                )
                .0,
                MemoryStatus::TagCheck
            );
            assert_eq!(store, before);
            assert_eq!(snapshot(&backing, 4), [0; 4]);
            thread.policy.reject_tag = false;
            let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 9);
            let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
            assert_eq!(
                (result.0, result.1, store.status),
                (MemoryStatus::Success, 0, 1)
            );
            domain.system.failed.store(true, Ordering::Release);
            let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            let before = data;
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
                MemoryStatus::Domain
            );
            assert_eq!(data, before);
        }

        fn exclusive_joined() -> (Arc<MemoryBacking>, Arc<MemoryDomain>, Arc<MemoryView>) {
            let backing = backing();
            let second = view(&backing, 2, STORAGE_BYTES - 2, RIGHTS);
            let alias = MemoryView::new(
                backing.clone(),
                GUEST_BASE + 0x1000,
                0,
                STORAGE_BYTES,
                RIGHTS,
            )
            .unwrap();
            let domain = domain(vec![view(&backing, 0, 2, RIGHTS), second.clone(), alias]);
            (backing, domain, second)
        }

        #[test]
        fn exclusive_service_second_view_retirement_and_mapdead_gap_clear_actual_global_mark() {
            let (backing, domain, second) = exclusive_joined();
            let (mut thread, mut endpoint, events) = exclusive_bound(&domain);
            // The mapping is dead but its first-generation view is live, so the load
            // must be caught by the final retirement invalidation.
            domain
                .system
                .reservations
                .revoke_mapping(&domain.registered_views()[1].monitor)
                .unwrap();
            assert!(second.is_current());
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            assert!(!endpoint.is_set());
            domain.retire(&second).unwrap();
            assert!(exclusive_wait(&mut endpoint, &events));
            let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 7);
            assert_eq!(
                exclusive_invoke(
                    &mut thread,
                    GUEST_BASE + 0x1000,
                    4,
                    &mut store,
                    flags::WRITE
                )
                .0,
                MemoryStatus::Success
            );
            assert_eq!(store.status, 1);
            assert_eq!(snapshot(&backing, 4), [0; 4]);
            load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE + 0x1000, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            assert_eq!(domain.retire(&second), Err(MemoryStatus::InvalidRequest));
            assert!(!endpoint.is_set());
            store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 7);
            assert_eq!(
                exclusive_invoke(
                    &mut thread,
                    GUEST_BASE + 0x1000,
                    4,
                    &mut store,
                    flags::WRITE
                )
                .0,
                MemoryStatus::Success
            );
            assert_eq!(store.status, 0);
            assert_eq!(&snapshot(&backing, 4), &7_u32.to_le_bytes());
        }

        #[test]
        fn exclusive_service_stale_second_view_is_rechecked_inside_gate() {
            let (backing, domain, second) = exclusive_joined();
            let physical = domain.resolve(GUEST_BASE, 4, AccessKind::Read).unwrap();
            let access = monitor::Access::new(
                backing,
                domain.registered_views()[0].monitor.clone(),
                0,
                4,
                monitor::Shape::Scalar,
            )
            .unwrap();
            domain.retire(&second).unwrap();
            let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
            let mut native = false;
            let result = domain.system.reservations.load_with_scope(
                &mut thread.reservation,
                &access,
                monitor::ReservationScope::Global,
                || {
                    physical.check_current()?;
                    native = true;
                    Ok::<_, MemoryStatus>(())
                },
            );
            assert_eq!(
                result,
                Err(monitor::AccessError::Memory(MemoryStatus::Domain))
            );
            assert!(!native);
        }

        #[test]
        fn exclusive_service_inflight_load_refuses_retirement_until_original_finalization() {
            let (backing, domain, second) = exclusive_joined();
            let monitor = domain
                .registered_views()
                .into_iter()
                .find(|registered| Arc::ptr_eq(&registered.view, &second))
                .unwrap()
                .monitor;
            let generation = domain.generation().unwrap();
            let (mut thread, endpoint, events) = exclusive_bound(&domain);
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let release = Arc::new(std::sync::Barrier::new(2));
            thread.policy.block = Some((entered_tx, release.clone()));
            let load = std::thread::spawn(move || {
                let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
                let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0);
                (thread, endpoint, events, result)
            });
            entered_rx.recv().unwrap();
            let d = domain.clone();
            let retiring = second.clone();
            let (refusal_tx, refusal_rx) = std::sync::mpsc::channel();
            let retire = std::thread::spawn(move || {
                refusal_tx.send(d.retire(&retiring)).unwrap();
            });
            // The native borrow is still live inside the blocked callback, so service
            // admission must refuse instead of waiting on the callback's monitor gate.
            let refusal = refusal_rx.recv_timeout(std::time::Duration::from_secs(2));
            // Always release and join the load before asserting, even if a broken
            // retirement path waited on the gate.
            release.wait();
            let (mut thread, mut endpoint, events, result) = load.join().unwrap();
            retire.join().unwrap();
            assert_eq!(result.0, MemoryStatus::Success);
            assert_eq!(refusal.unwrap(), Err(MemoryStatus::Domain));
            assert!(second.is_current());
            assert!(monitor.is_live());
            assert_eq!(domain.generation().unwrap(), generation);
            assert!(!endpoint.is_set());
            // Finalization released the borrow, so the domain may now retire the view
            // and invalidate the alias reservation.
            domain.retire(&second).unwrap();
            assert!(!second.is_current());
            assert!(!monitor.is_live());
            assert_eq!(domain.generation().unwrap(), generation + 1);
            assert!(exclusive_wait(&mut endpoint, &events));
            assert!(!exclusive_wait(&mut endpoint, &events));
            let mut data = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 1);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE + 0x1000, 4, &mut data, flags::WRITE).0,
                MemoryStatus::Success
            );
            assert_eq!(data.status, 1);
            assert_eq!(snapshot(&backing, 4), [0; 4]);
        }

        #[test]
        fn exclusive_service_contended_width4_has_one_actual_native_winner() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let mut joins = Vec::new();
            for value in [0x12345678_u128, 0x87654321] {
                let (mut thread, endpoint, events) = exclusive_bound(&domain);
                let barrier = barrier.clone();
                joins.push(std::thread::spawn(move || {
                    let _owners = (endpoint, events);
                    let mut load =
                        exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
                    assert_eq!(
                        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                        MemoryStatus::Success
                    );
                    barrier.wait();
                    let mut store =
                        exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, value);
                    let result =
                        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
                    assert_eq!(result.0, MemoryStatus::Success);
                    store.status
                }));
            }
            let statuses = joins
                .into_iter()
                .map(|j| j.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(statuses.iter().filter(|&&s| s == 0).count(), 1);
            let value = u32::from_le_bytes(snapshot(&backing, 4).try_into().unwrap());
            assert!([0x12345678, 0x87654321].contains(&value));
        }

        #[test]
        fn exclusive_service_permission_and_raw_payload_fail_before_any_effect() {
            let backing = backing();
            let denied = AccessPermissions {
                writable: false,
                ..RIGHTS
            };
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, denied)]);
            let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
            let mut store = exclusive_data(
                ExclusiveOperation::Store,
                ExclusiveShape::Scalar,
                0xfeedbeef,
            );
            let before = store;
            let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
            assert_eq!((result.0, result.1), (MemoryStatus::Permission, 0));
            assert_eq!(store, before);
            assert_eq!(thread.policy.checked, 0);
            for index in 0..6 {
                let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
                match index {
                    0 => data.operation = u32::MAX,
                    1 => data.order = u32::MAX,
                    2 => data.shape = u32::MAX,
                    3 => data.status = 1,
                    4 => data.value[0] = 1,
                    _ => data.value[1] = 1,
                }
                let before = data;
                assert_eq!(
                    exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
                    MemoryStatus::InvalidRequest
                );
                assert_eq!(data, before);
            }
            let mut clear = exclusive_data(ExclusiveOperation::Clear, ExclusiveShape::Scalar, 0);
            let before = clear;
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 0, &mut clear, 0).0,
                MemoryStatus::InvalidRequest
            );
            assert_eq!(clear, before);
            assert_eq!(snapshot(&backing, STORAGE_BYTES), vec![0; STORAGE_BYTES]);
        }

        #[test]
        fn exclusive_service_poisoned_domain_refuses_retirement_before_mapping_effects() {
            let (backing, domain, second) = exclusive_joined();
            let monitor = domain
                .registered_views()
                .into_iter()
                .find(|registered| Arc::ptr_eq(&registered.view, &second))
                .unwrap()
                .monitor;
            let generation = domain.generation().unwrap();
            let (mut thread, endpoint, _events) = exclusive_bound(&domain);
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            assert!(!endpoint.is_set());
            let before = snapshot(&backing, 4);
            domain.system.failed.store(true, Ordering::Release);
            assert_eq!(domain.retire(&second), Err(MemoryStatus::Domain));
            assert!(second.is_current());
            assert!(monitor.is_live());
            assert_eq!(domain.state.lock().unwrap().snapshot.generation, generation);
            assert!(!endpoint.is_set());
            assert_eq!(domain.retire(&second), Err(MemoryStatus::Domain));
            // A failed domain admits neither native execution nor service mutation, and
            // keeps its storage.
            assert!(domain.check_execution().is_err());
            assert!(domain.execution_loan().is_err());
            let mut declined = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            let untouched = declined;
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut declined, 0).0,
                MemoryStatus::Domain
            );
            assert_eq!(declined, untouched);
            assert_eq!(snapshot(&backing, 4), before);
            assert!(!endpoint.is_set());
        }

        #[test]
        fn exclusive_service_shifted_relative_erg_geometry_declines_before_prefix_only_for_transfers()
         {
            let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
            // SAFETY: the owner keeps the whole allocation, including the prefix.
            let raw = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            let owner = Arc::new(Storage {
                pointer: raw,
                layout,
            });
            // SAFETY: shifted extent is live inside the real allocation and lifetime owner.
            let physical = unsafe {
                MemoryBacking::new(
                    NonNull::new(raw.as_ptr().add(8)).unwrap(),
                    STORAGE_BYTES - 8,
                    RIGHTS,
                    owner,
                )
            }
            .unwrap();
            let mapping =
                MemoryView::new(physical, GUEST_BASE + 8, 0, STORAGE_BYTES - 8, RIGHTS).unwrap();
            let domain = domain(vec![mapping]);
            let mut thread = domain.thread(ExclusivePolicy::default());
            let req = MemoryRequirements {
                required_pointer_arithmetic: None,
                required_address_checks: Default::default(),
                required_flags: flags::EXCLUSIVE,
                required_host_caps: 0,
                required_profile:
                    stela_compiler::context::memory::profile_requirements::NATIVE_ACCESS,
                required_sp_alignment: SpAlignmentRequirement::Any,
                ..MemoryRequirements::default()
            };
            assert!(matches!(
                thread.prepare(req),
                Err(MemoryStatus::Unsupported)
            ));
            let ordinary = MemoryRequirements {
                required_flags: 0,
                ..req
            };
            assert!(thread.prepare(ordinary).is_ok());
            let clear = MemoryRequirements {
                required_profile: 0,
                ..req
            };
            assert!(thread.prepare(clear).is_ok());
            assert_eq!(thread.policy.checked, 0);
        }

        #[test]
        fn exclusive_service_callback_fault_late_failure_cannot_escape_checked_finalization() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let (mut thread, endpoint, events) = exclusive_bound(&domain);
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            let (held_tx, held_rx) = std::sync::mpsc::channel();
            let release = Arc::new(std::sync::Barrier::new(2));
            let d = domain.clone();
            let release_writer = release.clone();
            let b = backing.clone();
            let writer = std::thread::spawn(move || {
                let range = monitor::WriteRange::new(b, 0, 4).unwrap();
                d.system
                    .reservations
                    .with_writer(&range, monitor::Invalidation::OnCommit, || {
                        held_tx.send(()).unwrap();
                        release_writer.wait();
                        Ok::<_, MemoryStatus>(())
                    })
                    .unwrap();
            });
            held_rx.recv().unwrap();
            let (validated_tx, validated_rx) = std::sync::mpsc::channel();
            thread.policy.validated = Some(validated_tx);
            let fault = std::thread::spawn(move || {
                let _owners = (endpoint, events);
                let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
                let before = data;
                let result = exclusive_invoke(&mut thread, GUEST_BASE + 15, 4, &mut data, 0);
                (result, data, before)
            });
            // Failure becomes visible after the callback's initial owner health check,
            // while the old reservation's cleanup is behind the real writer gate.
            validated_rx.recv().unwrap();
            domain.system.failed.store(true, Ordering::Release);
            release.wait();
            writer.join().unwrap();
            let (result, data, before) = fault.join().unwrap();
            assert_eq!(
                (result.0, result.1, result.2, result.3),
                (MemoryStatus::Domain, 0, GUEST_BASE + 15, TEST_PC)
            );
            assert_eq!(data, before);
            assert_eq!(snapshot(&backing, 4), [0; 4]);
        }

        #[test]
        fn exclusive_service_local_sp_fault_finalization_failure_discards_callback_result() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            let mut original = None;
            // SAFETY: this source-bound local-emitter analogue writes only diagnostic
            // fields; it does not invoke native code or lend guest RAM references.
            let result = unsafe {
                thread.with_checked_view(|view| {
                    view.record(MemoryStatus::StackAlignment, GUEST_BASE + 1, TEST_PC, 0);
                    original = Some((
                        view.fault_kind,
                        view.fault_address,
                        view.fault_pc,
                        view.completed_bytes,
                    ));
                    domain.system.failed.store(true, Ordering::Release);
                    42_u32
                })
            };
            assert_eq!(result, Err(MemoryStatus::Domain));
            assert_eq!(
                original,
                Some((
                    MemoryStatus::StackAlignment as u32,
                    GUEST_BASE + 1,
                    TEST_PC,
                    0
                ))
            );
            assert_eq!(snapshot(&backing, 4), [0; 4]);
        }

        #[test]
        fn exclusive_service_dedicated_tag_entry_cannot_bypass_typed_class_preflight() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let controls = crate::memory::policy::MemoryControls::new(
                crate::memory::policy::LowerAddressProfile::new(48, false).unwrap(),
                false,
                false,
                false,
                crate::memory::policy::TagCheckFaultMode::Ignore,
                false,
            );
            let mut thread = domain.thread(controls);
            for class in [
                flags::ATOMIC,
                flags::ORDERED,
                flags::EXCLUSIVE,
                flags::ATOMIC | flags::ORDERED | flags::EXCLUSIVE,
            ] {
                let req = MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: class,
                    required_host_caps: 0,
                    required_profile: 0,
                    required_sp_alignment: SpAlignmentRequirement::Any,
                    ..MemoryRequirements::default()
                };
                assert!(matches!(
                    thread.prepare_tag(req, false),
                    Err(MemoryStatus::InvalidRequest)
                ));
            }
        }
    }
    mod quantities {
        use super::*;

        #[test]
        fn crossing_quadword_split_requires_explicit_predicated_sve_or_asimd() {
            for descriptor in [
                0,
                flags::SME,
                flags::SME | flags::SVE_PREDICATED,
                flags::SVE_PREDICATED,
                flags::ASIMD,
            ] {
                let backing = backing();
                let readonly = AccessPermissions {
                    writable: false,
                    ..RIGHTS
                };
                let domain = domain(vec![
                    view(&backing, 0, 11, RIGHTS),
                    view(&backing, 11, 21, readonly),
                ]);
                let mut thread = domain.thread(Policy::default());
                let mut bytes = [0x63; 16];
                let result = invoke(
                    &mut thread,
                    GUEST_BASE + 8,
                    &mut bytes,
                    flags::WRITE | descriptor,
                );
                let special = descriptor & flags::SME == 0
                    && descriptor & (flags::SVE_PREDICATED | flags::ASIMD) != 0;
                assert_eq!(result.status, MemoryStatus::Permission as u32);
                assert_eq!(result.completed, if special { 0 } else { 3 });
                assert_eq!(
                    result.fault_address,
                    GUEST_BASE + if special { 8 } else { 11 }
                );
                assert_eq!(
                    &snapshot(&backing, 16)[8..11],
                    if special { &[0; 3] } else { &[0x63; 3] }
                );
            }
        }

        #[test]
        fn raw_reached_part_translation_precedes_permissions_and_retains_prefix() {
            use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
            for tbi in [false, true] {
                let backing = backing();
                let denied = AccessPermissions {
                    writable: false,
                    ..RIGHTS
                };
                let views = vec![
                    MemoryView::new(backing.clone(), 0xfff0, 0, 16, RIGHTS).unwrap(),
                    MemoryView::new(backing.clone(), 0x10000, 16, 16, denied).unwrap(),
                ];
                let domain = domain(views);
                let controls = MemoryControls::new(
                    LowerAddressProfile::new(16, tbi).unwrap(),
                    false,
                    false,
                    false,
                    TagCheckFaultMode::Ignore,
                    false,
                );
                let mut thread = domain.thread(controls);
                let mut staging = [0x7c; 2];
                let raw = 0xffff | if tbi { 0xa500_0000_0000_0000 } else { 0 };
                let request = MemoryRequest {
                    address: raw,
                    data: staging.as_mut_ptr(),
                    bytes: 2,
                    flags: flags::WRITE,
                    pc: TEST_PC,
                };
                unsafe {
                    thread.with_view(|context| {
                        assert_eq!(
                            (context.callback)(context, &request),
                            MemoryStatus::Translation as u32
                        );
                        assert_eq!(context.completed_bytes, 1);
                        assert_eq!(context.fault_address, raw + 1);
                        assert_eq!(context.fault_pc, TEST_PC);
                    });
                }
                assert_eq!(snapshot(&backing, 17)[15..17], [0x7c, 0]);
            }
        }

        #[test]
        fn fault_settlement_preserves_declines_and_clears_selected_architectural_faults() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Policy::default());
            let access = reservation_access(&domain, 0);
            for status in [
                MemoryStatus::Translation,
                MemoryStatus::Permission,
                MemoryStatus::Alignment,
                MemoryStatus::StackAlignment,
                MemoryStatus::TagCheck,
                MemoryStatus::Unsupported,
                MemoryStatus::InvalidRequest,
            ] {
                domain
                    .system
                    .reservations
                    .load(&mut thread.reservation, &access, || {
                        Ok::<_, MemoryStatus>(())
                    })
                    .unwrap();
                thread.settle_fault(status).unwrap();
                let outcome = domain
                    .system
                    .reservations
                    .store(&mut thread.reservation, &access, || {
                        Ok::<_, MemoryStatus>(())
                    })
                    .unwrap();
                assert_eq!(
                    outcome,
                    if is_guest_fault(status as u32) {
                        monitor::ConditionalWrite::Failed
                    } else {
                        monitor::ConditionalWrite::Stored(())
                    }
                );
            }
        }

        #[test]
        fn sme_crossing_prefix_invalidates_only_bytes_actually_written() {
            let backing = backing();
            let readonly = AccessPermissions {
                writable: false,
                ..RIGHTS
            };
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let domain = MemoryDomain::new(
                system.clone(),
                vec![
                    (view(&backing, 0, 11, RIGHTS), ATTRIBUTES),
                    (view(&backing, 11, 21, readonly), ATTRIBUTES),
                ],
                TargetCpu::detect(),
            )
            .unwrap();
            let mut writer = domain.thread(Policy::default());
            let mut touched = domain.thread(Policy::default());
            let mut untouched = domain.thread(Policy::default());
            let touched_access = reservation_access(&domain, 10);
            let untouched_access = monitor::Access::new(
                backing.clone(),
                domain.registered_views()[1].monitor.clone(),
                16,
                1,
                monitor::Shape::Scalar,
            )
            .unwrap();
            system
                .reservations
                .load(&mut touched.reservation, &touched_access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            system
                .reservations
                .load(&mut untouched.reservation, &untouched_access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            let mut bytes = [0x5e; 16];
            let result = invoke(
                &mut writer,
                GUEST_BASE + 8,
                &mut bytes,
                flags::WRITE | flags::SME,
            );
            assert_eq!(result.completed, 3);
            assert_eq!(
                system
                    .reservations
                    .store(&mut touched.reservation, &touched_access, || Ok::<
                        _,
                        MemoryStatus,
                    >(
                        ()
                    ))
                    .unwrap(),
                monitor::ConditionalWrite::Failed
            );
            assert_eq!(
                system
                    .reservations
                    .store(&mut untouched.reservation, &untouched_access, || Ok::<
                        _,
                        MemoryStatus,
                    >(
                        ()
                    ))
                    .unwrap(),
                monitor::ConditionalWrite::Stored(())
            );
        }

        #[test]
        fn each_wrapping_raw_part_is_translated_in_its_own_regime() {
            struct WrappingPolicy;
            impl DataPolicy for WrappingPolicy {
                fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
                    Ok(())
                }
                fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
                    Ok(address & 0xffff)
                }
                fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
                    Ok(())
                }
            }
            let backing = backing();
            let domain = domain(vec![
                MemoryView::new(backing.clone(), 0xfff0, 0, 16, RIGHTS).unwrap(),
                MemoryView::new(backing.clone(), 0, 16, 16, RIGHTS).unwrap(),
            ]);
            let mut thread = domain.thread(WrappingPolicy);
            let mut staging = [0x2d, 0x7b];
            let request = MemoryRequest {
                address: u64::MAX,
                data: staging.as_mut_ptr(),
                bytes: 2,
                flags: flags::WRITE,
                pc: TEST_PC,
            };
            unsafe {
                thread.with_view(|context| {
                    assert_eq!(
                        (context.callback)(context, &request),
                        MemoryStatus::Success as u32
                    );
                    assert_eq!(context.completed_bytes, 2);
                });
            }
            assert_eq!(snapshot(&backing, 17)[15..17], staging);
        }

        #[test]
        fn local_stack_fault_keeps_named_provenance_and_clears_selected_reservation() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Policy::default());
            let access = reservation_access(&domain, 0);
            domain
                .system
                .reservations
                .load(&mut thread.reservation, &access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            unsafe {
                thread.with_view(|context| {
                    context.record(MemoryStatus::StackAlignment, GUEST_BASE + 1, TEST_PC, 0);
                    assert_eq!(context.fault_kind, 8);
                    assert_eq!(context.fault_address, GUEST_BASE + 1);
                    assert_eq!(context.fault_pc, TEST_PC);
                    assert_eq!(context.completed_bytes, 0);
                });
            }
            assert_eq!(
                domain
                    .system
                    .reservations
                    .store(&mut thread.reservation, &access, || Ok::<_, MemoryStatus>(
                        ()
                    )),
                Ok(monitor::ConditionalWrite::Failed)
            );
            assert_eq!(snapshot(&backing, 1), [0]);
        }

        #[test]
        fn exact_pair_and_asimd_quantity_table_preserves_mem_branch_order() {
            let cases: &[(usize, usize, u32, &[usize], bool)] = &[
                (0, 16, flags::ASIMD, &[8, 8], false),
                (8, 16, flags::ASIMD, &[8, 8], false),
                (0, 16, flags::ASIMD | flags::PAIR, &[8, 8], true),
                (8, 16, flags::ASIMD | flags::PAIR, &[8, 8], true),
                (0, 32, flags::ASIMD | flags::PAIR, &[8, 8, 8, 8], false),
                (8, 32, flags::ASIMD | flags::PAIR, &[8, 8, 8, 8], false),
                (4, 8, flags::PAIR, &[8], true),
                (12, 8, flags::PAIR, &[4, 4], false),
                (0, 16, flags::PAIR, &[16], true),
                (8, 16, flags::PAIR, &[8, 8], false),
                (0, 16, flags::SVE_PREDICATED, &[16], false),
                (8, 16, flags::SVE_PREDICATED, &[8, 8], false),
                (8, 16, flags::SME, &[1; 16], false),
            ];
            for (residue, bytes, descriptor, widths, retains_pair) in cases {
                let parts = AccessParts::new(GUEST_BASE + *residue as u64, *bytes, *descriptor)
                    .collect::<Vec<_>>();
                assert_eq!(parts.iter().map(|p| p.bytes).collect::<Vec<_>>(), *widths);
                assert!(
                    parts
                        .iter()
                        .all(|p| (p.flags & flags::PAIR != 0) == *retains_pair)
                );
                assert!(
                    parts
                        .iter()
                        .all(|p| (p.address as usize & 15) + p.bytes <= 16)
                );
            }
            for (bytes, descriptor) in [
                (16, flags::ASIMD),
                (16, flags::ASIMD | flags::PAIR),
                (32, flags::ASIMD | flags::PAIR),
                (16, flags::PAIR),
            ] {
                for residue in [1, 3, 5, 7, 9, 11, 13, 15] {
                    let parts = AccessParts::new(GUEST_BASE + residue, bytes, descriptor)
                        .collect::<Vec<_>>();
                    assert_eq!(parts.len(), bytes);
                    assert!(parts.iter().all(|p| p.bytes == 1 && p.flags == descriptor));
                }
            }
        }

        #[test]
        fn aligned_asimd_first_split_preserves_store_prefix_while_sve_lse2_combines() {
            for descriptor in [
                flags::ASIMD,
                flags::ASIMD | flags::PAIR,
                flags::SVE_PREDICATED,
                flags::PAIR,
            ] {
                let physical = backing();
                let readonly = AccessPermissions {
                    writable: false,
                    ..RIGHTS
                };
                let domain = domain(vec![
                    view(&physical, 0, 8, RIGHTS),
                    view(&physical, 8, 24, readonly),
                ]);
                let mut thread = domain.thread(Policy::default());
                let mut data = [0x57; 16];
                let outcome = invoke(
                    &mut thread,
                    GUEST_BASE,
                    &mut data,
                    flags::WRITE | descriptor,
                );
                let prefix = if descriptor & flags::ASIMD != 0 { 8 } else { 0 };
                assert_eq!(outcome.status, MemoryStatus::Permission as u32);
                assert_eq!(outcome.completed, prefix);
                assert_eq!(outcome.fault_address, GUEST_BASE + prefix);
                assert_eq!(outcome.fault_pc, TEST_PC);
                assert_eq!(
                    &snapshot(&physical, 16)[..8],
                    if prefix == 8 { &[0x57; 8] } else { &[0; 8] }
                );
                if prefix == 8 {
                    assert_eq!(thread.policy.checked_flags, [flags::WRITE | descriptor]);
                }
            }
        }

        #[test]
        fn pair_half_quantity_is_checked_before_any_byte_and_not_family_split() {
            for (address, width, prefix_boundary) in
                [(GUEST_BASE + 8, 16, 11), (GUEST_BASE + 12, 8, 14)]
            {
                let physical = backing();
                let readonly = AccessPermissions {
                    writable: false,
                    ..RIGHTS
                };
                let domain = domain(vec![
                    view(&physical, 0, prefix_boundary, RIGHTS),
                    view(&physical, prefix_boundary, 32 - prefix_boundary, readonly),
                ]);
                let mut thread = domain.thread(Policy::default());
                let mut data = vec![0x38; width];
                let result = invoke(&mut thread, address, &mut data, flags::WRITE | flags::PAIR);
                assert_eq!(result.status, MemoryStatus::Permission as u32);
                assert_eq!(result.completed, 0);
                assert_eq!(result.fault_address, address);
                assert!(snapshot(&physical, 32).iter().all(|b| *b == 0));
            }
        }

        #[test]
        fn every_wide_asimd_residue_executes_on_declared_baseline_without_wide_host_caps() {
            for bytes in [16, 32] {
                for residue in 0..16 {
                    let physical = backing();
                    let domain = MemoryDomain::new(
                        MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
                        vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
                        TargetCpu::Baseline,
                    )
                    .unwrap();
                    let mut thread = domain.thread(Policy::default());
                    let descriptor = flags::ASIMD | if bytes == 32 { flags::PAIR } else { 0 };
                    let address = GUEST_BASE + 16 + residue as u64;
                    let mut expected = (0..bytes).map(|i| (i + 1) as u8).collect::<Vec<_>>();
                    let written = invoke(
                        &mut thread,
                        address,
                        &mut expected,
                        descriptor | flags::WRITE,
                    );
                    assert_eq!(written.status, MemoryStatus::Success as u32);
                    assert_eq!(written.completed, bytes as u64);
                    let mut actual = vec![0xa5; bytes];
                    assert_eq!(
                        invoke(&mut thread, address, &mut actual, descriptor).status,
                        MemoryStatus::Success as u32
                    );
                    assert_eq!(actual, expected);
                    let mut full = vec![0; STORAGE_BYTES];
                    full[16 + residue..16 + residue + bytes].copy_from_slice(&expected);
                    assert_eq!(snapshot(&physical, STORAGE_BYTES), full);
                }
            }
        }

        #[test]
        fn asimd32_prefix_and_descriptor_clear_do_not_touch_later_reservation_granules() {
            let physical = backing();
            let readonly = AccessPermissions {
                writable: false,
                ..RIGHTS
            };
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let domain = MemoryDomain::new(
                system.clone(),
                vec![
                    (view(&physical, 0, 8, RIGHTS), ATTRIBUTES),
                    (view(&physical, 8, STORAGE_BYTES - 8, readonly), ATTRIBUTES),
                ],
                TargetCpu::Baseline,
            )
            .unwrap();
            let mut writer = domain.thread(Policy::default());
            let mut touched = domain.thread(Policy::default());
            let mut later = domain.thread(Policy::default());
            let first = reservation_access(&domain, 0);
            let future = monitor::Access::new(
                physical.clone(),
                domain.registered_views()[1].monitor.clone(),
                16,
                1,
                monitor::Shape::Scalar,
            )
            .unwrap();
            system
                .reservations
                .load(&mut touched.reservation, &first, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            system
                .reservations
                .load(
                    &mut later.reservation,
                    &future,
                    || Ok::<_, MemoryStatus>(()),
                )
                .unwrap();
            let mut data = [0x75; 32];
            let result = invoke(
                &mut writer,
                GUEST_BASE,
                &mut data,
                flags::ASIMD | flags::PAIR | flags::WRITE,
            );
            assert_eq!(result.status, MemoryStatus::Permission as u32);
            assert_eq!(result.completed, 8);
            assert_eq!(result.fault_address, GUEST_BASE + 8);
            assert_eq!(writer.policy.checked_flags, [flags::ASIMD | flags::WRITE]);
            assert_eq!(
                system
                    .reservations
                    .store(&mut touched.reservation, &first, || Ok::<_, MemoryStatus>(
                        ()
                    ))
                    .unwrap(),
                monitor::ConditionalWrite::Failed
            );
            assert_eq!(
                system
                    .reservations
                    .store(
                        &mut later.reservation,
                        &future,
                        || Ok::<_, MemoryStatus>(())
                    )
                    .unwrap(),
                monitor::ConditionalWrite::Stored(())
            );
            assert!(
                snapshot(&physical, STORAGE_BYTES)[8..]
                    .iter()
                    .all(|b| *b == 0)
            );
        }

        #[test]
        fn small_combined_pair_read_still_requires_atomic16_when_it_crosses_host8() {
            let physical = backing();
            let domain = MemoryDomain::new(
                MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
                vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
                TargetCpu::Baseline,
            )
            .unwrap();
            let mut thread = domain.thread(Policy::default());
            let mut data = [0xa5; 8];
            let result = invoke(&mut thread, GUEST_BASE + 4, &mut data, flags::PAIR);
            assert_eq!(result.status, MemoryStatus::Unsupported as u32);
            assert_eq!(result.completed, 0);
            assert_eq!(data, [0xa5; 8]);
        }
    }
    mod reservations {
        use super::*;

        #[test]
        fn controlled_tag_fault_clears_other_reservation_and_releases_writer_gate() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut observer = domain.thread(Policy::default());
            let access = reservation_access(&domain, 0);
            domain
                .system
                .reservations
                .load(&mut observer.reservation, &access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            let mut writer = domain.thread(Policy {
                reject: Some(GUEST_BASE),
                ..Policy::default()
            });
            let mut bytes = [0x6b];
            let fault = invoke(
                &mut writer,
                GUEST_BASE,
                &mut bytes,
                flags::WRITE | flags::TAG_CHECKED,
            );
            assert_eq!(fault.status, MemoryStatus::TagCheck as u32);
            assert_eq!(fault.completed, 0);
            assert_eq!(snapshot(&backing, 1), [0]);
            let conditional = domain
                .system
                .reservations
                .store(&mut observer.reservation, &access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            assert_eq!(conditional, monitor::ConditionalWrite::Failed);
            writer.policy_mut().reject = None;
            assert_eq!(
                invoke(&mut writer, GUEST_BASE, &mut bytes, flags::WRITE).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(snapshot(&backing, 1), bytes);
            assert!(domain.check_execution().is_ok());
        }

        #[test]
        fn retirement_rejects_access_and_invalidates_reserved_mapping() {
            let backing = backing();
            let mapping = view(&backing, 0, STORAGE_BYTES, RIGHTS);
            let domain = domain(vec![Arc::clone(&mapping)]);
            let mut thread = domain.thread(Policy::default());
            let access = reservation_access(&domain, 0);
            domain
                .system
                .reservations
                .load(&mut thread.reservation, &access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            domain.retire(&mapping).unwrap();
            assert!(!mapping.is_current());
            assert!(matches!(
                domain
                    .system
                    .reservations
                    .store(&mut thread.reservation, &access, || Ok::<_, MemoryStatus>(
                        ()
                    )),
                Err(monitor::AccessError::Monitor(
                    monitor::MonitorError::DeadMapping
                ))
            ));
            let mut bytes = [0];
            assert_eq!(
                invoke(&mut thread, GUEST_BASE, &mut bytes, 0).status,
                MemoryStatus::Translation as u32
            );
        }

        #[test]
        fn discontiguous_physical_views_and_overlapping_guest_views_decline() {
            let backing = backing();
            let first = view(&backing, 0, 4, RIGHTS);
            let discontiguous =
                MemoryView::new(Arc::clone(&backing), GUEST_BASE + 4, 16, 12, RIGHTS).unwrap();
            let domain = domain(vec![Arc::clone(&first), discontiguous]);
            let mut thread = domain.thread(Policy::default());
            let mut bytes = [0x3d; 8];
            assert_eq!(
                invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE).status,
                MemoryStatus::Unsupported as u32
            );
            assert_eq!(snapshot(&backing, 8), [0; 8]);
            assert!(
                MemoryDomain::new(
                    MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
                    vec![
                        (first, ATTRIBUTES),
                        (view(&backing, 2, 4, RIGHTS), ATTRIBUTES)
                    ],
                    TargetCpu::Baseline,
                )
                .is_err()
            );
        }

        fn in_system(system: &Arc<MemorySystem>, views: Vec<Arc<MemoryView>>) -> Arc<MemoryDomain> {
            MemoryDomain::new(
                Arc::clone(system),
                views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
                TargetCpu::detect(),
            )
            .unwrap()
        }

        #[test]
        fn shared_backing_writer_invalidates_reservations_across_address_spaces() {
            let physical = backing();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let first = in_system(&system, vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
            let alias_base = GUEST_BASE * 2;
            let alias =
                MemoryView::new(Arc::clone(&physical), alias_base, 0, STORAGE_BYTES, RIGHTS)
                    .unwrap();
            let second = in_system(&system, vec![alias]);
            let mut observer = first.thread(Policy::default());
            let access = reservation_access(&first, 0);
            system
                .reservations
                .load(&mut observer.reservation, &access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            let mut writer = second.thread(Policy::default());
            let mut bytes = [0x43];
            assert_eq!(
                invoke(&mut writer, alias_base, &mut bytes, flags::WRITE).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(
                system
                    .reservations
                    .store(
                        &mut observer.reservation,
                        &access,
                        || Ok::<_, MemoryStatus>(())
                    )
                    .unwrap(),
                monitor::ConditionalWrite::Failed
            );
            assert_eq!(snapshot(&physical, 1), bytes);
        }

        #[test]
        fn conflicting_system_cannot_register_a_live_physical_backing() {
            let physical = backing();
            let first_system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let second_system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
            let first = in_system(&first_system, vec![Arc::clone(&mapping)]);
            let same_system_snapshot = in_system(&first_system, vec![Arc::clone(&mapping)]);
            assert!(matches!(
                MemoryDomain::new(
                    Arc::clone(&second_system),
                    vec![(Arc::clone(&mapping), ATTRIBUTES)],
                    TargetCpu::Baseline
                ),
                Err(MemoryStatus::Domain)
            ));
            drop(first_system);
            drop(first);
            assert!(matches!(
                MemoryDomain::new(
                    Arc::clone(&second_system),
                    vec![(Arc::clone(&mapping), ATTRIBUTES)],
                    TargetCpu::Baseline
                ),
                Err(MemoryStatus::Domain)
            ));
            drop(same_system_snapshot);
            assert!(
                MemoryDomain::new(
                    second_system,
                    vec![(mapping, ATTRIBUTES)],
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }

        #[test]
        fn retirement_reaches_reservations_from_every_snapshot_of_the_same_view() {
            let physical = backing();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
            let first = in_system(&system, vec![Arc::clone(&mapping)]);
            let second = in_system(&system, vec![Arc::clone(&mapping)]);
            let alias = in_system(&system, vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
            let mut observer = second.thread(Policy::default());
            let original = reservation_access(&second, 0);
            system
                .reservations
                .load(&mut observer.reservation, &original, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            first.retire(&mapping).unwrap();
            let alias_access = reservation_access(&alias, 0);
            let result = system
                .reservations
                .store(&mut observer.reservation, &alias_access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            assert_eq!(result, monitor::ConditionalWrite::Failed);
        }

        #[test]
        fn one_view_generation_cannot_change_attributes_between_live_snapshots() {
            let physical = backing();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
            let original = in_system(&system, vec![Arc::clone(&mapping)]);
            let changed = MappingAttributes {
                tagged: !ATTRIBUTES.tagged,
                ..ATTRIBUTES
            };
            assert!(matches!(
                MemoryDomain::new(
                    Arc::clone(&system),
                    vec![(Arc::clone(&mapping), changed)],
                    TargetCpu::Baseline
                ),
                Err(MemoryStatus::InvalidRequest)
            ));
            let unchanged = in_system(&system, vec![mapping]);
            assert!(Arc::ptr_eq(
                &original.registered_views()[0].monitor,
                &unchanged.registered_views()[0].monitor
            ));
        }

        #[test]
        fn retiring_an_unregistered_view_declines_without_mutation() {
            let physical = backing();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
            let original = in_system(&system, vec![mapping]);
            let unregistered = view(&physical, 0, STORAGE_BYTES, RIGHTS);
            assert_eq!(
                original.retire(&unregistered),
                Err(MemoryStatus::InvalidRequest)
            );
            assert!(unregistered.is_current());
            assert!(original.registered_views()[0].view.is_current());
        }

        #[test]
        fn platform_and_abi_declines_preserve_existing_local_reservation() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Policy::default());
            let access = reservation_access(&domain, 0);
            for unavailable in [true, false] {
                domain
                    .system
                    .reservations
                    .load(&mut thread.reservation, &access, || {
                        Ok::<_, MemoryStatus>(())
                    })
                    .unwrap();
                thread.policy_mut().unavailable = unavailable;
                let mut staging = [0x7b; 3];
                let result = invoke(&mut thread, GUEST_BASE, &mut staging, flags::WRITE);
                assert_eq!(
                    result.status,
                    if unavailable {
                        MemoryStatus::Unsupported
                    } else {
                        MemoryStatus::InvalidRequest
                    } as u32
                );
                assert_eq!(result.completed, 0);
                assert_eq!(snapshot(&backing, 3), [0; 3]);
                thread.policy_mut().unavailable = false;
                assert_eq!(
                    domain
                        .system
                        .reservations
                        .store(&mut thread.reservation, &access, || Ok::<_, MemoryStatus>(
                            ()
                        )),
                    Ok(monitor::ConditionalWrite::Stored(()))
                );
            }
        }

        #[test]
        fn local_native_fault_record_clears_reservation_at_invocation_return() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Policy::default());
            let access = reservation_access(&domain, 0);
            domain
                .system
                .reservations
                .load(&mut thread.reservation, &access, || {
                    Ok::<_, MemoryStatus>(())
                })
                .unwrap();
            // SAFETY: the callback only records a local fault, retaining no pointers.
            unsafe {
                thread.with_view(|context| {
                    context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 0)
                });
            }
            assert_eq!(
                domain
                    .system
                    .reservations
                    .store(&mut thread.reservation, &access, || Ok::<_, MemoryStatus>(
                        ()
                    )),
                Ok(monitor::ConditionalWrite::Failed)
            );
            assert_eq!(snapshot(&backing, 1), [0]);
        }
    }

    const GUEST_BASE: u64 = 0x1000;
    const STORAGE_BYTES: usize = 64;
    const TEST_PC: u64 = 0x1234;
    const TEST_ERG_BYTES: u64 = 16;
    const TEST_STRIPES: usize = 4;
    const RIGHTS: AccessPermissions = AccessPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    const ATTRIBUTES: MappingAttributes = MappingAttributes {
        tagged: false,
        shareable: true,
    };

    struct Storage {
        pointer: NonNull<u8>,
        layout: Layout,
    }

    // SAFETY: this owner retains raw storage without lending Rust references.
    unsafe impl Send for Storage {}
    // SAFETY: byte accesses go through the tested execution domain.
    unsafe impl Sync for Storage {}

    impl Drop for Storage {
        fn drop(&mut self) {
            // SAFETY: the allocation and layout are owned here.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    fn backing() -> Arc<MemoryBacking> {
        let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
        // SAFETY: valid nonempty layout retained for its matching deallocation.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let storage = Arc::new(Storage { pointer, layout });
        // SAFETY: storage owns stable raw bytes and rights; no Rust references
        // alias them and tests access only through the native access boundary.
        unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, RIGHTS, storage) }.unwrap()
    }

    fn view(
        backing: &Arc<MemoryBacking>,
        offset: usize,
        bytes: usize,
        rights: AccessPermissions,
    ) -> Arc<MemoryView> {
        MemoryView::new(
            Arc::clone(backing),
            GUEST_BASE + offset as u64,
            offset,
            bytes,
            rights,
        )
        .unwrap()
    }

    fn domain(views: Vec<Arc<MemoryView>>) -> Arc<MemoryDomain> {
        MemoryDomain::new(
            MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
            views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
            TargetCpu::detect(),
        )
        .unwrap()
    }

    mod system_reads {
        use super::*;
        use stela_compiler::context::memory::{
            InstructionRequirements,
            exclusive::{ExclusiveData, ExclusiveOperation},
        };
        #[derive(Default)]
        struct ReadPolicy;
        impl DataPolicy for ReadPolicy {
            fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
                Ok(())
            }
            fn validate_operation_execution(
                &self,
                _: MemoryOperationClass,
            ) -> Result<(), MemoryStatus> {
                Ok(())
            }
            fn validate_instructions(
                &self,
                _: InstructionRequirements,
            ) -> Result<(), MemoryStatus> {
                Ok(())
            }
            fn translate(&self, raw: u64) -> Result<u64, MemoryStatus> {
                Ok(raw)
            }
            fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
                Ok(())
            }
        }
        fn physical_fixture() -> (Arc<MemoryBacking>, Arc<MemoryDomain>) {
            // Synthetic software mapping authority tests actual native memory
            // recipes only. CPL0/source-CPU entry is separately qualified.
            assert!(TargetCpu::X86_64_V2.supported());
            let backing = backing();
            let readonly = AccessPermissions {
                writable: false,
                ..RIGHTS
            };
            let views = vec![
                (
                    MemoryView::new(Arc::clone(&backing), GUEST_BASE, 0, STORAGE_BYTES, readonly)
                        .unwrap(),
                    ATTRIBUTES,
                ),
                (
                    MemoryView::new(
                        Arc::clone(&backing),
                        GUEST_BASE + 0x1000,
                        0,
                        STORAGE_BYTES,
                        RIGHTS,
                    )
                    .unwrap(),
                    ATTRIBUTES,
                ),
            ];
            let domain = MemoryDomain::construct_admitted(
                None,
                MemorySystem::new(16, 4).unwrap(),
                views,
                TargetCpu::X86_64_V2,
                DomainRole::NativeSystemRam,
            )
            .unwrap();
            (backing, domain)
        }
        fn exclusive(
            thread: &mut MemoryThread<ReadPolicy>,
            data: &mut ExclusiveData,
        ) -> (MemoryStatus, u64) {
            let write = data.operation == ExclusiveOperation::Store as u32;
            let request = MemoryRequest {
                address: GUEST_BASE + 0x1000,
                bytes: 16,
                data: core::ptr::from_mut(data).cast(),
                flags: flags::EXCLUSIVE | if write { flags::WRITE } else { 0 },
                pc: TEST_PC,
            };
            // SAFETY: retained exact native-capable fixture/storage/events and
            // initialized private staging. No production admission is asserted.
            unsafe {
                thread.with_checked_view(|view| {
                    let status = (view.callback)(view, &request);
                    (
                        MemoryStatus::from_code(status).unwrap(),
                        view.completed_bytes,
                    )
                })
            }
            .unwrap()
        }
        #[test]
        fn cx16_source_read_only_alias_preserves_real_global_reservation() {
            let (backing, domain) = physical_fixture();
            assert!(matches!(
                domain
                    .thread(ReadPolicy)
                    .prepare(MemoryRequirements::default()),
                Err(MemoryStatus::Unsupported)
            ));
            let events = crate::system::events::EventDomain::new();
            let endpoint = events.register(false, None).unwrap();
            let mut writer = domain.thread(ReadPolicy);
            writer.bind_events(&endpoint.producer()).unwrap();
            let mut load = ExclusiveData {
                operation: ExclusiveOperation::Load as u32,
                shape: 1,
                ..Default::default()
            };
            assert_eq!(
                exclusive(&mut writer, &mut load),
                (MemoryStatus::Success, 16)
            );
            let mut reader = domain.thread(ReadPolicy);
            let mut bytes = [0xff; 16];
            let request = MemoryRequest {
                address: GUEST_BASE,
                bytes: 16,
                data: bytes.as_mut_ptr(),
                flags: 0,
                pc: TEST_PC,
            };
            // SAFETY: same retained real native fixture, read-only source view
            // and private destination. Fallback host writeback stays gated.
            let status =
                unsafe { reader.with_checked_view(|view| (view.callback)(view, &request)) }
                    .unwrap();
            assert_eq!(status, MemoryStatus::Success as u32);
            assert_eq!(bytes, [0; 16]);
            assert_eq!(snapshot(&backing, STORAGE_BYTES), [0; STORAGE_BYTES]);
            let mut store = ExclusiveData {
                operation: ExclusiveOperation::Store as u32,
                shape: 1,
                value: [0x1234, 0x5678],
                ..Default::default()
            };
            assert_eq!(
                exclusive(&mut writer, &mut store),
                (MemoryStatus::Success, 16)
            );
            assert_eq!(
                store.status, 0,
                "observer must not invalidate the source reservation"
            );
            let mut expected = [0; STORAGE_BYTES];
            expected[..8].copy_from_slice(&0x1234u64.to_le_bytes());
            expected[8..16].copy_from_slice(&0x5678u64.to_le_bytes());
            assert_eq!(snapshot(&backing, STORAGE_BYTES), expected);
        }
        #[test]
        fn real_alias_writer_aba_still_invalidates_after_observer_read() {
            let (backing, domain) = physical_fixture();
            let events = crate::system::events::EventDomain::new();
            let endpoint = events.register(false, None).unwrap();
            let mut writer = domain.thread(ReadPolicy);
            writer.bind_events(&endpoint.producer()).unwrap();
            let mut load = ExclusiveData {
                operation: ExclusiveOperation::Load as u32,
                shape: 1,
                ..Default::default()
            };
            assert_eq!(exclusive(&mut writer, &mut load).0, MemoryStatus::Success);
            // This real host writer uses exactly the same physical monitor,
            // including the A->B->A case invisible to byte comparison.
            unsafe {
                domain.system.publish(&backing, 0, &[1; 16]).unwrap();
                domain.system.publish(&backing, 0, &[0; 16]).unwrap();
            }
            let mut store = ExclusiveData {
                operation: ExclusiveOperation::Store as u32,
                shape: 1,
                value: [7, 9],
                ..Default::default()
            };
            assert_eq!(exclusive(&mut writer, &mut store).0, MemoryStatus::Success);
            assert_eq!(store.status, 1);
            assert_eq!(snapshot(&backing, STORAGE_BYTES), [0; STORAGE_BYTES]);
        }
    }

    mod access_intent {
        use super::*;
        use stela_compiler::context::memory::{
            FaultAccess, InstructionRequirements, MemoryOrder,
            atomic::{AtomicData, AtomicOperation},
            exclusive::{ExclusiveData, ExclusiveOperation},
            ordered::{OrderedData, OrderedOperation},
        };

        #[derive(Default)]
        struct Directed {
            checked: Vec<DataRequest>,
            parts: Vec<(DataRequest, DataPart)>,
            deny_write: Option<u64>,
        }
        impl DataPolicy for Directed {
            fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
                Ok(())
            }
            fn validate_operation_execution(
                &self,
                _: MemoryOperationClass,
            ) -> Result<(), MemoryStatus> {
                Ok(())
            }
            fn validate_instructions(
                &self,
                _: InstructionRequirements,
            ) -> Result<(), MemoryStatus> {
                Ok(())
            }
            fn translate(&self, raw: u64) -> Result<u64, MemoryStatus> {
                Ok(raw)
            }
            fn validate_data_request(&mut self, request: DataRequest) -> Result<(), MemoryStatus> {
                self.checked.push(request);
                Ok(())
            }
            fn translate_part(
                &mut self,
                request: DataRequest,
                part: DataPart,
            ) -> Result<u64, (MemoryStatus, u64)> {
                self.parts.push((request, part));
                if part.kind == AccessKind::Write && self.deny_write == Some(part.address) {
                    Err((MemoryStatus::Permission, part.address))
                } else {
                    Ok(part.address)
                }
            }
            fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
                Ok(())
            }
        }
        fn callback(thread: &mut MemoryThread<Directed>, request: MemoryRequest) -> MemoryFault {
            // SAFETY: every fixture retains initialized disjoint typed staging,
            // canonical backing, private context and exact request for this call.
            unsafe {
                thread.with_checked_view(|view| {
                    (view.callback)(view, &request);
                    MemoryFault {
                        status: MemoryStatus::from_code(view.fault_kind).unwrap(),
                        access: FaultAccess::from_code(view.fault_access).unwrap(),
                        address: view.fault_address,
                        pc: view.fault_pc,
                        completed_bytes: view.completed_bytes,
                    }
                })
            }
            .unwrap()
        }
        #[test]
        fn dynamic_write_rights_preserve_original_request_and_exact_reached_prefix() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Directed {
                deny_write: Some(GUEST_BASE + 16),
                ..Default::default()
            });
            let before = snapshot(&backing, STORAGE_BYTES);
            let mut bytes = [0x5a; 8];
            let fault = callback(
                &mut thread,
                MemoryRequest {
                    address: GUEST_BASE + 13,
                    data: bytes.as_mut_ptr(),
                    bytes: 8,
                    flags: flags::WRITE,
                    pc: TEST_PC,
                },
            );
            assert_eq!(
                (fault.status, fault.address, fault.pc, fault.completed_bytes),
                (MemoryStatus::Permission, GUEST_BASE + 16, TEST_PC, 3)
            );
            let intent = DataRequest {
                address: GUEST_BASE + 13,
                bytes: 8,
                flags: flags::WRITE,
                pc: Some(TEST_PC),
                operation: DataOperation::Ordinary,
            };
            assert_eq!(thread.policy.checked, [intent]);
            assert_eq!(
                thread.policy.parts,
                (13..=16)
                    .map(|offset| (
                        intent,
                        DataPart {
                            address: GUEST_BASE + offset,
                            bytes: 1,
                            kind: AccessKind::Write,
                        }
                    ))
                    .collect::<Vec<_>>()
            );
            let mut expected = before;
            expected[13..16].fill(0x5a);
            assert_eq!(snapshot(&backing, STORAGE_BYTES), expected);
        }
        #[test]
        fn cas_checks_dynamic_read_then_write_even_when_comparison_will_fail() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Directed {
                deny_write: Some(GUEST_BASE),
                ..Default::default()
            });
            let before = snapshot(&backing, STORAGE_BYTES);
            let mut data = AtomicData {
                operation: AtomicOperation::CompareExchange as u32,
                compare: [1, 0],
                operand: [7, 0],
                ..Default::default()
            };
            let original = data;
            let fault = callback(
                &mut thread,
                MemoryRequest {
                    address: GUEST_BASE,
                    data: core::ptr::from_mut(&mut data).cast(),
                    bytes: 8,
                    flags: flags::ATOMIC | flags::WRITE,
                    pc: TEST_PC,
                },
            );
            assert_eq!(
                (fault.status, fault.access, fault.completed_bytes),
                (MemoryStatus::Permission, FaultAccess::Write, 0)
            );
            assert_eq!(data, original);
            assert_eq!(snapshot(&backing, STORAGE_BYTES), before);
            assert_eq!(
                thread
                    .policy
                    .parts
                    .iter()
                    .map(|(request, part)| (request.operation, part.kind))
                    .collect::<Vec<_>>(),
                [
                    (DataOperation::Atomic, AccessKind::Read),
                    (DataOperation::Atomic, AccessKind::Write)
                ]
            );
        }
        #[test]
        fn ordered_adaptation_retains_source_category_and_exclusive_direction() {
            let backing = backing();
            let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Directed::default());
            let events = crate::system::events::EventDomain::new();
            let endpoint = events.register(false, None).unwrap();
            thread.bind_events(&endpoint.producer()).unwrap();
            thread.check_event_endpoint(&endpoint).unwrap();
            let mut ordered = OrderedData {
                operation: OrderedOperation::Store as u32,
                order: MemoryOrder::Release as u32,
                value: [0x12, 0],
                ..Default::default()
            };
            let result = callback(
                &mut thread,
                MemoryRequest {
                    address: GUEST_BASE,
                    data: core::ptr::from_mut(&mut ordered).cast(),
                    bytes: 8,
                    flags: flags::ORDERED | flags::WRITE,
                    pc: TEST_PC,
                },
            );
            assert_eq!(result.status, MemoryStatus::Success);
            let mut exclusive = ExclusiveData {
                operation: ExclusiveOperation::Load as u32,
                ..Default::default()
            };
            let result = callback(
                &mut thread,
                MemoryRequest {
                    address: GUEST_BASE,
                    data: core::ptr::from_mut(&mut exclusive).cast(),
                    bytes: 8,
                    flags: flags::EXCLUSIVE,
                    pc: TEST_PC + 4,
                },
            );
            assert_eq!(result.status, MemoryStatus::Success);
            assert_eq!(exclusive.value, [0x12, 0]);
            exclusive = ExclusiveData {
                operation: ExclusiveOperation::Store as u32,
                value: [0x34, 0],
                ..Default::default()
            };
            let result = callback(
                &mut thread,
                MemoryRequest {
                    address: GUEST_BASE,
                    data: core::ptr::from_mut(&mut exclusive).cast(),
                    bytes: 8,
                    flags: flags::EXCLUSIVE | flags::WRITE,
                    pc: TEST_PC + 8,
                },
            );
            assert_eq!(result.status, MemoryStatus::Success);
            assert_eq!(
                thread
                    .policy
                    .parts
                    .iter()
                    .map(|(request, part)| (request.operation, part.kind))
                    .collect::<Vec<_>>(),
                [
                    (DataOperation::Ordered, AccessKind::Write),
                    (DataOperation::Exclusive, AccessKind::Read),
                    (DataOperation::Exclusive, AccessKind::Write)
                ]
            );
            assert_eq!(
                thread
                    .policy
                    .checked
                    .iter()
                    .map(|request| request.pc)
                    .collect::<Vec<_>>(),
                [Some(TEST_PC), Some(TEST_PC + 4), Some(TEST_PC + 8)]
            );
            assert_eq!(&snapshot(&backing, 8), &0x34u64.to_le_bytes());
        }
    }

    #[derive(Default)]
    struct Policy {
        unavailable: bool,
        reject: Option<u64>,
        checked: Vec<(u64, usize)>,
        checked_flags: Vec<u32>,
    }

    impl DataPolicy for Policy {
        fn validate_execution(&self, _required_flags: u32) -> Result<(), MemoryStatus> {
            if self.unavailable {
                Err(MemoryStatus::Unsupported)
            } else {
                Ok(())
            }
        }
        fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
            Ok(raw_address)
        }

        fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
            self.checked.push((access.raw_address, access.bytes));
            self.checked_flags.push(access.flags);
            if self.reject == Some(access.raw_address) {
                Err(MemoryStatus::TagCheck)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug)]
    struct Outcome {
        status: u32,
        fault_kind: u32,
        fault_address: u64,
        fault_pc: u64,
        completed: u64,
    }

    fn invoke(
        thread: &mut MemoryThread<Policy>,
        address: u64,
        bytes: &mut [u8],
        flags: u32,
    ) -> Outcome {
        let request = MemoryRequest {
            address,
            data: bytes.as_mut_ptr(),
            bytes: bytes.len() as u32,
            flags,
            pc: TEST_PC,
        };
        // SAFETY: the synchronous callback receives valid ABI objects and private
        // staging disjoint from raw guest storage, with no retained pointers.
        unsafe {
            thread.with_view(|context| {
                let status = (context.callback)(context, &request);
                Outcome {
                    status,
                    fault_kind: context.fault_kind,
                    fault_address: context.fault_address,
                    fault_pc: context.fault_pc,
                    completed: context.completed_bytes,
                }
            })
        }
    }

    fn snapshot(backing: &MemoryBacking, bytes: usize) -> Vec<u8> {
        (0..bytes)
            .map(|offset| {
                let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
                // SAFETY: tests inspect after synchronous execution; no byte access
                // overlaps this exact live one-byte native read.
                unsafe { access::read_part(pointer.as_ptr(), 1, TargetCpu::Baseline) }.unwrap()
                    as u8
            })
            .collect()
    }

    fn reservation_access(
        domain: &MemoryDomain,
        offset: u64,
    ) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
        let registered = &domain.registered_views()[0];
        monitor::Access::new(
            Arc::clone(registered.view.backing()),
            Arc::clone(&registered.monitor),
            offset,
            1,
            monitor::Shape::Scalar,
        )
        .unwrap()
    }
}
