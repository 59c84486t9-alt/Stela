//! Context-backed native memory execution, with one physical writer domain.
//!
//! Families submit reached elements and retain their own register staging. This
//! owner resolves each actually reached atomic part, checks tags and publishes
//! writes through the shared reservation domain. It does not interpret opcodes.

#[path = "domain/publication.rs"]
mod publication;
pub use publication::PublicationFault;
#[path = "domain/profile.rs"]
mod profile;
pub use profile::{CheckedMemoryEntry, MemoryProfile};

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

use stela_compiler::{
    TargetCpu,
    context::memory::{
        MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest,
        MemoryRequirements, MemoryStatus, flags,
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
    /// Reject unavailable effective-control profiles before any guest effect.
    fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus>;
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

struct RegisteredView {
    view: Arc<MemoryView>,
    monitor: Arc<ReservationMapping>,
}

/// One guest machine's physical coherence and reservation owner. Shared backing
/// across address spaces must bind to this same owner; COW creates new backing.
pub struct MemorySystem {
    identity: Arc<()>,
    reservations: Arc<ReservationDomain>,
    mappings: Mutex<MappingRegistry>,
    failed: AtomicBool,
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

/// Immutable address-space snapshot. Replacement/reprotection requires a new
/// snapshot and explicit retirement; host mapping rights remain pinned by the
/// unsafe backing contract throughout every native invocation.
pub struct MemoryDomain {
    views: Vec<RegisteredView>,
    target: TargetCpu,
    system: Arc<MemorySystem>,
    address_space: Option<u64>,
    profile: MemoryProfile,
}

impl MemoryDomain {
    pub fn new(
        system: Arc<MemorySystem>,
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
    ) -> Result<Arc<Self>, MemoryStatus> {
        Self::construct(None, system, views, target)
    }

    /// Bind this snapshot to its real process address-space identity.
    pub fn new_for_address_space(
        address_space: u64,
        system: Arc<MemorySystem>,
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
    ) -> Result<Arc<Self>, MemoryStatus> {
        Self::construct(Some(address_space), system, views, target)
    }

    fn construct(
        address_space: Option<u64>,
        system: Arc<MemorySystem>,
        mut views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
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
            views,
            target,
            system,
            address_space,
            profile,
        }))
    }

    pub fn address_space(&self) -> Option<u64> {
        self.address_space
    }

    pub fn profile(&self) -> &MemoryProfile {
        &self.profile
    }

    pub fn thread<P: DataPolicy>(self: &Arc<Self>, policy: P) -> MemoryThread<P> {
        MemoryThread {
            domain: Arc::clone(self),
            reservation: self.system.reservations.thread(),
            policy,
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
    /// The address-space owner must also exclude in-flight native accesses.
    pub fn retire(&self, view: &Arc<MemoryView>) -> Result<(), MemoryStatus> {
        let registered = self
            .views
            .iter()
            .find(|registered| Arc::ptr_eq(&registered.view, view))
            .ok_or(MemoryStatus::InvalidRequest)?;
        self.system
            .reservations
            .revoke_mapping(&registered.monitor)
            .map_err(|_| MemoryStatus::Domain)?;
        registered.view.retire();
        Ok(())
    }

    fn resolve(
        &self,
        address: u64,
        bytes: usize,
        kind: AccessKind,
    ) -> Result<PhysicalAccess, MemoryStatus> {
        let mut first_span: Option<ResolvedAccess> = None;
        let mut remaining_spans = Vec::new();
        let mut current = address;
        let mut remaining = bytes;
        let mut attributes = None;
        while remaining != 0 {
            let index = self
                .views
                .partition_point(|view| view.view.guest_base() <= current);
            let registered = index
                .checked_sub(1)
                .and_then(|index| self.views.get(index))
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

impl<P: DataPolicy> MemoryThread<P> {
    pub fn address_space(&self) -> Option<u64> {
        self.domain.address_space()
    }

    pub fn profile(&self) -> &MemoryProfile {
        self.domain.profile()
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
                .profile
                .validate(requirements, owner.domain.target)?;
            owner.policy.validate_execution(requirements.required_flags)
        })
    }
    /// Native entry must validate effective controls before executing an instruction.
    pub fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus> {
        self.domain.check_execution()?;
        self.policy.validate_execution(required_flags)
    }

    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.policy
    }

    pub fn clear_reservation(&mut self) -> Result<(), MemoryStatus> {
        self.domain.check_execution()?;
        self.domain
            .system
            .reservations
            .clear(&mut self.reservation)
            .map_err(|_| MemoryStatus::Domain)
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
    ///
    /// # Safety
    /// Native code may call only the supplied callback with valid requests and
    /// disjoint private staging buffers of the declared size. It must preserve
    /// the header, opaque pointer and callback, retain no pointers, not reenter
    /// this owner, and honor the mapping/staging lifetime and separation contracts.
    /// Guest and native physical addresses must have congruent low four bits
    /// for the declared SCA16 profile; unsupported native footprints fail explicitly.
    pub unsafe fn with_view<R>(&mut self, callback: impl FnOnce(&mut MemoryContextView) -> R) -> R {
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
        if let Some(status) = MemoryStatus::from_code(view.fault_kind) {
            // Includes locally emitted SP/alignment faults which never call dispatch.
            let _ = self.settle_fault(status);
        }
        result
    }

    unsafe fn transfer(
        &mut self,
        view: &mut MemoryContextView,
        request: &MemoryRequest,
    ) -> Result<(), (MemoryStatus, u64)> {
        self.validate_execution(request.flags)
            .map_err(|status| (status, request.address))?;
        if request.data.is_null()
            || request.flags & !flags::KNOWN != 0
            || !matches!(request.bytes, 1 | 2 | 4 | 8 | 16)
        {
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
                            .check(physical.data(raw, part.bytes, request.flags))?;
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
                    .check(physical.data(raw, part.bytes, request.flags))
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
}

struct AccessParts {
    address: u64,
    bytes: usize,
    offset: usize,
    part_bytes: usize,
}

impl AccessParts {
    fn new(address: u64, bytes: usize, descriptor: u32) -> Self {
        let residue = address as usize & (SCA_BYTES - 1);
        let part_bytes = if residue + bytes <= SCA_BYTES {
            bytes
        } else if bytes == SCA_BYTES
            && residue == HALF_SCA_BYTES
            && descriptor & flags::SME == 0
            && descriptor & (flags::SVE_PREDICATED | flags::ASIMD) != 0
        {
            HALF_SCA_BYTES
        } else {
            1
        };
        Self {
            address,
            bytes,
            offset: 0,
            part_bytes,
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
        };
        self.offset += self.part_bytes;
        Some(part)
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "domain/tests.rs"]
mod tests;
