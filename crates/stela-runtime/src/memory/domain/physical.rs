//! Physical reads of source from loader-provided private RAM.
pub(crate) mod completion;

use super::{
    AccessKind, Arc, MemoryDomain, MemoryExecutionLoan, MemoryStatus, PhysicalAccess, access,
};
use crate::memory::{
    source_ram::{SourcePhysicalRamBinding, SourceRamLayout},
    stage1::{PhysicalMemory, PhysicalReadError},
};

mod mutable_source;
pub(in crate::memory) use mutable_source::RegionReload;

const DESCRIPTOR_BYTES: usize = 8;
const DESCRIPTOR_ALIGNMENT_MASK: u64 = DESCRIPTOR_BYTES as u64 - 1;

/// Owns the physical address placements and their backing and view generations.
pub struct PhysicalAddressSpace {
    domain: Arc<MemoryDomain>,
    binding: SourcePhysicalRamBinding,
}

/// Descriptor reads of the physical domain, tied to the lifetime of the outer
/// borrow.
pub(crate) struct BorrowedDescriptors<'loan> {
    physical: &'loan PhysicalAddressSpace,
    execution: &'loan MemoryExecutionLoan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhysicalReadPlatformError {
    Domain(MemoryStatus),
    Unavailable,
    Alignment,
    HostAlignment,
    UnsupportedHost,
}
impl core::fmt::Display for PhysicalReadPlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "physical RAM platform refusal: {self:?}")
    }
}
impl core::error::Error for PhysicalReadPlatformError {}

pub(crate) struct PhysicalRamReadPin<'loan> {
    physical: &'loan PhysicalAddressSpace,
    execution: &'loan MemoryExecutionLoan,
    reached: PhysicalAccess,
    bytes: usize,
}
impl PhysicalRamReadPin<'_> {
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(super) fn pointer(&self) -> *const u8 {
        self.reached.first().host_ptr().as_ptr().cast_const()
    }
    #[cfg(test)]
    pub(super) fn memory_system(&self) -> &super::MemorySystem {
        &self.physical.domain.system
    }
    pub(super) fn check_current(&self) -> Result<(), PhysicalReadPlatformError> {
        self.physical.check_execution_loan(self.execution)?;
        self.physical.check_reached(&self.reached)
    }
}

impl PhysicalAddressSpace {
    /// Create a host-service writer for one RAM extent. It gives no guest,
    /// CPU, DMA or execution access.
    pub(crate) fn source_ram_publisher(
        &mut self,
        source_pa: u64,
        bytes: usize,
    ) -> Result<crate::memory::source_ram::SourceRamPublisher, MemoryStatus> {
        self.check_source_binding()
            .map_err(|_| MemoryStatus::Domain)?;
        self.binding.publisher(source_pa, bytes)
    }

    pub(crate) fn from_materialized(
        binding: SourcePhysicalRamBinding,
    ) -> Result<Self, PhysicalReadPlatformError> {
        let domain = Arc::clone(binding.domain());
        let physical = Self { domain, binding };
        physical.check_source_binding()?;
        Ok(physical)
    }

    /// The domain, for constructing the new machine's thread and consumer.
    pub(crate) fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub(crate) fn layout(&self) -> &SourceRamLayout {
        self.binding.layout()
    }

    /// One construction borrow for the installed-source owner before any PE
    /// exists, held through the initial source fetch and registration.
    pub(crate) fn initial_source_execution_loan(
        &self,
    ) -> Result<MemoryExecutionLoan, PhysicalReadPlatformError> {
        let execution = self
            .domain
            .execution_loan()
            .map_err(PhysicalReadPlatformError::Domain)?;
        self.check_execution_loan(&execution)?;
        Ok(execution)
    }

    /// Check health and the current binding from metadata only; byte reads must
    /// hold and validate their own execution borrow.
    fn check_source_binding(&self) -> Result<(), PhysicalReadPlatformError> {
        self.domain
            .check_execution()
            .map_err(PhysicalReadPlatformError::Domain)?;
        if !self.domain.is_source_physical_ram()
            || !Arc::ptr_eq(&self.domain, self.binding.domain())
            || !Arc::ptr_eq(&self.domain.system, self.binding.system())
            || self
                .domain
                .generation()
                .map_err(PhysicalReadPlatformError::Domain)?
                != self.binding.generation()
            || !self.binding.current_views()
        {
            return Err(PhysicalReadPlatformError::Unavailable);
        }
        Ok(())
    }

    /// Check domain membership and health.
    pub(crate) fn check_execution_loan(
        &self,
        execution: &MemoryExecutionLoan,
    ) -> Result<(), PhysicalReadPlatformError> {
        execution
            .check_domain(&self.domain)
            .map_err(PhysicalReadPlatformError::Domain)?;
        execution
            .check_memory_system(self.binding.system())
            .map_err(PhysicalReadPlatformError::Domain)?;
        self.check_source_binding()
    }

    fn check_reached(&self, reached: &PhysicalAccess) -> Result<(), PhysicalReadPlatformError> {
        if !core::iter::once(reached.first())
            .chain(reached._remaining.iter())
            .all(|span| span.view().is_current() && self.binding.owns_view(span.view()))
        {
            return Err(PhysicalReadPlatformError::Unavailable);
        }
        Ok(())
    }

    /// Existing descriptor and legacy read64 clients retain their exact width.
    pub(crate) fn resolve_ram8<'loan>(
        &'loan self,
        execution: &'loan MemoryExecutionLoan,
        physical_address: u64,
    ) -> Result<PhysicalRamReadPin<'loan>, PhysicalReadPlatformError> {
        self.resolve_ram_scalar(execution, physical_address, DESCRIPTOR_BYTES as u8)
    }
    /// Resolve exactly the naturally aligned scalar footprint.
    pub(crate) fn resolve_ram_scalar<'loan>(
        &'loan self,
        execution: &'loan MemoryExecutionLoan,
        physical_address: u64,
        bytes: u8,
    ) -> Result<PhysicalRamReadPin<'loan>, PhysicalReadPlatformError> {
        self.check_execution_loan(execution)?;
        if !matches!(bytes, 1 | 2 | 4 | 8) {
            return Err(PhysicalReadPlatformError::Domain(
                MemoryStatus::InvalidRequest,
            ));
        }
        let bytes = usize::from(bytes);
        if !cfg!(target_arch = "x86_64") {
            return Err(PhysicalReadPlatformError::UnsupportedHost);
        }
        if physical_address & (bytes as u64 - 1) != 0
            || physical_address.checked_add(bytes as u64).is_none()
        {
            return Err(PhysicalReadPlatformError::Alignment);
        }
        let reached = self
            .domain
            .resolve_source_physical(execution, physical_address, bytes, AccessKind::Read)
            .map_err(PhysicalReadPlatformError::Domain)?;
        self.check_reached(&reached)?;
        let pointer = reached.first().host_ptr().as_ptr();
        if pointer as usize & (bytes - 1) != 0 {
            return Err(PhysicalReadPlatformError::HostAlignment);
        }
        let (address, footprint_bytes) =
            access::read_footprint(pointer as usize, bytes, self.domain.target)
                .map_err(|_| PhysicalReadPlatformError::UnsupportedHost)?;
        if address != pointer as usize || footprint_bytes != bytes {
            return Err(PhysicalReadPlatformError::UnsupportedHost);
        }
        Ok(PhysicalRamReadPin {
            physical: self,
            execution,
            reached,
            bytes,
        })
    }
    /// Borrow physical descriptor reads under the outer borrow. Membership and
    /// binding are checked now and on every read.
    pub(crate) fn borrow_descriptors<'loan>(
        &'loan self,
        execution: &'loan MemoryExecutionLoan,
    ) -> Result<BorrowedDescriptors<'loan>, PhysicalReadPlatformError> {
        self.check_execution_loan(execution)?;
        Ok(BorrowedDescriptors {
            physical: self,
            execution,
        })
    }

    /// One descriptor read using the supplied invocation; no nested borrow or
    /// virtual lookup.
    fn read_descriptor_with_loan(
        &self,
        execution: &MemoryExecutionLoan,
        physical_address: u64,
    ) -> Result<u64, PhysicalReadError> {
        if physical_address & DESCRIPTOR_ALIGNMENT_MASK != 0 {
            return Err(PhysicalReadError::Platform(
                "physical descriptor address is not aligned to eight bytes",
            ));
        }
        self.check_execution_loan(execution).map_err(|_| {
            PhysicalReadError::Platform("physical descriptor source binding is unavailable")
        })?;
        let physical = self
            .domain
            .resolve_source_physical(
                execution,
                physical_address,
                DESCRIPTOR_BYTES,
                AccessKind::Read,
            )
            .map_err(platform_error)?;
        self.check_reached(&physical).map_err(|_| {
            PhysicalReadError::Platform("physical descriptor source generation is unavailable")
        })?;
        let first = physical.first();
        let pointer = first.host_ptr().as_ptr();
        if pointer as usize & (DESCRIPTOR_BYTES - 1) != 0 {
            return Err(PhysicalReadError::Platform(
                "physical descriptor native address is not aligned to eight bytes",
            ));
        }
        let (footprint_address, footprint_bytes) =
            access::read_footprint(pointer as usize, DESCRIPTOR_BYTES, self.domain.target)
                .map_err(|_| {
                    PhysicalReadError::Platform("physical descriptor native read is unsupported")
                })?;
        if footprint_address != pointer as usize || footprint_bytes != DESCRIPTOR_BYTES {
            return Err(PhysicalReadError::Platform(
                "physical descriptor native read requires an unsupported envelope",
            ));
        }
        first
            .view()
            .backing()
            .host_pointer(first.backing_offset(), DESCRIPTOR_BYTES, AccessKind::Read)
            .map_err(|_| {
                PhysicalReadError::Platform("physical descriptor native extent is unavailable")
            })?;
        if !first.view().is_current()
            || physical
                ._remaining
                .iter()
                .any(|span| !span.view().is_current())
        {
            return Err(PhysicalReadError::Platform(
                "physical descriptor mapping has been retired",
            ));
        }
        // SAFETY: materialized source RAM and the alignment checks establish an
        // 8-byte coherent host-RAM footprint. The execution borrow excludes
        // rights changes, and the source views and backings stay pinned through
        // the read.
        let value = unsafe { access::read_part(pointer, DESCRIPTOR_BYTES, self.domain.target) }
            .map_err(|_| {
                PhysicalReadError::Platform("physical descriptor native read is unsupported")
            })?;
        self.domain.check_execution().map_err(platform_error)?;
        self.check_execution_loan(execution).map_err(|_| {
            PhysicalReadError::Platform("physical descriptor source binding is unavailable")
        })?;
        self.check_reached(&physical).map_err(|_| {
            PhysicalReadError::Platform("physical descriptor source generation is unavailable")
        })?;
        Ok(value as u64)
    }
}

impl PhysicalMemory for PhysicalAddressSpace {
    fn read_descriptor(&self, physical_address: u64) -> Result<u64, PhysicalReadError> {
        // Check alignment before taking a borrow, as the standalone path does.
        if physical_address & DESCRIPTOR_ALIGNMENT_MASK != 0 {
            return Err(PhysicalReadError::Platform(
                "physical descriptor address is not aligned to eight bytes",
            ));
        }
        let execution = self.domain.execution_loan().map_err(platform_error)?;
        self.read_descriptor_with_loan(&execution, physical_address)
    }
}

impl PhysicalMemory for BorrowedDescriptors<'_> {
    fn read_descriptor(&self, physical_address: u64) -> Result<u64, PhysicalReadError> {
        self.physical
            .read_descriptor_with_loan(self.execution, physical_address)
    }
}

fn platform_error(status: MemoryStatus) -> PhysicalReadError {
    PhysicalReadError::Platform(match status {
        MemoryStatus::Domain => "physical memory domain is unavailable",
        MemoryStatus::Translation => "physical descriptor mapping is unavailable or retired",
        MemoryStatus::Permission => "physical descriptor mapping denies reads",
        MemoryStatus::Unsupported => "physical descriptor storage layout is unsupported",
        MemoryStatus::InvalidRequest => "physical descriptor request is invalid",
        _ => "physical descriptor resolution returned an unsupported diagnostic",
    })
}

mod fetch;
pub(crate) use fetch::{BoundPhysicalInstruction, ImmutableCodeBacking};

mod stores;
pub(crate) use stores::{
    M0RamWritePlatformError, M0RamWritePrepared, M0RamWriteProgress,
    prepare_aligned_device_ram_scalar_or_pair,
};

// Raw RAM observations for tests.
#[cfg(test)]
mod source_diagnostic;

// Test-only operations.
#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
impl PhysicalAddressSpace {}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
impl super::MemorySystem {}

mod walked;

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::completion::{RamCompletionError, RamCompletionProgress};
    use super::*;
    use crate::memory::{
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
        source_ram::{
            OwnedRamExtent, PhysicalRamRange, SourceRamBuildError, SourceRamDeclaration,
            SourceRamPermissions, SourceRamSystemConfig, materialize_source_ram,
        },
    };
    use stela_compiler::{TargetCpu, context::memory::MemoryRequirements};

    fn extent(source_pa: u64, bytes: Vec<u8>, executable: bool) -> OwnedRamExtent {
        OwnedRamExtent {
            source_pa,
            bytes,
            permissions: SourceRamPermissions {
                readable: true,
                writable: !executable,
                executable,
            },
        }
    }

    fn declaration(initialized: Vec<OwnedRamExtent>) -> SourceRamDeclaration {
        SourceRamDeclaration {
            address_space: 7,
            target: TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: 0x1000,
                bytes: 0x4000,
            }],
            initialized,
        }
    }

    fn config() -> SourceRamSystemConfig {
        SourceRamSystemConfig {
            reservation_granule_bytes: 16,
            reservation_stripe_count: 8,
        }
    }

    fn physical() -> PhysicalAddressSpace {
        let original: Vec<u8> = (0..29).collect();
        let materialized = materialize_source_ram(
            declaration(vec![
                extent(0x1003, original, false),
                extent(0x3000, vec![0xa5; 16], true),
            ]),
            config(),
        )
        .unwrap();
        let (binding, immutable_sources) = materialized.into_parts();
        assert_eq!(immutable_sources.len(), 1);
        assert!(
            !immutable_sources[0]
                .backing()
                .maximum_permissions()
                .writable
        );
        assert!(
            immutable_sources[0]
                .backing()
                .maximum_permissions()
                .executable
        );
        PhysicalAddressSpace::from_materialized(binding).unwrap()
    }

    #[test]
    fn explicit_pa_materialization_pins_exact_initialized_bytes_and_alignment() {
        let physical = physical();
        let execution = physical.domain().execution_loan().unwrap();
        let pin = physical.resolve_ram8(&execution, 0x1008).unwrap();
        assert_eq!(pin.pointer() as usize & 7, 0);
        assert!(std::ptr::eq(
            pin.memory_system(),
            physical.memory_system().as_ref()
        ));
        pin.check_current().unwrap();
        // SAFETY: materialized source, an aligned readable quantity, and every
        // reached backing and view held through the read.
        let value = unsafe { access::read_part(pin.pointer(), 8, TargetCpu::Baseline) }.unwrap();
        assert_eq!(
            value as u64,
            u64::from_le_bytes([5, 6, 7, 8, 9, 10, 11, 12])
        );
        assert_eq!(
            physical.read_descriptor(0x3000).unwrap(),
            0xa5a5_a5a5_a5a5_a5a5
        );
        // Capacity holes, leading padding, rounded tails and out-of-capacity values
        // never become readable by retaining the surrounding allocation.
        for address in [0x1000, 0x1020, 0x2000, 0x3010, 0x6000] {
            assert!(physical.resolve_ram8(&execution, address).is_err());
        }
        assert!(matches!(
            physical.resolve_ram8(&execution, 0x1009),
            Err(PhysicalReadPlatformError::Alignment)
        ));
        assert_eq!(physical.layout().declared_capacity[0].bytes, 0x4000);
        assert_eq!(physical.layout().initialized[0].range.bytes, 29);
        assert_eq!(
            physical.layout().initialized[0].source_sha256,
            crate::sha256(&(0..29).collect::<Vec<u8>>())
        );
    }

    #[test]
    fn physical_role_denies_generic_callbacks_and_survives_snapshot_publication() {
        let physical = physical();
        let policy = MemoryControls::new(
            LowerAddressProfile::new(44, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let mut thread = physical.domain().thread(policy);
        assert!(matches!(thread.profile(), Err(MemoryStatus::Unsupported)));
        assert!(matches!(
            thread.prepare(MemoryRequirements::default()),
            Err(MemoryStatus::Unsupported)
        ));
        let called = std::cell::Cell::new(false);
        // SAFETY: no native code or staging is invoked; the unsupported physical
        // role must decline before exposing a generic callback at all.
        assert_eq!(
            unsafe { thread.with_checked_view(|_| called.set(true)) },
            Err(MemoryStatus::Unsupported)
        );
        assert!(!called.get());
        let service = physical.domain.service_loan().unwrap();
        let snapshot = service.prepare(service.views().unwrap()).unwrap();
        service.commit(snapshot).unwrap();
        drop(service);
        assert!(physical.domain.is_source_physical_ram());
        assert!(matches!(thread.profile(), Err(MemoryStatus::Unsupported)));
        assert_eq!(thread.validate_execution(0), Err(MemoryStatus::Unsupported));
        let execution = thread.execution_loan().unwrap();
        assert_eq!(
            physical.check_execution_loan(&execution),
            Err(PhysicalReadPlatformError::Unavailable)
        );
    }

    #[test]
    fn physical_binding_rejects_foreign_outer_and_retirement_while_pinned() {
        let first = physical();
        let other = physical();
        let foreign = other.domain().execution_loan().unwrap();
        assert!(matches!(
            first.check_execution_loan(&foreign),
            Err(PhysicalReadPlatformError::Domain(MemoryStatus::Domain))
        ));
        let execution = first.domain().execution_loan().unwrap();
        let pin = first.resolve_ram8(&execution, 0x1008).unwrap();
        let view = Arc::clone(pin.reached.first().view());
        assert_eq!(first.domain.retire(&view), Err(MemoryStatus::Domain));
        pin.check_current().unwrap();
        drop(pin);
        drop(execution);
        first.domain.retire(&view).unwrap();
        let execution = first.domain().execution_loan().unwrap();
        assert_eq!(
            first.check_execution_loan(&execution),
            Err(PhysicalReadPlatformError::Unavailable)
        );
    }

    #[test]
    fn malformed_capacity_extents_and_write_execute_decline_without_binding() {
        let mut overlap = declaration(vec![
            extent(0x1000, vec![1; 16], false),
            extent(0x1008, vec![2; 16], false),
        ]);
        assert!(matches!(
            materialize_source_ram(overlap, config()),
            Err(SourceRamBuildError::Declaration(_))
        ));
        overlap = declaration(vec![extent(0x6000, vec![1; 8], false)]);
        assert!(matches!(
            materialize_source_ram(overlap, config()),
            Err(SourceRamBuildError::Declaration(_))
        ));
        let mut overflow = declaration(vec![extent(0x1000, vec![1; 8], false)]);
        overflow.declared_capacity[0] = PhysicalRamRange {
            source_pa: u64::MAX - 3,
            bytes: 8,
        };
        assert!(matches!(
            materialize_source_ram(overflow, config()),
            Err(SourceRamBuildError::Declaration(_))
        ));
        let mut writable_code = extent(0x1000, vec![1; 8], true);
        writable_code.permissions.writable = true;
        assert!(matches!(
            materialize_source_ram(declaration(vec![writable_code]), config()),
            Err(SourceRamBuildError::Declaration(_))
        ));
    }

    #[test]
    fn metadata_fetch_check_never_mints_a_loan_and_initial_loan_excludes_service() {
        let physical = physical();
        let service = physical.domain.service_loan().unwrap();
        // The metadata check must succeed without a native borrow while the service
        // scope is held.
        physical.check_fetch_execution().unwrap();
        assert!(matches!(
            physical.initial_source_execution_loan(),
            Err(PhysicalReadPlatformError::Domain(MemoryStatus::Domain))
        ));
        physical.check_fetch_execution().unwrap();
        drop(service);
        let construction = physical.initial_source_execution_loan().unwrap();
        physical.check_execution_loan(&construction).unwrap();
        assert!(matches!(
            physical.domain.service_loan(),
            Err(MemoryStatus::Domain)
        ));
        drop(construction);
        physical.domain.service_loan().unwrap();
    }

    #[test]
    fn actual_ram_completion_retains_same_order_owner_and_cannot_be_replayed() {
        let actual = physical();
        let outer = actual.domain().execution_loan().unwrap();
        let mut prepared = actual.prepare_ram_completion(&outer).unwrap();
        assert_eq!(prepared.progress(), RamCompletionProgress::Unattempted);
        // A second session cannot bypass the machine's serializer.
        assert!(matches!(
            actual.prepare_ram_completion(&outer),
            Err(RamCompletionError::Ordering(_))
        ));
        prepared.complete().unwrap();
        assert_eq!(prepared.progress(), RamCompletionProgress::Completed);
        assert!(matches!(
            prepared.complete(),
            Err(RamCompletionError::AlreadyAttempted(
                RamCompletionProgress::Completed
            ))
        ));
        // Completion keeps its borrows until settlement.
        assert!(matches!(
            actual.prepare_ram_completion(&outer),
            Err(RamCompletionError::Ordering(_))
        ));
        drop(prepared);
        drop(actual.prepare_ram_completion(&outer).unwrap());
    }

    #[test]
    fn ram_completion_rejects_another_actual_domain_before_any_fence() {
        let actual = physical();
        let foreign = physical();
        let wrong_outer = foreign.domain().execution_loan().unwrap();
        assert!(matches!(
            actual.prepare_ram_completion(&wrong_outer),
            Err(RamCompletionError::Physical(_))
        ));
        let outer = actual.domain().execution_loan().unwrap();
        let mut prepared = actual.prepare_ram_completion(&outer).unwrap();
        prepared.complete().unwrap();
    }

    #[test]
    fn scalar_pins_cover_only_exact_narrow_quantities_at_real_extent_end() {
        let space = physical();
        let outer = space.domain().execution_loan().unwrap();
        for bytes in [1_u8, 2, 4, 8] {
            let address = 0x1020 - u64::from(bytes);
            let pin = space.resolve_ram_scalar(&outer, address, bytes).unwrap();
            assert_eq!(pin.bytes(), usize::from(bytes));
            assert_eq!(pin.pointer() as usize & (usize::from(bytes) - 1), 0);
            pin.check_current().unwrap();
            let (footprint, width) = access::read_footprint(
                pin.pointer() as usize,
                usize::from(bytes),
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(
                (footprint, width),
                (pin.pointer() as usize, usize::from(bytes))
            );
            // Resolution and footprint checks issue no target read. The adjacent
            // uninitialized capacity is not admitted by the backing allocation.
            assert!(space.resolve_ram_scalar(&outer, 0x1020, bytes).is_err());
        }
        assert!(matches!(
            space.resolve_ram_scalar(&outer, 0x101f, 2),
            Err(PhysicalReadPlatformError::Alignment)
        ));
        assert!(matches!(
            space.resolve_ram_scalar(&outer, 0x101c, 3),
            Err(PhysicalReadPlatformError::Domain(
                MemoryStatus::InvalidRequest
            ))
        ));
        let foreign = physical();
        let foreign_outer = foreign.domain().execution_loan().unwrap();
        assert!(space.resolve_ram_scalar(&foreign_outer, 0x101f, 1).is_err());
    }
}
