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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;

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
