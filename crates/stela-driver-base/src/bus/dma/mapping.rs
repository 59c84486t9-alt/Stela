//! Device-domain DMA leases. Every lease goes through a [`DmaDomain`] the
//! platform supplies: either an IOMMU domain (VT-d or AMD-Vi) that isolates
//! one requester, or the named passthrough domain, which maps the handoff's
//! DMA region at identity and leaves the device's DMA unrestricted, and which
//! the platform reports once when it hands one out. Drivers work with either;
//! code that needs isolation asks [`DmaDomain::kind`].
use super::pages::DmaPages;
use alloc::sync::Arc;
use core::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};

static QUARANTINED_MAPPINGS: AtomicU64 = AtomicU64::new(0);
static QUARANTINED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Cumulative kept resources whose owner dropped an active DMA lease.
/// These monotonic counters saturate instead of wrapping. They do not claim
/// that pages or translations have been reclaimed by reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuarantineStatus {
    pub mappings: u64,
    pub bytes: u64,
}

pub fn quarantine_status() -> QuarantineStatus {
    QuarantineStatus {
        mappings: QUARANTINED_MAPPINGS.load(Ordering::Relaxed),
        bytes: QUARANTINED_BYTES.load(Ordering::Relaxed),
    }
}

fn count_quarantine(counter: &AtomicU64, amount: u64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    ToDevice,
    FromDevice,
    Bidirectional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaError {
    Config(crate::bus::pci::ConfigError),
    PciCapability(crate::bus::pci::CapabilityError),
    IommuUnavailable,
    InvalidRange,
    AddressLimit,
    MappingFailed,
    InvalidationFailed,
    VisibilityFailed,
    CoherenceUnavailable,
    DrainUnavailable,
    Unmapped,
}
impl From<crate::bus::pci::ConfigError> for DmaError {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}
impl From<crate::bus::pci::CapabilityError> for DmaError {
    fn from(error: crate::bus::pci::CapabilityError) -> Self {
        Self::PciCapability(error)
    }
}

/// Whether a domain isolates its requester's DMA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainKind {
    /// An IOMMU domain: the requester reaches only the pages mapped into it.
    Isolated,
    /// Identity over the handoff's DMA region: a mapping's IOVA is its
    /// physical address, and the device can reach any memory.
    Passthrough,
}

/// An opaque unique mapping identifier plus its contiguous device IOVA span.
/// The identifier is interpreted only by the attached platform domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainMapping {
    pub id: u64,
    pub address: u64,
    pub bytes: usize,
}

/// A requester's DMA domain and its cache visibility operations.
///
/// # Safety
/// An [`Isolated`](DomainKind::Isolated) implementor binds the device's
/// requester to an IOMMU domain, maps this ordered page sequence (including
/// repeated-page aliases) with the direction's access permissions, and
/// finishes page-table visibility and required IOTLB invalidation before `map`
/// returns. A [`Passthrough`](DomainKind::Passthrough) implementor reports
/// that kind, maps only pages inside the handoff's DMA region, returns their
/// physical addresses as IOVAs and has no translation to invalidate; it
/// grants no isolation, and every other requirement here still holds. `Err` must leave no live translation, or quarantine the real pins,
/// hardware tables and domain reservation until acknowledged removal/reset;
/// the backend's own Drop must preserve such uncertain mappings. IOVAs must
/// fit `address_limit`. Mapping identifiers must be
/// unique until successful unmap; IOVAs must not alias other live allocations.
/// `unmap` must remove translations and complete all required invalidations
/// before success. On failure it must keep the mapping/domain reservation so
/// a retry cannot target reused state. Sync operations perform the platform's
/// cache/ordering work for the given direction, not just compiler
/// fences. A domain may not shut down while any lease keeps its Arc.
/// Implementations may require process/deferred context for every operation
/// and final release; Send/Sync does not imply hard-IRQ-safe release.
pub unsafe trait DmaDomain: Send + Sync {
    /// Whether this domain isolates its requester. The passthrough domain
    /// overrides this; code that needs isolation checks it.
    fn kind(&self) -> DomainKind {
        DomainKind::Isolated
    }
    /// # Safety
    /// Keep the supplied page pin and this domain until successful quiescent
    /// unmap; uncertain teardown must quarantine both. Prefer `DmaMapping`.
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        address_limit: u64,
    ) -> Result<DomainMapping, DmaError>;
    /// # Safety
    /// The mapping belongs to this domain, all device accesses have completed,
    /// and submissions/IRQ workers referencing it are stopped and drained.
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError>;
    /// # Safety
    /// The token is a live mapping from this domain, the direction matches
    /// its creation, and `range` is ordered and within its reserved bytes.
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError>;
    /// # Safety
    /// As for `sync_for_device`, and hardware completion establishes
    /// CPU ownership of this range before cache invalidation or CPU access.
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError>;

    /// Observe one little-endian word while the device may keep writing.
    ///
    /// Unlike `sync_for_cpu`, this transfers no ownership. Implementations
    /// must independently check coherent device/CPU access to the
    /// mapping's RAM; CPU WB policy or an ordering fence alone cannot
    /// grant that capability. Read from those exact pins, without accepting a
    /// caller's unrelated CPU pointer. Never invalidate a live device buffer.
    /// Each aligned word is an observation, not an atomic multiword snapshot
    /// or proof that firmware produced a new sample. Legacy backends refuse.
    ///
    /// # Safety
    /// The private mapping and direction belong to this domain and remain
    /// live. `offset..offset+4` is in bounds and naturally aligned. Ordinary
    /// CPU writers/references cannot race the device or this observation.
    unsafe fn read_coherent_u32(
        &self,
        _mapping: DomainMapping,
        _offset: usize,
        _direction: Direction,
    ) -> Result<u32, DmaError> {
        Err(DmaError::CoherenceUnavailable)
    }

    /// Complete previously issued translated DMA payload writes through this
    /// domain's owned remapper/root path.
    ///
    /// This does not stop a device, drain IRQ/work callbacks, remove mappings,
    /// or certify posted MSI, peer/bypass traffic, or accesses outside that
    /// translated payload path. Success must
    /// come from hardware completion, not BusMaster-clear, a CPU fence,
    /// or translation invalidation without its required write-drain semantics.
    /// Failure must keep the domain, translations, pins and root owners.
    ///
    /// # Safety
    /// Device engines and submissions are stopped and cannot issue new DMA.
    /// The driver keeps all target backing, configuration and root owners
    /// through this operation and subsequent IRQ/work drain and unmapping.
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        Err(DmaError::DrainUnavailable)
    }
}

/// Keeps the page pin and domain alive until quiescence, unmap and
/// completed IOTLB invalidation. The consumer owns device completion/fences.
///
/// A lease dropped without successful explicit `unmap` is quarantined: its
/// domain and pins are held. Drop cannot establish device
/// quiescence, and must never return potentially active DMA pages to a heap.
/// `quarantine_status` makes abandoned leases and kept bytes observable.
pub struct DmaMapping {
    domain: Option<Arc<dyn DmaDomain>>,
    pages: Option<DmaPages>,
    mapping: DomainMapping,
    direction: Direction,
}

impl DmaMapping {
    pub fn map(
        domain: Arc<dyn DmaDomain>,
        pages: impl Into<DmaPages>,
        direction: Direction,
        address_limit: u64,
    ) -> Result<Self, DmaError> {
        let pages = pages.into();
        // SAFETY: the lease keeps pages/domain through acknowledged unmap,
        // quarantining them if a caller drops it without proving quiescence.
        let mapping = unsafe { domain.map(&pages, direction, address_limit)? };
        let mut lease = Self {
            domain: Some(domain),
            pages: Some(pages),
            mapping,
            direction,
        };
        let valid = mapping.bytes == lease.pages.as_ref().expect("retained").bytes()
            && mapping.address.is_multiple_of(4096)
            && mapping
                .address
                .checked_add(mapping.bytes as u64 - 1)
                .is_some_and(|last| last <= address_limit);
        if !valid {
            // The IOVA has not been exposed, so no device may reference it.
            // SAFETY: this newly installed mapping has never been published.
            unsafe { lease.unmap()? };
            return Err(DmaError::AddressLimit);
        }
        Ok(lease)
    }

    /// An installed IOVA is not a device-publication barrier. Call
    /// `sync_for_device`, then the device's specified descriptor/doorbell order.
    pub fn address(&self) -> Result<u64, DmaError> {
        self.domain.as_ref().ok_or(DmaError::Unmapped)?;
        Ok(self.mapping.address)
    }

    pub fn bytes(&self) -> usize {
        self.mapping.bytes
    }

    fn domain(&self, range: &Range<usize>) -> Result<&dyn DmaDomain, DmaError> {
        if range.start > range.end || range.end > self.bytes() {
            return Err(DmaError::InvalidRange);
        }
        self.domain.as_deref().ok_or(DmaError::Unmapped)
    }

    pub fn sync_for_device(&self, range: Range<usize>) -> Result<(), DmaError> {
        let domain = self.domain(&range)?;
        // SAFETY: private token/direction came from this domain; the
        // live lease and checked range preserve its reserved bounds.
        unsafe { domain.sync_for_device(self.mapping, range, self.direction) }
    }

    /// # Safety
    /// The device has completed the relevant reads/writes and cannot access
    /// the range until the next ownership transfer. The consumer must observe
    /// the hardware completion/fence before reading CPU memory.
    pub unsafe fn sync_for_cpu(&self, range: Range<usize>) -> Result<(), DmaError> {
        let domain = self.domain(&range)?;
        // SAFETY: token/direction/bounds are held and checked; the caller
        // establishes hardware completion and CPU ownership of the range.
        unsafe { domain.sync_for_cpu(self.mapping, range, self.direction) }
    }

    /// Read a coherent little-endian word from this exact device mapping.
    /// Does not stop DMA or establish freshness/whole-record consistency.
    /// Unsupported backends explicitly return `CoherenceUnavailable`.
    pub fn read_coherent_u32(&self, offset: usize) -> Result<u32, DmaError> {
        let end = offset.checked_add(4).ok_or(DmaError::InvalidRange)?;
        let domain = self.domain(&(offset..end))?;
        if !offset.is_multiple_of(4) || self.direction == Direction::ToDevice {
            return Err(DmaError::InvalidRange);
        }
        // SAFETY: this private token/direction and checked aligned
        // range name the mapping. Safe CPU aliases expose no writers;
        // raw CPU access already requires the caller's synchronization.
        unsafe { domain.read_coherent_u32(self.mapping, offset, self.direction) }
    }

    /// Release only after hardware completion and a stopped submission path.
    /// An invalidation failure keeps the complete lease for retry/reset.
    ///
    /// # Safety
    /// All device accesses to this mapping have finished, submissions and IRQ
    /// workers referencing it are drained, and no new access can begin. The
    /// backend and backing's process/deferred-context restrictions apply.
    pub unsafe fn unmap(&mut self) -> Result<(), DmaError> {
        let domain = self.domain.as_ref().ok_or(DmaError::Unmapped)?;
        // SAFETY: the caller supplied hardware quiescence; this kept
        // mapping was created by exactly this domain and has not been reused.
        unsafe { domain.unmap(self.mapping)? };
        self.domain = None;
        self.pages = None;
        Ok(())
    }
}

impl Drop for DmaMapping {
    fn drop(&mut self) {
        if let Some(domain) = self.domain.take() {
            count_quarantine(&QUARANTINED_MAPPINGS, 1);
            count_quarantine(
                &QUARANTINED_BYTES,
                self.pages.as_ref().map_or(0, DmaPages::bytes) as u64,
            );
            core::mem::forget(domain);
            if let Some(pages) = self.pages.take() {
                core::mem::forget(pages);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::memory::{CacheAttribute, PageBacking, PinnedPages};
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        vec::Vec,
    };
    use core::{alloc::Layout, ptr::NonNull, sync::atomic::AtomicUsize};

    struct ModelBacking {
        pointer: NonNull<u8>,
        pages: Vec<u64>,
        released: Arc<AtomicUsize>,
    }
    // SAFETY: test-owned aligned RAM, immutable metadata, raw pointers only.
    unsafe impl Send for ModelBacking {}
    // SAFETY: no safe CPU references or asynchronous writes in this model.
    unsafe impl Sync for ModelBacking {}
    // SAFETY: this model's owned RAM represents one physical page;
    // no hardware DMA or privileged physical mapping is claimed by the test.
    unsafe impl PageBacking for ModelBacking {
        fn cpu_base(&self) -> NonNull<u8> {
            self.pointer
        }
        fn physical_pages(&self) -> &[u64] {
            &self.pages
        }
        fn page_shift(&self) -> u8 {
            12
        }
        fn cache_attribute(&self) -> CacheAttribute {
            CacheAttribute::WriteBack
        }
    }
    impl Drop for ModelBacking {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::Relaxed);
            // SAFETY: exactly the model's unique live aligned allocation.
            unsafe {
                dealloc(
                    self.pointer.as_ptr(),
                    Layout::from_size_align(4096, 4096).unwrap(),
                )
            };
        }
    }
    struct ModelDomain;
    // SAFETY: synchronous model, no hardware translations. The test
    // specifically verifies resource ownership when no quiescence is proven.
    unsafe impl DmaDomain for ModelDomain {
        unsafe fn map(
            &self,
            pages: &DmaPages,
            _: Direction,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            if limit < 0x20fff {
                return Err(DmaError::AddressLimit);
            }
            Ok(DomainMapping {
                id: 1,
                address: 0x20000,
                bytes: pages.bytes(),
            })
        }
        unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            Ok(())
        }
    }

    #[test]
    fn abandoned_active_dma_is_quarantined_with_its_backing() {
        let released = Arc::new(AtomicUsize::new(0));
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        // SAFETY: uniquely owned model RAM, released only by backing.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let pages = PinnedPages::new(
            Box::new(ModelBacking {
                pointer,
                pages: vec![0x500000],
                released: released.clone(),
            }),
            4096,
            4096,
        )
        .unwrap();
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let domain = Arc::new(ModelDomain);
        let before = quarantine_status();
        let lease =
            DmaMapping::map(domain.clone(), pages, Direction::Bidirectional, u64::MAX).unwrap();
        drop(lease);
        drop(cpu);
        assert_eq!(released.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&domain), 2);
        let after = quarantine_status();
        // Other driver tests may quarantine their own leases concurrently.
        // These global monotonic counters include at least this exact lease;
        // the checks above independently prove its own backing/domain remain.
        assert!(after.mappings > before.mappings);
        assert!(after.bytes >= before.bytes + 4096);
        // Deliberate kept allocation: no fake completion/reset is supplied.
    }

    #[test]
    fn a_domain_is_isolated_unless_it_reports_passthrough() {
        assert_eq!(ModelDomain.kind(), DomainKind::Isolated);
    }

    #[test]
    fn legacy_visibility_does_not_grant_continuous_reads_or_posted_write_drain() {
        let domain = Arc::new(ModelDomain);
        assert_eq!(
            // SAFETY: this synchronous model has no hardware, but its legacy visibility methods
            // must not imply the new independent capabilities.
            unsafe { domain.drain_posted_writes() },
            Err(DmaError::DrainUnavailable)
        );
        for direction in [
            Direction::FromDevice,
            Direction::Bidirectional,
            Direction::ToDevice,
        ] {
            let released = Arc::new(AtomicUsize::new(0));
            let layout = Layout::from_size_align(4096, 4096).unwrap();
            // SAFETY: zeroed, uniquely kept model RAM.
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            let pin = PinnedPages::new(
                Box::new(ModelBacking {
                    pointer,
                    pages: vec![0x10000],
                    released: released.clone(),
                }),
                4096,
                4096,
            )
            .unwrap();
            let mut lease = DmaMapping::map(domain.clone(), pin, direction, u64::MAX).unwrap();
            for offset in [1, 4093, 4096, usize::MAX] {
                assert_eq!(lease.read_coherent_u32(offset), Err(DmaError::InvalidRange));
            }
            let error = if direction == Direction::ToDevice {
                DmaError::InvalidRange
            } else {
                DmaError::CoherenceUnavailable
            };
            assert_eq!(lease.read_coherent_u32(0), Err(error));
            assert_eq!(lease.read_coherent_u32(4092), Err(error));
            assert_eq!(released.load(Ordering::Relaxed), 0);
            // SAFETY: no modeled device or worker ever received this mapping.
            unsafe { lease.unmap() }.unwrap();
            assert_eq!(released.load(Ordering::Relaxed), 1);
            assert_eq!(lease.read_coherent_u32(0), Err(DmaError::Unmapped));
        }
    }
}
