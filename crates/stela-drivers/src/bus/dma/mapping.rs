//! Device-domain DMA leases. A physical page list is never an identity-DMA
//! fallback. The platform supplies a real attached VT-d/AMD-Vi domain.
use super::memory::PinnedPages;
use alloc::sync::Arc;
use core::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};

static QUARANTINED_MAPPINGS: AtomicU64 = AtomicU64::new(0);
static QUARANTINED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Cumulative retained resources whose owner dropped an active DMA lease.
/// These monotonic counters saturate instead of wrapping. They do not claim
/// that retained pages or translations have been reclaimed by reset.
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
    IommuUnavailable,
    InvalidRange,
    AddressLimit,
    MappingFailed,
    InvalidationFailed,
    VisibilityFailed,
    Unmapped,
}

/// An opaque unique mapping identifier plus its contiguous device IOVA span.
/// The identifier is interpreted only by the attached platform domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainMapping {
    pub id: u64,
    pub address: u64,
    pub bytes: usize,
}

/// Real platform IOMMU ownership and cache visibility operations.
///
/// # Safety
/// Implementors must bind the actual device/requester to an isolated domain,
/// map exactly these pinned pages with the direction's access permissions, and
/// finish page-table visibility and required IOTLB invalidation before `map`
/// returns. `Err` must leave no live translation, or quarantine the real pins,
/// hardware tables and domain reservation until acknowledged removal/reset;
/// the backend's own Drop must preserve such uncertain mappings. IOVAs must
/// fit `address_limit`. Mapping identifiers must be
/// unique until successful unmap; IOVAs must not alias other live allocations.
/// `unmap` must remove translations and complete all required invalidations
/// before success. On failure it must retain the mapping/domain reservation so
/// a retry cannot target reused state. Sync operations perform the platform's
/// actual cache/ordering work for the given direction, not just compiler
/// fences. A domain may not shut down while any lease retains its Arc.
/// Implementations may require process/deferred context for every operation
/// and final release; Send/Sync does not imply hard-IRQ-safe release.
pub unsafe trait DmaDomain: Send + Sync {
    /// # Safety
    /// Retain the supplied page pin and this domain until successful quiescent
    /// unmap; uncertain teardown must quarantine both. Prefer `DmaMapping`.
    unsafe fn map(
        &self,
        pages: &PinnedPages,
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
    /// As for `sync_for_device`, and actual hardware completion establishes
    /// CPU ownership of this range before cache invalidation or CPU access.
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError>;
}

/// Keeps the actual page pin and domain alive until quiescence, unmap and
/// completed IOTLB invalidation. The consumer owns device completion/fences.
///
/// A lease dropped without successful explicit `unmap` is quarantined: its
/// domain and pins are deliberately retained. Drop cannot establish device
/// quiescence, and must never return potentially active DMA pages to a heap.
/// `quarantine_status` makes abandoned leases and retained bytes observable.
pub struct DmaMapping {
    domain: Option<Arc<dyn DmaDomain>>,
    pages: Option<PinnedPages>,
    mapping: DomainMapping,
    direction: Direction,
}

impl DmaMapping {
    pub fn map(
        domain: Arc<dyn DmaDomain>,
        pages: PinnedPages,
        direction: Direction,
        address_limit: u64,
    ) -> Result<Self, DmaError> {
        // SAFETY: the lease retains pages/domain through acknowledged unmap,
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
        // SAFETY: private token/direction came from this retained domain; the
        // live lease and checked range preserve its actual reserved bounds.
        unsafe { domain.sync_for_device(self.mapping, range, self.direction) }
    }

    /// # Safety
    /// The device has completed the relevant reads/writes and cannot access
    /// the range until the next ownership transfer. The consumer must observe
    /// the actual hardware completion/fence before reading CPU memory.
    pub unsafe fn sync_for_cpu(&self, range: Range<usize>) -> Result<(), DmaError> {
        let domain = self.domain(&range)?;
        // SAFETY: token/direction/bounds are retained and checked; the caller
        // establishes hardware completion and CPU ownership of the range.
        unsafe { domain.sync_for_cpu(self.mapping, range, self.direction) }
    }

    /// Release only after hardware completion and a stopped submission path.
    /// An invalidation failure retains the complete lease for retry/reset.
    ///
    /// # Safety
    /// All device accesses to this mapping have finished, submissions and IRQ
    /// workers referencing it are drained, and no new access can begin. The
    /// backend and backing's process/deferred-context restrictions apply.
    pub unsafe fn unmap(&mut self) -> Result<(), DmaError> {
        let domain = self.domain.as_ref().ok_or(DmaError::Unmapped)?;
        // SAFETY: the caller supplied hardware quiescence; this retained
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
                self.pages.as_ref().map_or(0, PinnedPages::bytes) as u64,
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
    use crate::bus::dma::memory::{CacheAttribute, PageBacking};
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
    // SAFETY: this model's owned RAM represents one retained physical page;
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
    // SAFETY: synchronous model, no actual hardware translations. The test
    // specifically verifies resource ownership when no quiescence is proven.
    unsafe impl DmaDomain for ModelDomain {
        unsafe fn map(
            &self,
            pages: &PinnedPages,
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
    fn abandoning_active_dma_retains_real_backing_and_domain_and_reports_quarantine() {
        let released = Arc::new(AtomicUsize::new(0));
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        // SAFETY: actual uniquely owned model RAM, released only by backing.
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
        // Deliberate retained allocation: no fake completion/reset is supplied.
    }
}
