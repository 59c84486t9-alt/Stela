//! Owned Xe GuC CT RAM preparation. This does not install GGTT mappings,
//! register/enable firmware transport, route interrupts or establish coherent
//! concurrent firmware access. Those missing operations remain owner duties.
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
};
use alloc::sync::Arc;

// Retained xe_guc_ct.c: separate BOs; descriptors are 64 bytes at H2G offset 0
// and G2H offset 0x800. Commands start at 0x1000 in each BO.
const DESCRIPTOR_BYTES: usize = 16 * 4;
const COMMAND_OFFSET: usize = 4096;
pub const H2G_COMMAND_BYTES: usize = 4096;
pub const G2H_COMMAND_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Memory(MemoryError),
    Dma(DmaError),
    InvalidAllocation,
}

impl From<MemoryError> for StorageError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}
impl From<DmaError> for StorageError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtBuffer {
    HostToGuc,
    GucToHost,
}

/// Matches the four region selectors in the retained native CT I/O adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CtRegion {
    H2gDescriptor,
    H2gCommands,
    G2hDescriptor,
    G2hCommands,
}

struct Buffer {
    dma: Option<DmaMapping>,
    descriptor: CpuMapping,
    commands: CpuMapping,
}

impl Buffer {
    fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        command_bytes: usize,
        descriptor_offset: usize,
        address_limit: u64,
    ) -> Result<Self, StorageError> {
        let bytes = COMMAND_OFFSET + command_bytes;
        let pages = source.allocate(bytes, 4096, CacheAttribute::WriteBack)?;
        if pages.logical_bytes() != bytes || pages.cache_attribute() != CacheAttribute::WriteBack {
            return Err(StorageError::InvalidAllocation);
        }
        // Canonical PageSource/PageBacking owns zeroing, reservations, cache
        // attributes and the mapping. No allocator or physical address fallback.
        let descriptor = pages.cpu_mapping_range(
            CacheAttribute::WriteBack,
            descriptor_offset..descriptor_offset + DESCRIPTOR_BYTES,
        )?;
        let commands = pages.cpu_mapping_range(CacheAttribute::WriteBack, COMMAND_OFFSET..bytes)?;
        let dma = DmaMapping::map(domain, pages, Direction::Bidirectional, address_limit)?;
        Ok(Self {
            dma: Some(dma),
            descriptor,
            commands,
        })
    }

    fn mapping(&self) -> Result<&DmaMapping, DmaError> {
        self.dma.as_ref().ok_or(DmaError::Unmapped)
    }

    /// # Safety
    /// No device, GGTT binding, submission or IRQ worker may reference this
    /// allocation now or begin doing so during/after the removal.
    unsafe fn unmap(&mut self) -> Result<(), DmaError> {
        if let Some(mapping) = self.dma.as_mut() {
            // SAFETY: the private unpublished owner or public quiescent owner
            // establishes the complete device/worker stop requirement.
            unsafe { mapping.unmap()? };
            self.dma = None;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Storage {
    h2g: Option<Buffer>,
    g2h: Option<Buffer>,
}

impl Storage {
    fn buffer(&self, which: CtBuffer) -> &Buffer {
        match which {
            CtBuffer::HostToGuc => self.h2g.as_ref(),
            CtBuffer::GucToHost => self.g2h.as_ref(),
        }
        .expect("only complete CT storage is exposed")
    }

    fn region(&self, which: CtRegion) -> &CpuMapping {
        match which {
            CtRegion::H2gDescriptor => &self.buffer(CtBuffer::HostToGuc).descriptor,
            CtRegion::H2gCommands => &self.buffer(CtBuffer::HostToGuc).commands,
            CtRegion::G2hDescriptor => &self.buffer(CtBuffer::GucToHost).descriptor,
            CtRegion::G2hCommands => &self.buffer(CtBuffer::GucToHost).commands,
        }
    }

    /// # Safety
    /// Both allocations satisfy Buffer::unmap's complete quiescence contract.
    unsafe fn unmap(&mut self) -> Result<(), DmaError> {
        // Try both independent removals. A failed lease stays retained for
        // retry, while successful removal never targets a reused token again.
        let h2g = self.h2g.as_mut().map_or(Ok(()), |buffer| {
            // SAFETY: the caller establishes quiescence for both buffers.
            unsafe { buffer.unmap() }
        });
        let g2h = self.g2h.as_mut().map_or(Ok(()), |buffer| {
            // SAFETY: the caller establishes quiescence for both buffers.
            unsafe { buffer.unmap() }
        });
        h2g.and(g2h)
    }
}

/// Storage whose DMA addresses have never been exposed by this API. Explicit
/// rollback can remove those mappings; Drop uses canonical DMA quarantine
/// because it cannot establish the domain's allowed process/deferred context.
/// CPU views expose raw pointers, never Rust buffer references.
pub struct UnpublishedCtStorage {
    storage: Storage,
}

impl UnpublishedCtStorage {
    pub fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        address_limit: u64,
    ) -> Result<Self, StorageError> {
        let mut result = Self {
            storage: Storage::default(),
        };
        let allocate = (|| -> Result<(), StorageError> {
            result.storage.h2g = Some(Buffer::allocate(
                source,
                Arc::clone(&domain),
                H2G_COMMAND_BYTES,
                0,
                address_limit,
            )?);
            result.storage.g2h = Some(Buffer::allocate(
                source,
                domain,
                G2H_COMMAND_BYTES,
                2048,
                address_limit,
            )?);
            Ok(())
        })();
        if let Err(error) = allocate {
            // Same process/deferred context as the successful map operation;
            // no device address was exposed, so no completion is invented.
            result.rollback()?;
            return Err(error);
        }
        Ok(result)
    }

    /// The borrowed canonical CPU mapping retains its pin. Dereferencing a raw
    /// address requires exclusive CPU access and this storage's live lifetime.
    /// No device IOVA or GGTT address is available in the unpublished state.
    pub fn cpu_region(&self, region: CtRegion) -> &CpuMapping {
        self.storage.region(region)
    }

    /// Remove mappings that have never been exposed to the device. Call in
    /// the domain's allowed process/deferred context. Failed leases remain
    /// retained for retry; abandoning them invokes canonical quarantine.
    pub fn rollback(&mut self) -> Result<(), DmaError> {
        // SAFETY: only the unpublished type offers this safe operation, and
        // it has no API exposing an IOVA or installing a GGTT/device binding.
        unsafe { self.storage.unmap() }
    }

    /// Consume the unpublished state and complete the domain's actual DMA
    /// visibility operations before exposing any IOVA. This is a conservative
    /// publication boundary, not firmware registration or an enable ack. The
    /// owner can now install real GPU GGTT bindings and register/enable CT.
    /// Once addresses can escape, Drop never assumes device completion.
    pub fn publish(mut self) -> Result<PublishedCtStorage, StorageError> {
        let prepare = (|| -> Result<(), DmaError> {
            for which in [CtBuffer::HostToGuc, CtBuffer::GucToHost] {
                let mapping = self.storage.buffer(which).mapping()?;
                mapping.sync_for_device(0..mapping.bytes())?;
            }
            Ok(())
        })();
        if let Err(error) = prepare {
            self.rollback()?;
            return Err(error.into());
        }
        Ok(PublishedCtStorage {
            storage: self.storage,
        })
    }
}

/// Potentially published leases. `mapping().address()` is device IOVA, NEVER
/// GuC GGTT VA. Firmware registration requires separate real GGTT ownership.
/// Active CT access additionally needs actual concurrent DMA coherence, GT
/// power/forcewake, ordered MMIO and IRQ/fence ownership. This helper supplies
/// none of those services and must not be attached to CT callbacks as a proxy.
pub struct PublishedCtStorage {
    storage: Storage,
}

impl PublishedCtStorage {
    pub fn mapping(&self, buffer: CtBuffer) -> Result<&DmaMapping, DmaError> {
        self.storage.buffer(buffer).mapping()
    }

    /// Raw CPU views only. The owner must retain this storage while pointers
    /// are used, prove the device's real coherence/ownership protocol for each
    /// access and serialize CPU/firmware/IRQ users. No safe slice is exposed.
    /// DmaMapping::sync_for_cpu still requires its actual exclusive-completion
    /// contract; it cannot be used to pretend a concurrent GuC descriptor is
    /// quiescent. WB CPU cache policy alone does not prove device coherence.
    pub fn cpu_region(&self, region: CtRegion) -> &CpuMapping {
        self.storage.region(region)
    }

    /// # Safety
    /// Firmware CT is actually disabled/acknowledged, device accesses have
    /// ended, submissions and IRQ workers are stopped/drained, real GGTT
    /// bindings are removed with completed GT invalidation, and no future
    /// accesses can begin. Owner process/context restrictions still apply.
    /// Errors retain failed leases for retry; abandoning them quarantines the
    /// actual pages/domain. This method never manufactures completion proof.
    pub unsafe fn unmap_after_quiescence(&mut self) -> Result<(), DmaError> {
        // SAFETY: the caller establishes the complete hardware/worker stop.
        unsafe { self.storage.unmap() }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::bus::dma::memory::{PageBacking, PinnedPages};
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        vec::Vec,
    };
    use core::{
        alloc::Layout,
        ptr::NonNull,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use std::sync::Mutex;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Map(u64, usize, usize),
        Sync(u64, usize),
        Unmap(u64),
    }

    #[derive(Default)]
    struct Model {
        events: Mutex<Vec<Event>>,
        allocations: AtomicUsize,
        released: AtomicUsize,
        maps: AtomicUsize,
        syncs: AtomicUsize,
        fail_allocate: AtomicUsize,
        fail_map: AtomicUsize,
        fail_sync: AtomicUsize,
        fail_unmap_id: AtomicUsize,
        invalid_logical: AtomicUsize,
        invalid_span: AtomicUsize,
    }

    struct Backing {
        address: NonNull<u8>,
        layout: Layout,
        pages: Vec<u64>,
        model: Arc<Model>,
    }
    // SAFETY: model-only owned aligned CPU RAM, immutable metadata and no
    // hardware DMA or safe references. Fixture physical numbers are not used
    // as actual physical addresses by any platform implementation.
    unsafe impl Send for Backing {}
    // SAFETY: same model-only allocation; all mutation uses checked raw access.
    unsafe impl Sync for Backing {}
    // SAFETY: this synchronous model owns/zeros/frees its host allocation;
    // fixture page numbers simulate reservations without privileged mappings.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            self.address
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
    impl Drop for Backing {
        fn drop(&mut self) {
            self.model.released.fetch_add(1, Ordering::Relaxed);
            // SAFETY: exactly this backing's unique live model allocation.
            unsafe { dealloc(self.address.as_ptr(), self.layout) };
        }
    }

    impl PageSource for Arc<Model> {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert_eq!(alignment, 4096);
            assert_eq!(attribute, CacheAttribute::WriteBack);
            let index = self.allocations.fetch_add(1, Ordering::Relaxed) + 1;
            if self.fail_allocate.load(Ordering::Relaxed) == index {
                return Err(MemoryError::OutOfMemory);
            }
            // Extra native page tests logical ranges independently of reserved
            // bytes. Production code never allocates pages itself.
            let reserved = bytes.div_ceil(4096) * 4096 + 4096;
            let layout = Layout::from_size_align(reserved, alignment).unwrap();
            // SAFETY: valid nonzero model layout, checked for allocation failure.
            let address =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            let backing = Backing {
                address,
                layout,
                model: Arc::clone(self),
                pages: (0..reserved / 4096)
                    .map(|page| 0x1000_0000 + index as u64 * 0x10_0000 + page as u64 * 4096)
                    .collect(),
            };
            PinnedPages::new(
                Box::new(backing),
                if self.invalid_logical.load(Ordering::Relaxed) != 0 {
                    bytes - 1
                } else {
                    bytes
                },
                alignment,
            )
        }
    }

    // SAFETY: synchronous ownership/failure model only, not an IOMMU backend.
    // No hardware observes fixture IOVAs; unmap/sync record exact tokens/ranges.
    unsafe impl DmaDomain for Model {
        unsafe fn map(
            &self,
            pages: &crate::bus::dma::pages::DmaPages,
            direction: Direction,
            _: u64,
        ) -> Result<crate::bus::dma::mapping::DomainMapping, DmaError> {
            let pages = pages.as_single().ok_or(DmaError::MappingFailed)?;
            assert_eq!(direction, Direction::Bidirectional);
            let id = self.maps.fetch_add(1, Ordering::Relaxed) + 1;
            self.events.lock().unwrap().push(Event::Map(
                id as u64,
                pages.logical_bytes(),
                pages.bytes(),
            ));
            if self.fail_map.load(Ordering::Relaxed) == id {
                return Err(DmaError::MappingFailed);
            }
            Ok(crate::bus::dma::mapping::DomainMapping {
                id: id as u64,
                address: 0x8000_0000 + id as u64 * 0x10_0000,
                bytes: pages.bytes()
                    - if self.invalid_span.load(Ordering::Relaxed) != 0 {
                        4096
                    } else {
                        0
                    },
            })
        }
        unsafe fn unmap(
            &self,
            mapping: crate::bus::dma::mapping::DomainMapping,
        ) -> Result<(), DmaError> {
            self.events.lock().unwrap().push(Event::Unmap(mapping.id));
            if self.fail_unmap_id.load(Ordering::Relaxed) as u64 == mapping.id {
                Err(DmaError::InvalidationFailed)
            } else {
                Ok(())
            }
        }
        unsafe fn sync_for_device(
            &self,
            mapping: crate::bus::dma::mapping::DomainMapping,
            range: core::ops::Range<usize>,
            direction: Direction,
        ) -> Result<(), DmaError> {
            assert_eq!(range.start, 0);
            assert_eq!(range.end, mapping.bytes);
            assert_eq!(direction, Direction::Bidirectional);
            self.events
                .lock()
                .unwrap()
                .push(Event::Sync(mapping.id, range.len()));
            let index = self.syncs.fetch_add(1, Ordering::Relaxed) + 1;
            if self.fail_sync.load(Ordering::Relaxed) == index {
                Err(DmaError::VisibilityFailed)
            } else {
                Ok(())
            }
        }
        unsafe fn sync_for_cpu(
            &self,
            _: crate::bus::dma::mapping::DomainMapping,
            _: core::ops::Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            panic!("CT storage must never pretend active firmware has completed")
        }
    }

    fn allocate(model: &Arc<Model>) -> Result<UnpublishedCtStorage, StorageError> {
        let domain: Arc<dyn DmaDomain> = model.clone();
        UnpublishedCtStorage::allocate(model, domain, u64::MAX)
    }

    #[test]
    fn exact_layout_real_visibility_order_and_explicit_quiescent_release() {
        let model = Arc::new(Model::default());
        let storage = allocate(&model).unwrap();
        for (region, range) in [
            (CtRegion::H2gDescriptor, 0..64),
            (CtRegion::H2gCommands, 4096..8192),
            (CtRegion::G2hDescriptor, 2048..2112),
            (CtRegion::G2hCommands, 4096..135168),
        ] {
            let cpu = storage.cpu_region(region);
            assert_eq!(cpu.range(), range);
            assert_eq!(cpu.address(cpu.bytes(), 1), Err(MemoryError::InvalidSize));
            assert_eq!(
                // SAFETY: unpublished model allocation, exclusive CPU ownership, aligned live
                // pointer; no device has received any IOVA.
                unsafe { cpu.address(0, 4).unwrap().cast::<u32>().as_ptr().read() },
                0
            );
        }
        let mut published = storage.publish().unwrap();
        assert_eq!(
            *model.events.lock().unwrap(),
            [
                Event::Map(1, 8192, 12288),
                Event::Map(2, 135168, 139264),
                Event::Sync(1, 12288),
                Event::Sync(2, 139264)
            ]
        );
        let iova = published
            .mapping(CtBuffer::HostToGuc)
            .unwrap()
            .address()
            .unwrap();
        assert_eq!(iova, 0x8010_0000); // Neither fixture physical PA nor GGTT VA.
        // SAFETY: model has no hardware, GGTT bindings, firmware or IRQ workers.
        unsafe { published.unmap_after_quiescence() }.unwrap();
        assert!(matches!(
            published.mapping(CtBuffer::HostToGuc),
            Err(DmaError::Unmapped)
        ));
        assert!(matches!(
            published.mapping(CtBuffer::GucToHost),
            Err(DmaError::Unmapped)
        ));
        assert_eq!(model.released.load(Ordering::Relaxed), 0); // CPU views retain pins.
        drop(published);
        assert_eq!(model.released.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn second_allocation_or_mapping_failure_rolls_back_only_unpublished_resources() {
        for fail_map in [false, true] {
            let model = Arc::new(Model::default());
            if fail_map {
                model.fail_map.store(2, Ordering::Relaxed);
            } else {
                model.fail_allocate.store(2, Ordering::Relaxed);
            }
            let error = allocate(&model).err().unwrap();
            assert_eq!(
                error,
                if fail_map {
                    StorageError::Dma(DmaError::MappingFailed)
                } else {
                    StorageError::Memory(MemoryError::OutOfMemory)
                }
            );
            assert_eq!(
                model.released.load(Ordering::Relaxed),
                if fail_map { 2 } else { 1 }
            );
            assert_eq!(model.events.lock().unwrap().last(), Some(&Event::Unmap(1)));
            assert_eq!(model.syncs.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn failed_publication_sync_returns_no_address_and_rolls_back_both_mappings() {
        let model = Arc::new(Model::default());
        model.fail_sync.store(2, Ordering::Relaxed);
        assert!(matches!(
            allocate(&model).unwrap().publish(),
            Err(StorageError::Dma(DmaError::VisibilityFailed))
        ));
        assert_eq!(model.released.load(Ordering::Relaxed), 2);
        assert_eq!(
            &model.events.lock().unwrap()[4..],
            [Event::Unmap(1), Event::Unmap(2)]
        );
    }

    #[test]
    fn drop_never_assumes_quiescence_or_an_allowed_unmap_context() {
        for publish in [false, true] {
            let model = Arc::new(Model::default());
            let storage = allocate(&model).unwrap();
            if publish {
                drop(storage.publish().unwrap());
            } else {
                drop(storage);
            }
            assert_eq!(model.released.load(Ordering::Relaxed), 0);
            assert!(
                !model
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|event| matches!(event, Event::Unmap(_)))
            );
        }
    }

    #[test]
    fn failed_teardown_retains_exact_lease_and_successful_token_is_not_reused() {
        let model = Arc::new(Model::default());
        let mut published = allocate(&model).unwrap().publish().unwrap();
        model.fail_unmap_id.store(1, Ordering::Relaxed);
        assert_eq!(
            // SAFETY: synchronous model, no hardware or asynchronous users.
            unsafe { published.unmap_after_quiescence() },
            Err(DmaError::InvalidationFailed)
        );
        assert_eq!(
            published.mapping(CtBuffer::HostToGuc).unwrap().address(),
            Ok(0x8010_0000)
        );
        assert!(matches!(
            published.mapping(CtBuffer::GucToHost),
            Err(DmaError::Unmapped)
        ));
        model.fail_unmap_id.store(0, Ordering::Relaxed);
        // SAFETY: the same full model quiescence still holds for the retry.
        unsafe { published.unmap_after_quiescence() }.unwrap();
        assert_eq!(
            model
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == Event::Unmap(2))
                .count(),
            1
        );
        drop(published);
        assert_eq!(model.released.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn explicit_unpublished_rollback_prevents_later_publication() {
        let model = Arc::new(Model::default());
        let mut storage = allocate(&model).unwrap();
        storage.rollback().unwrap();
        assert!(matches!(
            storage.publish(),
            Err(StorageError::Dma(DmaError::Unmapped))
        ));
        assert_eq!(model.released.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failed_rollback_reports_invalidation_and_quarantines_the_live_lease() {
        let model = Arc::new(Model::default());
        model.fail_allocate.store(2, Ordering::Relaxed);
        model.fail_unmap_id.store(1, Ordering::Relaxed);
        assert!(matches!(
            allocate(&model),
            Err(StorageError::Dma(DmaError::InvalidationFailed))
        ));
        assert_eq!(model.released.load(Ordering::Relaxed), 0);
        assert_eq!(
            *model.events.lock().unwrap(),
            [Event::Map(1, 8192, 12288), Event::Unmap(1)]
        );
        assert_eq!(model.syncs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn address_limit_applies_to_the_whole_reserved_dma_mapping() {
        let model = Arc::new(Model::default());
        let domain: Arc<dyn DmaDomain> = model.clone();
        // Model base plus logical bytes fits; the extra reserved native page
        // crosses this limit and must be removed before publication.
        assert!(matches!(
            UnpublishedCtStorage::allocate(&model, domain, 0x8010_1fff),
            Err(StorageError::Dma(DmaError::AddressLimit))
        ));
        assert_eq!(model.released.load(Ordering::Relaxed), 1);
        assert_eq!(
            *model.events.lock().unwrap(),
            [Event::Map(1, 8192, 12288), Event::Unmap(1)]
        );
        assert_eq!(model.syncs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn invalid_source_logical_length_or_domain_span_is_not_published() {
        for span in [false, true] {
            let model = Arc::new(Model::default());
            if span {
                model.invalid_span.store(1, Ordering::Relaxed);
            } else {
                model.invalid_logical.store(1, Ordering::Relaxed);
            }
            let error = allocate(&model).err().unwrap();
            assert_eq!(
                error,
                if span {
                    StorageError::Dma(DmaError::AddressLimit)
                } else {
                    StorageError::InvalidAllocation
                }
            );
            assert_eq!(model.released.load(Ordering::Relaxed), 1);
            assert_eq!(model.syncs.load(Ordering::Relaxed), 0);
        }
    }
}
