//! Owned system-RAM storage for amdgpu's CPU page-table writer.
//!
//! This module does not create a BO, GPU VM/root binding or GPU address space.
//! The canonical platform allocator and attached DMA domain supply all storage.
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
};
use alloc::sync::Arc;
use core::{ffi::c_void, marker::PhantomData};

/// AMDGPU_GPU_PAGE_SIZE in the amdgpu headers, independently of the
/// native CPU page size. These are ordinary system-memory leaf PTE updates.
pub const GPU_PAGE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Memory(MemoryError),
    Dma(DmaError),
    InvalidRange,
    MappingUnavailable,
}

/// An error after CPU stores may leave a modified, unpublished table. The real
/// owner must keep both table and source leases, then retry visibility or
/// tear down under GPU quiescence. No rollback or GPU flush is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateError {
    pub error: StorageError,
    pub written: u32,
}

/// Exact request to the existing CPU PTE loop. Flags and override selection
/// must come from the initialized GMC/VM policy, never a generic default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemPageUpdate {
    pub table_offset: usize,
    pub source_offset: usize,
    pub count: u32,
    pub flags: u64,
    pub override_pte: bool,
}

/// Exact invalid-entry policy selected by the initialized GMC/VM owner.
/// `flags` must encode an invalid entry for that table and generation;
/// clearing address bits alone does not invalidate a GPU translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemPageClear {
    pub table_offset: usize,
    pub count: u32,
    pub flags: u64,
}

/// Initialized GMC entry operations, borrowed for synchronous calls.
/// These functions must not unwind or keep the table pointer.
pub struct GmcCpuCallbacks<'a> {
    context: *mut c_void,
    override_flags: unsafe extern "C" fn(*mut c_void, u64, *mut u64),
    set_pte_pde: unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64, u64),
    _borrow: PhantomData<&'a mut c_void>,
}

impl<'a> GmcCpuCallbacks<'a> {
    /// Borrow the device/VM owner's initialized generation callbacks.
    ///
    /// # Safety
    /// `context` and both callbacks must remain valid and exclusively borrowed
    /// for `'a`. They must implement the real GMC override and entry-write
    /// algorithms, including architecture-correct stores and flags. Every call
    /// must be synchronous, infallible for its prevalidated range, non-reentrant
    /// and non-unwinding. The override must resolve RAM/NUMA/coherency
    /// facts without treating domain IOVAs as CPU physical addresses. Callers
    /// must not supply placeholders or infer device initialization from PCI ID.
    pub unsafe fn borrow_initialized(
        context: *mut c_void,
        override_flags: unsafe extern "C" fn(*mut c_void, u64, *mut u64),
        set_pte_pde: unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64, u64),
    ) -> Self {
        Self {
            context,
            override_flags,
            set_pte_pde,
            _borrow: PhantomData,
        }
    }
}

/// CPU and domain mappings from the same canonical reserved RAM allocation.
/// Dropping an active DMA lease uses canonical quarantine, keeping the real
/// pages and domain. Explicit release requires GPU quiescence and process or
/// deferred context; this type cannot prove those hardware conditions.
pub struct RamPageTable {
    cpu: CpuMapping,
    dma: DmaMapping,
}

impl RamPageTable {
    /// Allocate real table storage using the platform's existing page source
    /// and attached requester domain. `alignment`, cache policy and address
    /// limit must satisfy the device's requirements. Failure propagates
    /// the real service error; no identity-DMA or heap fallback exists.
    /// This does not publish or register the storage with a GPU.
    pub fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        address_limit: u64,
    ) -> Result<Self, StorageError> {
        if bytes == 0 || !bytes.is_multiple_of(size_of::<u64>()) || !alignment.is_power_of_two() {
            return Err(StorageError::InvalidRange);
        }
        let pages = source
            .allocate(bytes, alignment, attribute)
            .map_err(StorageError::Memory)?;
        if pages.logical_bytes() != bytes || pages.alignment() < alignment {
            return Err(StorageError::Memory(MemoryError::InvalidSize));
        }
        let cpu = pages
            .cpu_mapping_range(attribute, 0..bytes)
            .map_err(StorageError::Memory)?;
        let mut dma = DmaMapping::map(domain, pages, Direction::ToDevice, address_limit)
            .map_err(StorageError::Dma)?;
        if !dma
            .address()
            .map_err(StorageError::Dma)?
            .is_multiple_of(alignment as u64)
        {
            // SAFETY: this new mapping has not been exposed to any GPU owner.
            // Failure preserves the canonical quarantine instead of freeing it.
            unsafe { dma.unmap().map_err(StorageError::Dma)? };
            return Err(StorageError::InvalidRange);
        }
        Ok(Self { cpu, dma })
    }

    pub fn bytes(&self) -> usize {
        self.cpu.bytes()
    }

    /// Requester-domain IOVA, not a GPU VA or CPU physical address.
    /// Obtaining it does not establish GPU page-table binding or visibility.
    pub fn domain_address(&self) -> Result<u64, StorageError> {
        self.dma.address().map_err(StorageError::Dma)
    }

    /// Write bounded leaf PTEs with amdgpu's CPU loop, then perform the
    /// canonical DMA domain's CPU-to-device visibility operation.
    /// Success reports CPU entries written; it does not publish a GPU mapping.
    /// A DMA visibility error reports the written count and keeps ownership.
    ///
    /// # Safety
    /// The initialized GPU owns this table and `source` in exactly the
    /// same requester/domain. Its BO/VM reservations and reset/read exclusion
    /// must cover the entire update. All prior GPU/CPU users of this range must
    /// have finished; no concurrent writer or active Rust reference may alias
    /// the destination. The owner must validate table level/index and
    /// generation PTE flags, address-mask/aperture compatibility, source access
    /// rights and logical BO bounds. Source-data visibility and cache
    /// ownership transfers remain the source owner's responsibility. The
    /// callbacks must be that owner's initialized GMC operations. Domain IOVA,
    /// CPU physical pages and GPU VA must never be substituted for one another.
    /// Both table and source leases must remain held until PTE removal,
    /// GPU HDP/TLB publication/invalidation and hardware fence completion
    /// establish that no access remains. Required process/deferred context
    /// applies. This method supplies none of those VM, fence or TLB services.
    pub unsafe fn write_system_pages(
        &mut self,
        source: &DmaMapping,
        update: SystemPageUpdate,
        gmc: &mut GmcCpuCallbacks<'_>,
    ) -> Result<u32, UpdateError> {
        let fail = |error| UpdateError { error, written: 0 };
        self.dma.address().map_err(|e| fail(StorageError::Dma(e)))?;
        let source_base = source.address().map_err(|e| fail(StorageError::Dma(e)))?;
        let table_bytes = (update.count as usize)
            .checked_mul(size_of::<u64>())
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        let source_bytes = (update.count as usize)
            .checked_mul(GPU_PAGE_BYTES)
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        if !update.table_offset.is_multiple_of(size_of::<u64>())
            || !update.source_offset.is_multiple_of(GPU_PAGE_BYTES)
            || update
                .table_offset
                .checked_add(table_bytes)
                .is_none_or(|end| end > self.bytes())
            || update
                .source_offset
                .checked_add(source_bytes)
                .is_none_or(|end| end > source.bytes())
        {
            return Err(fail(StorageError::InvalidRange));
        }
        let address = source_base
            .checked_add(update.source_offset as u64)
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        if update.count == 0 {
            return Ok(0);
        }
        let table = self
            .cpu
            .address(update.table_offset, table_bytes)
            .map_err(|_| fail(StorageError::MappingUnavailable))?;
        // amdgpu_vm_cpu_update for a contiguous source, which has no pages_addr.
        let mut flags = update.flags;
        if update.override_pte {
            // SAFETY: the initialized GMC callback's contract covers these arguments.
            unsafe { (gmc.override_flags)(gmc.context, address, &mut flags) };
        }
        for index in 0..update.count {
            let entry = address + u64::from(index) * GPU_PAGE_BYTES as u64;
            // SAFETY: the mapping covers count entries from the checked offset;
            // the initialized GMC callback owns the architecture-correct store.
            unsafe { (gmc.set_pte_pde)(gmc.context, table.as_ptr().cast(), index, entry, flags) };
        }
        let written = update.count;
        if written != 0 {
            self.dma
                .sync_for_device(update.table_offset..update.table_offset + table_bytes)
                .map_err(|error| UpdateError {
                    error: StorageError::Dma(error),
                    written,
                })?;
        }
        Ok(written)
    }

    /// Replace bounded system-memory leaf PTEs with the initialized owner's
    /// invalid encoding, then make those CPU stores visible through the real
    /// DMA domain. Address bits are zero; `flags` supplies the GMC policy.
    /// No source-address override is run for an invalid entry.
    ///
    /// Success reports CPU entries written. It does not remove an existing GPU
    /// translation or authorize releasing its backing: GPU HDP/TLB invalidation
    /// and completion remain mandatory, even after successful DMA visibility.
    /// A visibility failure keeps modified entries and reports their count.
    ///
    /// # Safety
    /// The initialized VM owner must hold the same reservations, table
    /// level/index, reset and CPU-write exclusion as `write_system_pages`.
    /// `flags` must be that generation's invalid system-memory leaf encoding,
    /// with no valid/access bits, PRT/sparse marker or physical address bits.
    /// Sparse/fault mappings require their original separate VM path. The
    /// callbacks must belong to this initialized GMC and implement its
    /// entry stores.
    /// All old source/table leases and VM references must remain held until
    /// GPU HDP/TLB invalidation and hardware completion establish that
    /// stale translations and in-flight requests cannot access them. No new
    /// writer or submission may race the clear/publication/retirement sequence.
    /// Required process/deferred context applies. This operation itself proves
    /// neither GPU quiescence nor the absence of cached translations.
    pub unsafe fn clear_system_pages(
        &mut self,
        update: SystemPageClear,
        gmc: &mut GmcCpuCallbacks<'_>,
    ) -> Result<u32, UpdateError> {
        let fail = |error| UpdateError { error, written: 0 };
        self.dma.address().map_err(|e| fail(StorageError::Dma(e)))?;
        let table_bytes = (update.count as usize)
            .checked_mul(size_of::<u64>())
            .ok_or_else(|| fail(StorageError::InvalidRange))?;
        if !update.table_offset.is_multiple_of(size_of::<u64>())
            || update
                .table_offset
                .checked_add(table_bytes)
                .is_none_or(|end| end > self.bytes())
        {
            return Err(fail(StorageError::InvalidRange));
        }
        if update.count == 0 {
            return Ok(0);
        }
        let table = self
            .cpu
            .address(update.table_offset, table_bytes)
            .map_err(|_| fail(StorageError::MappingUnavailable))?;
        for index in 0..update.count {
            // SAFETY: the owner supplies the invalid-entry encoding and
            // initialized GMC store; preflight bounds every destination entry.
            unsafe {
                (gmc.set_pte_pde)(gmc.context, table.as_ptr().cast(), index, 0, update.flags)
            };
        }
        self.dma
            .sync_for_device(update.table_offset..update.table_offset + table_bytes)
            .map_err(|error| UpdateError {
                error: StorageError::Dma(error),
                written: update.count,
            })?;
        Ok(update.count)
    }

    /// Release only after removal from all GPU page directories/VM roots,
    /// GPU TLB invalidation, completion and drained users. A failed
    /// domain unmap keeps storage for retry; Drop quarantines it otherwise.
    ///
    /// # Safety
    /// All hardware accesses have finished and cannot restart; reservations,
    /// submissions and IRQ workers referencing the table are drained. The
    /// canonical domain/backing's process/deferred release rules must hold.
    pub unsafe fn unmap(&mut self) -> Result<(), StorageError> {
        // SAFETY: caller establishes complete GPU quiescence and release context.
        unsafe { self.dma.unmap().map_err(StorageError::Dma) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::{
        mapping::DomainMapping,
        memory::{PageBacking, PinnedPages},
    };
    use alloc::{
        alloc::{alloc_zeroed, dealloc},
        boxed::Box,
        vec::Vec,
    };
    use core::{
        alloc::Layout,
        ops::Range,
        ptr::{self, NonNull},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    struct ModelBacking {
        pointer: NonNull<u8>,
        layout: Layout,
        physical: Vec<u64>,
        released: Arc<AtomicUsize>,
        attribute: CacheAttribute,
    }
    // SAFETY: test-owned RAM with immutable metadata and no safe data references.
    unsafe impl Send for ModelBacking {}
    // SAFETY: this synchronous model has no hardware or asynchronous writers.
    unsafe impl Sync for ModelBacking {}
    // SAFETY: uniquely owned zeroed aligned RAM represents kept model pages.
    // Physical metadata is synthetic and is never supplied to a real device.
    unsafe impl PageBacking for ModelBacking {
        fn cpu_base(&self) -> NonNull<u8> {
            self.pointer
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            12
        }
        fn cache_attribute(&self) -> CacheAttribute {
            self.attribute
        }
    }
    impl Drop for ModelBacking {
        fn drop(&mut self) {
            self.released.fetch_add(1, Ordering::Relaxed);
            // SAFETY: precisely this backing's live unique model allocation.
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }
    #[derive(Default)]
    struct ModelSource {
        released: Arc<AtomicUsize>,
        allocations: AtomicU64,
    }
    impl PageSource for ModelSource {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            if !alignment.is_power_of_two() || alignment < GPU_PAGE_BYTES {
                return Err(MemoryError::InvalidAlignment);
            }
            let size = bytes
                .checked_add(GPU_PAGE_BYTES - 1)
                .ok_or(MemoryError::InvalidSize)?
                & !(GPU_PAGE_BYTES - 1);
            let layout = Layout::from_size_align(size, alignment)
                .map_err(|_| MemoryError::InvalidAlignment)?;
            // SAFETY: this fixture owns and later frees the exact zeroed allocation.
            let pointer =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            let id = self.allocations.fetch_add(1, Ordering::Relaxed);
            let physical = (0..size / GPU_PAGE_BYTES)
                .map(|page| 0x900000 + id * 0x100000 + page as u64 * 8192)
                .collect();
            PinnedPages::new(
                Box::new(ModelBacking {
                    pointer,
                    layout,
                    physical,
                    released: self.released.clone(),
                    attribute,
                }),
                bytes,
                alignment,
            )
        }
    }

    #[derive(Default)]
    struct ModelDomain {
        next: AtomicU64,
        iova_offset: AtomicU64,
        fail_sync: AtomicBool,
        fail_unmap: AtomicBool,
        fail_map: AtomicBool,
        syncs: AtomicUsize,
        unmaps: AtomicUsize,
        start: AtomicUsize,
        end: AtomicUsize,
    }
    // SAFETY: synchronous ownership model, no hardware mappings or invalidation.
    // Distinct IOVA and physical metadata exercise address separation.
    unsafe impl DmaDomain for ModelDomain {
        unsafe fn map(
            &self,
            pages: &crate::bus::dma::pages::DmaPages,
            _: Direction,
            _: u64,
        ) -> Result<DomainMapping, DmaError> {
            if self.fail_map.load(Ordering::Relaxed) {
                return Err(DmaError::IommuUnavailable);
            }
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            Ok(DomainMapping {
                id,
                address: 0x200000 + id * 0x100000 + self.iova_offset.load(Ordering::Relaxed),
                bytes: pages.bytes(),
            })
        }
        unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
            self.unmaps.fetch_add(1, Ordering::Relaxed);
            if self.fail_unmap.load(Ordering::Relaxed) {
                Err(DmaError::InvalidationFailed)
            } else {
                Ok(())
            }
        }
        unsafe fn sync_for_device(
            &self,
            _: DomainMapping,
            range: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            self.syncs.fetch_add(1, Ordering::Relaxed);
            self.start.store(range.start, Ordering::Relaxed);
            self.end.store(range.end, Ordering::Relaxed);
            if self.fail_sync.load(Ordering::Relaxed) {
                Err(DmaError::VisibilityFailed)
            } else {
                Ok(())
            }
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

    #[derive(Default)]
    struct ModelGmc {
        writes: u32,
        overrides: u32,
        last_address: u64,
    }
    unsafe extern "C" fn model_override(context: *mut c_void, address: u64, flags: *mut u64) {
        // SAFETY: the test supplies the exclusive model and this synchronous flag.
        let gmc = unsafe { &mut *context.cast::<ModelGmc>() };
        gmc.overrides += 1;
        gmc.last_address = address;
        // Test marker, not a claim of generation coherency or NUMA policy.
        // SAFETY: `flags` is the model's live out-parameter for this synchronous call.
        unsafe { *flags ^= 0x80 };
    }
    unsafe extern "C" fn model_set(
        context: *mut c_void,
        mapping: *mut c_void,
        index: u32,
        address: u64,
        flags: u64,
    ) {
        // SAFETY: C preflight bounds the mapped model storage.
        let gmc = unsafe { &mut *context.cast::<ModelGmc>() };
        gmc.writes += 1;
        // amdgpu_gmc_set_pte_pde's encoding.
        let value = (address & 0x0000_ffff_ffff_f000) | flags;
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe {
            mapping
                .cast::<u64>()
                .add(index as usize)
                .write_volatile(value)
        };
    }

    fn table(source: &ModelSource, domain: Arc<ModelDomain>, bytes: usize) -> RamPageTable {
        RamPageTable::allocate(
            source,
            domain,
            bytes,
            4096,
            CacheAttribute::WriteBack,
            (1 << 48) - 1,
        )
        .unwrap()
    }
    fn source_mapping(source: &ModelSource, domain: Arc<ModelDomain>) -> DmaMapping {
        let pages = source
            .allocate(3 * GPU_PAGE_BYTES, 4096, CacheAttribute::WriteBack)
            .unwrap();
        assert_eq!(pages.physical_pages()[1] - pages.physical_pages()[0], 8192);
        let lease = DmaMapping::map(
            domain,
            pages.clone(),
            Direction::Bidirectional,
            (1 << 48) - 1,
        )
        .unwrap();
        assert_ne!(lease.address().unwrap(), pages.physical_pages()[0]);
        lease
    }
    fn request() -> SystemPageUpdate {
        SystemPageUpdate {
            table_offset: 8,
            source_offset: GPU_PAGE_BYTES,
            count: 2,
            flags: 3,
            override_pte: true,
        }
    }
    fn update(
        table: &mut RamPageTable,
        source: &DmaMapping,
        request: SystemPageUpdate,
        gmc: &mut ModelGmc,
    ) -> Result<u32, UpdateError> {
        // SAFETY: synchronous isolated CPU model, no GPU users, fences or VM binding.
        let mut callbacks = unsafe {
            GmcCpuCallbacks::borrow_initialized(
                ptr::from_mut(gmc).cast(),
                model_override,
                model_set,
            )
        };
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { table.write_system_pages(source, request, &mut callbacks) }
    }
    fn clear(
        table: &mut RamPageTable,
        request: SystemPageClear,
        gmc: &mut ModelGmc,
    ) -> Result<u32, UpdateError> {
        // SAFETY: isolated CPU model, no device or cached GPU translations.
        let mut callbacks = unsafe {
            GmcCpuCallbacks::borrow_initialized(
                ptr::from_mut(gmc).cast(),
                model_override,
                model_set,
            )
        };
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { table.clear_system_pages(request, &mut callbacks) }
    }
    fn entry(table: &RamPageTable, offset: usize) -> u64 {
        let pointer = table.cpu.address(offset, 8).unwrap();
        // SAFETY: the synchronous model has completed its writes and has no device.
        unsafe { pointer.as_ptr().cast::<u64>().read_volatile() }
    }

    #[test]
    fn real_retained_storage_uses_domain_iova_and_original_cpu_entries() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut source = source_mapping(&pages, domain.clone());
        let mut gmc = ModelGmc::default();
        assert_eq!(update(&mut table, &source, request(), &mut gmc), Ok(2));
        assert_eq!(entry(&table, 0), 0);
        assert_eq!(entry(&table, 8), (source.address().unwrap() + 4096) | 0x83);
        assert_eq!(entry(&table, 16), (source.address().unwrap() + 8192) | 0x83);
        assert!(table.cpu.address(24, 8).is_err());
        assert_eq!((gmc.writes, gmc.overrides), (2, 1));
        assert_eq!(gmc.last_address, source.address().unwrap() + 4096);
        assert_eq!(domain.start.load(Ordering::Relaxed), 8);
        assert_eq!(domain.end.load(Ordering::Relaxed), 24);
        assert_eq!(domain.syncs.load(Ordering::Relaxed), 1);
        // SAFETY: no GPU, synchronous model has no remaining accesses.
        unsafe {
            table.unmap().unwrap();
            source.unmap().unwrap();
        }
        drop(table);
        drop(source);
        assert_eq!(pages.released.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn invalid_ranges_never_invoke_gmc_or_visibility() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut source = source_mapping(&pages, domain.clone());
        let mut gmc = ModelGmc::default();
        for request in [
            SystemPageUpdate {
                table_offset: 1,
                ..request()
            },
            SystemPageUpdate {
                table_offset: 16,
                ..request()
            },
            SystemPageUpdate {
                source_offset: 1,
                ..request()
            },
            SystemPageUpdate {
                source_offset: 2 * GPU_PAGE_BYTES,
                ..request()
            },
            SystemPageUpdate {
                table_offset: usize::MAX,
                ..request()
            },
        ] {
            assert_eq!(
                update(&mut table, &source, request, &mut gmc),
                Err(UpdateError {
                    error: StorageError::InvalidRange,
                    written: 0
                })
            );
        }
        assert_eq!((gmc.writes, gmc.overrides), (0, 0));
        assert_eq!(domain.syncs.load(Ordering::Relaxed), 0);
        assert_eq!(entry(&table, 8), 0);
        // SAFETY: no model device or live accesses.
        unsafe {
            table.unmap().unwrap();
            source.unmap().unwrap();
        }
    }

    #[test]
    fn visibility_failure_reports_written_and_keeps_all_leases() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut source = source_mapping(&pages, domain.clone());
        domain.fail_sync.store(true, Ordering::Relaxed);
        assert_eq!(
            update(&mut table, &source, request(), &mut ModelGmc::default()),
            Err(UpdateError {
                error: StorageError::Dma(DmaError::VisibilityFailed),
                written: 2
            })
        );
        assert_ne!(entry(&table, 8), 0);
        assert!(table.domain_address().is_ok() && source.address().is_ok());
        assert_eq!(pages.released.load(Ordering::Relaxed), 0);
        domain.fail_sync.store(false, Ordering::Relaxed);
        assert_eq!(
            update(&mut table, &source, request(), &mut ModelGmc::default()),
            Ok(2)
        );
        // SAFETY: no hardware exists in this model.
        unsafe {
            table.unmap().unwrap();
            source.unmap().unwrap();
        }
    }

    #[test]
    fn failed_teardown_is_retryable_and_unmapped_storage_cannot_be_written() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut source = source_mapping(&pages, domain.clone());
        domain.fail_unmap.store(true, Ordering::Relaxed);
        assert_eq!(
            // SAFETY: the model has no hardware users; backend injects invalidation failure.
            unsafe { table.unmap() },
            Err(StorageError::Dma(DmaError::InvalidationFailed))
        );
        assert!(table.domain_address().is_ok());
        assert_eq!(pages.released.load(Ordering::Relaxed), 0);
        domain.fail_unmap.store(false, Ordering::Relaxed);
        // SAFETY: retry remains quiescent and keeps the original domain mapping.
        unsafe {
            table.unmap().unwrap();
        }
        assert_eq!(
            update(&mut table, &source, request(), &mut ModelGmc::default()),
            Err(UpdateError {
                error: StorageError::Dma(DmaError::Unmapped),
                written: 0
            })
        );
        // SAFETY: no model device accesses the source either.
        unsafe {
            source.unmap().unwrap();
        }
        drop(table);
        drop(source);
        assert_eq!(pages.released.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn dropping_active_table_quarantines_its_actual_mapping_and_pin() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        drop(table(&pages, domain.clone(), 24));
        assert_eq!(pages.released.load(Ordering::Relaxed), 0);
        assert_eq!(domain.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&domain), 2);
    }

    #[test]
    fn unavailable_domain_does_not_fall_back_to_physical_addresses() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        domain.fail_map.store(true, Ordering::Relaxed);
        assert!(matches!(
            RamPageTable::allocate(
                &pages,
                domain,
                24,
                4096,
                CacheAttribute::WriteBack,
                (1 << 48) - 1
            ),
            Err(StorageError::Dma(DmaError::IommuUnavailable))
        ));
        assert_eq!(pages.released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn device_iova_alignment_is_checked_and_failed_cleanup_keeps_its_pin() {
        for fail_unmap in [false, true] {
            let pages = ModelSource::default();
            let domain = Arc::new(ModelDomain::default());
            domain.iova_offset.store(4096, Ordering::Relaxed);
            domain.fail_unmap.store(fail_unmap, Ordering::Relaxed);
            let result = RamPageTable::allocate(
                &pages,
                domain.clone(),
                24,
                8192,
                CacheAttribute::WriteBack,
                (1 << 48) - 1,
            );
            assert!(matches!(result, Err(error) if error == if fail_unmap {
                StorageError::Dma(DmaError::InvalidationFailed)
            } else { StorageError::InvalidRange }));
            assert_eq!(domain.unmaps.load(Ordering::Relaxed), 1);
            assert_eq!(
                pages.released.load(Ordering::Relaxed),
                usize::from(!fail_unmap)
            );
            assert_eq!(Arc::strong_count(&domain), if fail_unmap { 2 } else { 1 });
        }
    }

    #[test]
    fn clear_preserves_neighbors_and_uses_invalid_encoding_without_address_override() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut source = source_mapping(&pages, domain.clone());
        assert_eq!(
            update(&mut table, &source, request(), &mut ModelGmc::default()),
            Ok(2)
        );
        let neighbor = entry(&table, 16);
        let mut gmc = ModelGmc::default();
        assert_eq!(
            clear(
                &mut table,
                SystemPageClear {
                    table_offset: 8,
                    count: 1,
                    flags: 0x20
                },
                &mut gmc,
            ),
            Ok(1)
        );
        assert_eq!(entry(&table, 0), 0);
        // Synthetic invalid-policy marker, not a hardware capability claim.
        assert_eq!(entry(&table, 8), 0x20);
        assert_eq!(entry(&table, 16), neighbor);
        assert_eq!((gmc.writes, gmc.overrides), (1, 0));
        assert_eq!(domain.start.load(Ordering::Relaxed), 8);
        assert_eq!(domain.end.load(Ordering::Relaxed), 16);
        assert_eq!(pages.released.load(Ordering::Relaxed), 0);
        // SAFETY: model has no GPU/TLB users; real callers must drain both.
        unsafe {
            table.unmap().unwrap();
            source.unmap().unwrap();
        }
    }

    #[test]
    fn failed_clear_visibility_reports_modified_entries_and_retains_backing() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut source = source_mapping(&pages, domain.clone());
        assert_eq!(
            update(&mut table, &source, request(), &mut ModelGmc::default()),
            Ok(2)
        );
        domain.fail_sync.store(true, Ordering::Relaxed);
        let request = SystemPageClear {
            table_offset: 8,
            count: 2,
            flags: 0,
        };
        assert_eq!(
            clear(&mut table, request, &mut ModelGmc::default()),
            Err(UpdateError {
                error: StorageError::Dma(DmaError::VisibilityFailed),
                written: 2
            })
        );
        assert_eq!((entry(&table, 8), entry(&table, 16)), (0, 0));
        assert_eq!(pages.released.load(Ordering::Relaxed), 0);
        assert!(table.domain_address().is_ok() && source.address().is_ok());
        domain.fail_sync.store(false, Ordering::Relaxed);
        assert_eq!(clear(&mut table, request, &mut ModelGmc::default()), Ok(2));
        // SAFETY: the synchronous model has no stale GPU translations or DMA.
        unsafe {
            table.unmap().unwrap();
            source.unmap().unwrap();
        }
    }

    #[test]
    fn clear_preflights_ranges_and_active_mapping_before_any_store() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut gmc = ModelGmc::default();
        for (table_offset, count) in [
            (1, 1),
            (16, 2),
            (usize::MAX, 1),
            (24, 1),
            (32, 0),
            (0, u32::MAX),
        ] {
            assert_eq!(
                clear(
                    &mut table,
                    SystemPageClear {
                        table_offset,
                        count,
                        flags: 0
                    },
                    &mut gmc
                ),
                Err(UpdateError {
                    error: StorageError::InvalidRange,
                    written: 0
                })
            );
        }
        assert_eq!((gmc.writes, gmc.overrides), (0, 0));
        assert_eq!(domain.syncs.load(Ordering::Relaxed), 0);
        // SAFETY: table was never exposed to hardware in this model.
        unsafe {
            table.unmap().unwrap();
        }
        assert_eq!(
            clear(
                &mut table,
                SystemPageClear {
                    table_offset: 0,
                    count: 1,
                    flags: 0
                },
                &mut gmc
            ),
            Err(UpdateError {
                error: StorageError::Dma(DmaError::Unmapped),
                written: 0
            })
        );
        assert_eq!(gmc.writes, 0);
    }

    #[test]
    fn empty_clear_at_table_end_does_not_claim_visibility() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut gmc = ModelGmc::default();
        assert_eq!(
            clear(
                &mut table,
                SystemPageClear {
                    table_offset: 24,
                    count: 0,
                    flags: 0
                },
                &mut gmc
            ),
            Ok(0)
        );
        assert_eq!((gmc.writes, gmc.overrides), (0, 0));
        assert_eq!(domain.syncs.load(Ordering::Relaxed), 0);
        // SAFETY: no device has ever observed this model allocation.
        unsafe {
            table.unmap().unwrap();
        }
    }

    #[test]
    fn zero_entries_do_not_write_or_claim_visibility() {
        let pages = ModelSource::default();
        let domain = Arc::new(ModelDomain::default());
        let mut table = table(&pages, domain.clone(), 24);
        let mut source = source_mapping(&pages, domain.clone());
        let mut gmc = ModelGmc::default();
        assert_eq!(
            update(
                &mut table,
                &source,
                SystemPageUpdate {
                    table_offset: 24,
                    source_offset: 3 * GPU_PAGE_BYTES,
                    count: 0,
                    ..request()
                },
                &mut gmc
            ),
            Ok(0)
        );
        assert_eq!((gmc.writes, gmc.overrides), (0, 0));
        assert_eq!(domain.syncs.load(Ordering::Relaxed), 0);
        // SAFETY: the model never published any table or source to hardware.
        unsafe {
            table.unmap().unwrap();
            source.unmap().unwrap();
        }
    }
}
