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
        let layout =
            Layout::from_size_align(size, alignment).map_err(|_| MemoryError::InvalidAlignment)?;
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
        GmcCpuCallbacks::borrow_initialized(ptr::from_mut(gmc).cast(), model_override, model_set)
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
        GmcCpuCallbacks::borrow_initialized(ptr::from_mut(gmc).cast(), model_override, model_set)
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
fn real_kept_storage_uses_domain_iova_and_original_cpu_entries() {
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
fn dropping_active_table_quarantines_its_mapping_and_pin() {
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
fn failed_clear_visibility_reports_modified_entries_and_keeps_backing() {
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
