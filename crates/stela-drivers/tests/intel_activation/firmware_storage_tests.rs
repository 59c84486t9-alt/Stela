//! Actual public WOPCM/firmware backing owner transitions over isolated peers.
use super::*;
use bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DomainMapping},
    memory::{CacheAttribute, PageBacking, PageGeometry, PageSource, PinnedPages},
    pages::DmaPages,
};
use intel::wopcm::storage::Error as StorageError;
use std::sync::atomic::AtomicBool;

#[repr(align(4096))]
struct Page([u8; 4096]);
struct Pages {
    page: Box<Page>,
    model: Arc<Model>,
}
// SAFETY: isolated owned zeroed RAM page, symbolic PA, no hardware or safe
// aliases. Canonical pin/CPU/DMA ownership retains this same page until Drop.
unsafe impl PageBacking for Pages {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::from(&self.page.0[0])
    }
    fn physical_pages(&self) -> &[u64] {
        &[0x600000]
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Pages {
    fn drop(&mut self) {
        self.model.released.fetch_add(1, Ordering::SeqCst);
    }
}
struct Model {
    native: Arc<Counts>,
    expected: Vec<u8>,
    allocation_failure: AtomicBool,
    sync_failure: AtomicBool,
    unmap_failure: AtomicBool,
    maps: AtomicUsize,
    syncs: AtomicUsize,
    unmaps: AtomicUsize,
    released: AtomicUsize,
}
struct Source(Arc<Model>);
impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, bus::dma::memory::MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, bus::dma::memory::MemoryError> {
        assert_eq!((bytes, alignment), (4096, 4096));
        assert_eq!(attribute, CacheAttribute::WriteBack);
        if self.0.allocation_failure.load(Ordering::SeqCst) {
            return Err(bus::dma::memory::MemoryError::OutOfMemory);
        }
        PinnedPages::new(
            Box::new(Pages {
                page: Box::new(Page([0; 4096])),
                model: self.0.clone(),
            }),
            bytes,
            alignment,
        )
    }
}
// SAFETY: synchronous symbolic-domain peer paired with this actual native
// Device model. It never exposes native DMA or a real GGTT/physical grant.
unsafe impl DmaDomain for Model {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        _: u64,
    ) -> Result<DomainMapping, DmaError> {
        assert_eq!(direction, Direction::ToDevice);
        assert_eq!(self.native.wopcm_writes.load(Ordering::SeqCst), 2);
        let pages = pages.as_single().unwrap();
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let pointer = cpu.address(0, 4096).unwrap();
        // SAFETY: this private synchronous mapping peer observes the actual
        // completed CPU copy; no device or concurrent writer can access it.
        let copied = unsafe { std::slice::from_raw_parts(pointer.as_ptr(), 4096) };
        assert_eq!(&copied[..self.expected.len()], self.expected);
        assert!(copied[self.expected.len()..].iter().all(|byte| *byte == 0));
        self.maps.fetch_add(1, Ordering::SeqCst);
        Ok(DomainMapping {
            id: 91,
            address: 0x90000000,
            bytes: 4096,
        })
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        assert_eq!(mapping.id, 91);
        self.unmaps.fetch_add(1, Ordering::SeqCst);
        if self.unmap_failure.load(Ordering::SeqCst) {
            Err(DmaError::InvalidationFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: std::ops::Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        assert_eq!(mapping.id, 91);
        assert_eq!(range, 0..4096);
        assert_eq!(direction, Direction::ToDevice);
        self.syncs.fetch_add(1, Ordering::SeqCst);
        if self.sync_failure.load(Ordering::SeqCst) {
            Err(DmaError::MappingFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: std::ops::Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        panic!("firmware backing must never fabricate device completion")
    }
}

pub(super) fn owned_firmware_backing(authority: &Authority, next: &AtomicU64) {
    for operation in 0..3 {
        let (input, native) = owner(next.fetch_add(BYTES as u64, Ordering::SeqCst), 0x46d0);
        let mut device = Device::open(authority, input, true).unwrap();
        let catalog = wopcm_tests::catalog_for_device(&device);
        device.wake().unwrap();
        let preparation = device.prepare_wopcm(&catalog).unwrap();
        let digest = preparation.image().sha256();
        let model = Arc::new(Model {
            native: native.clone(),
            expected: preparation.image().bytes().to_vec(),
            allocation_failure: AtomicBool::new(true),
            sync_failure: AtomicBool::new(true),
            unmap_failure: AtomicBool::new(true),
            maps: AtomicUsize::new(0),
            syncs: AtomicUsize::new(0),
            unmaps: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
        });
        let domain: Arc<dyn DmaDomain> = model.clone();
        let source = Source(model.clone());
        // SAFETY: the private model domain is paired with this same native
        // Device, reset/WOPCM epoch and context; no actual DMA/GGTT user exists.
        let (preparation, error) =
            match unsafe { preparation.pin_firmware(&source, domain, u64::MAX) } {
                Err(failure) => failure,
                Ok(_) => panic!("programmed allocation failure must preserve preparation"),
            };
        assert_eq!(
            error,
            StorageError::Memory(bus::dma::memory::MemoryError::OutOfMemory)
        );
        assert_eq!(preparation.image().sha256(), digest);
        assert_eq!(native.wopcm_writes.load(Ordering::SeqCst), 2);
        model.allocation_failure.store(false, Ordering::SeqCst);
        let domain: Arc<dyn DmaDomain> = model.clone();
        // SAFETY: unchanged same-device/epoch model ownership and no users.
        let storage = unsafe { preparation.pin_firmware(&source, domain, u64::MAX) }
            .unwrap_or_else(|(_, error)| panic!("firmware pins: {error:?}"));
        assert_eq!(storage.preparation().image().sha256(), digest);
        let preparation = if operation == 1 {
            let (storage, error) = storage.rollback().err().expect("programmed unmap failure");
            assert_eq!(error, StorageError::Dma(DmaError::InvalidationFailed));
            model.unmap_failure.store(false, Ordering::SeqCst);
            storage
                .rollback()
                .unwrap_or_else(|(_, error)| panic!("rollback: {error:?}"))
        } else {
            let (storage, error) = storage
                .publish()
                .err()
                .expect("programmed visibility failure");
            assert_eq!(error, StorageError::Dma(DmaError::MappingFailed));
            model.sync_failure.store(false, Ordering::SeqCst);
            let published = storage
                .publish()
                .unwrap_or_else(|(_, error)| panic!("publication: {error:?}"));
            assert_eq!(published.mapping().address(), Ok(0x90000000));
            assert_eq!(published.preparation().image().sha256(), digest);
            if operation == 2 {
                drop(published);
                assert!(matches!(device.facts(), Err(Error::Closing)));
                assert!(matches!(device.sleep(), Err(Error::Closing)));
                assert!(matches!(device.retire(), Err(Error::Awake)));
                assert_eq!(model.released.load(Ordering::SeqCst), 0);
                drop(device);
                assert_eq!(native.finished.load(Ordering::SeqCst), 0);
                assert_eq!(native.dropped.load(Ordering::SeqCst), 0);
                assert_eq!(native.reservation_dropped.load(Ordering::SeqCst), 0);
                continue;
            }
            // SAFETY: no real DMA/firmware/GGTT/IRQ user ever existed in this
            // model; the same actual native preparation remains valid.
            let (published, error) = unsafe { published.retire_after_quiescence() }
                .err()
                .expect("programmed invalidation failure");
            assert_eq!(error, StorageError::Dma(DmaError::InvalidationFailed));
            assert_eq!(published.mapping().address(), Ok(0x90000000));
            assert_eq!(model.released.load(Ordering::SeqCst), 0);
            model.unmap_failure.store(false, Ordering::SeqCst);
            // SAFETY: unchanged complete model quiescence and native epoch.
            unsafe { published.retire_after_quiescence() }
                .unwrap_or_else(|(_, error)| panic!("retirement: {error:?}"))
        };
        assert_eq!(preparation.image().sha256(), digest);
        assert_eq!(native.wopcm_writes.load(Ordering::SeqCst), 2);
        device.sleep().unwrap();
        device.retire().unwrap();
        assert_eq!(model.maps.load(Ordering::SeqCst), 1);
        assert_eq!(model.unmaps.load(Ordering::SeqCst), 2);
        assert_eq!(model.released.load(Ordering::SeqCst), 1);
        assert_eq!(native.finished.load(Ordering::SeqCst), 1);
    }
}
