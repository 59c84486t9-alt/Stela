use super::*;
use crate::bus::dma::{
    mapping::{DmaError, DomainMapping},
    memory::{PageBacking, PinnedPages},
    pages::DmaPages,
};
use alloc::boxed::Box;
use core::{
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
extern crate std;
use std::sync::Mutex;

#[repr(align(8192))]
struct Buffer([u8; 8192]);
static NEXT_PHYSICAL: AtomicU64 = AtomicU64::new(0x800000);
struct Backing {
    buffer: Box<Buffer>,
    physical: [u64; 2],
    drops: Domain<AtomicUsize>,
}
// SAFETY: this model owns aligned, zeroed CPU storage and immutable symbolic
// noncontiguous PA labels; no label is dereferenced or submitted to hardware.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::from(&self.buffer.0[0])
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
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
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Source(Domain<AtomicUsize>);
impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        if bytes == 0 || bytes > 8192 {
            return Err(MemoryError::InvalidSize);
        }
        if attribute != CacheAttribute::WriteBack {
            return Err(MemoryError::CacheAttributeUnavailable);
        }
        let physical = NEXT_PHYSICAL.fetch_add(0x400000, Ordering::Relaxed);
        PinnedPages::new(
            Box::new(Backing {
                buffer: Box::new(Buffer([0; 8192])),
                physical: [physical, physical + 0x200000],
                drops: self.0.clone(),
            }),
            bytes,
            alignment,
        )
    }
}
#[derive(Default)]
struct Model {
    live: Mutex<Vec<DomainMapping>>,
    next: AtomicUsize,
    unmaps: AtomicUsize,
    fail_unmap: AtomicBool,
    fail_sync: AtomicBool,
    unaligned: AtomicBool,
    passthrough: AtomicBool,
}
// SAFETY: serialized synchronous model tracks unique mappings and acknowledges
// modeled removal. It neither grants native DMA nor performs hardware IO.
unsafe impl DmaDomain for Model {
    fn kind(&self) -> DomainKind {
        if self.passthrough.load(Ordering::Relaxed) {
            DomainKind::Passthrough
        } else {
            DomainKind::Isolated
        }
    }
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _: Direction,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        assert_eq!(pages.physical_pages().len(), 2);
        assert_ne!(pages.physical_pages()[0] + 4096, pages.physical_pages()[1]);
        let id = self.next.fetch_add(1, Ordering::Relaxed) as u64 + 1;
        let address = 0x20000
            + id * 0x10000
            + if self.unaligned.load(Ordering::Relaxed) {
                4096
            } else {
                0
            };
        if address + pages.bytes() as u64 - 1 > limit {
            return Err(DmaError::AddressLimit);
        }
        let mapping = DomainMapping {
            id,
            address,
            bytes: pages.bytes(),
        };
        self.live.lock().unwrap().push(mapping);
        Ok(mapping)
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        if self.fail_unmap.swap(false, Ordering::Relaxed) {
            return Err(DmaError::InvalidationFailed);
        }
        let mut live = self.live.lock().unwrap();
        let index = live
            .iter()
            .position(|entry| *entry == mapping)
            .ok_or(DmaError::Unmapped)?;
        live.remove(index);
        self.unmaps.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        assert!(self.live.lock().unwrap().contains(&mapping));
        if self.fail_sync.swap(false, Ordering::Relaxed) {
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
fn fixture() -> (Source, Domain<Model>) {
    (
        Source(Domain::new(AtomicUsize::new(0))),
        Domain::new(Model::default()),
    )
}

#[test]
fn translated_buffers_use_owned_cpu_mapping() {
    let (source, domain) = fixture();
    // SAFETY: model storage is coherent, exclusively owned and never submitted
    // to hardware; all mapping and retirement calls stay in this test context.
    let mut allocator = unsafe { DomainAllocator::new(&source, domain.clone(), u32::MAX.into()) };
    let mut buffer = allocator.allocate(6000, 128).unwrap();
    assert_ne!(buffer.bus_address(), buffer.as_ptr() as u64);
    assert_ne!(buffer.bus_address(), 0x800000);
    assert_eq!(buffer.len(), 6000);
    assert!(buffer.bytes().iter().all(|byte| *byte == 0));
    buffer.write(4096, 0x12345678u32);
    assert_eq!(buffer.read::<u32>(4096), 0x12345678);
    assert_eq!(source.0.load(Ordering::Relaxed), 0);
    assert_eq!(
        // SAFETY: this model has no device accesses, but a live buffer still must refuse teardown
        // before any modeled translation or CPU backing is freed.
        unsafe { allocator.retire() },
        Err(AllocationError::LiveBuffers)
    );
    assert_eq!(domain.unmaps.load(Ordering::Relaxed), 0);
    drop(buffer);
    // SAFETY: all modeled CPU/device users have ended, in the same context.
    unsafe { allocator.retire() }.unwrap();
    assert_eq!(domain.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(source.0.load(Ordering::Relaxed), 1);
}

#[test]
fn refused_layouts_do_not_publish_mappings() {
    let (source, domain) = fixture();
    // SAFETY: same exclusive, synchronous coherent model as above.
    let mut allocator = unsafe { DomainAllocator::new(&source, domain.clone(), u32::MAX.into()) };
    for (bytes, align) in [(0, 4096), (1, 0), (1, 3), (usize::MAX, 1)] {
        assert!(matches!(
            allocator.allocate(bytes, align),
            Err(BlockError::Dma(AllocationError::Region(
                region::Error::Layout(_)
            )))
        ));
    }
    assert_eq!(domain.next.load(Ordering::Relaxed), 0);
    domain.unaligned.store(true, Ordering::Relaxed);
    assert!(matches!(
        allocator.allocate(1, 8192),
        Err(BlockError::Dma(AllocationError::Region(
            region::Error::Memory(MemoryError::InvalidAlignment)
        )))
    ));
    assert!(domain.live.lock().unwrap().is_empty());
    assert_eq!(domain.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(source.0.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_visibility_retires_unpublished_translation() {
    let (source, domain) = fixture();
    domain.fail_sync.store(true, Ordering::Relaxed);
    // SAFETY: exclusive synchronous model, no hardware receives an IOVA.
    let mut allocator = unsafe { DomainAllocator::new(&source, domain.clone(), u32::MAX.into()) };
    assert!(matches!(
        allocator.allocate(4096, 4096),
        Err(BlockError::Dma(AllocationError::Region(
            region::Error::Dma(DmaError::VisibilityFailed)
        )))
    ));
    assert!(domain.live.lock().unwrap().is_empty());
    assert_eq!(source.0.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_unmap_keeps_pin_until_acknowledged_retry() {
    let (source, domain) = fixture();
    // SAFETY: exclusive synchronous model; CPU access uses its owned Box.
    let mut allocator = unsafe { DomainAllocator::new(&source, domain.clone(), u32::MAX.into()) };
    drop(allocator.allocate(4096, 4096).unwrap());
    domain.fail_unmap.store(true, Ordering::Relaxed);
    assert_eq!(
        // SAFETY: no modeled device or CPU user remains, in the same owner context.
        unsafe { allocator.retire() },
        Err(AllocationError::Region(region::Error::Dma(
            DmaError::InvalidationFailed
        )))
    );
    assert_eq!(source.0.load(Ordering::Relaxed), 0);
    assert_eq!(domain.live.lock().unwrap().len(), 1);
    // SAFETY: same quiescent owner retries its unchanged mapping.
    unsafe { allocator.retire() }.unwrap();
    assert_eq!(source.0.load(Ordering::Relaxed), 1);
}

#[test]
fn address_limit_failure_releases_unmapped_pins() {
    let (source, domain) = fixture();
    // SAFETY: exclusive synchronous model; its mapping must fit the supplied
    // controller aperture, without deriving that aperture from CPU pointers.
    let mut allocator = unsafe { DomainAllocator::new(&source, domain.clone(), 0xffff) };
    assert!(matches!(
        allocator.allocate(4096, 4096),
        Err(BlockError::Dma(AllocationError::Region(
            region::Error::Dma(DmaError::AddressLimit)
        )))
    ));
    assert!(domain.live.lock().unwrap().is_empty());
    assert_eq!(source.0.load(Ordering::Relaxed), 1);
}

#[test]
fn passthrough_requires_constrained_provider_selection() {
    struct Refusing {
        calls: AtomicUsize,
    }
    impl PageSource for Refusing {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            PageGeometry::base_only(12)
        }
        fn allocate(
            &self,
            _: usize,
            _: usize,
            _: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            panic!("passthrough must not try an unconstrained allocation")
        }
        fn allocate_below(
            &self,
            _: usize,
            _: usize,
            _: CacheAttribute,
            end: u64,
        ) -> Result<PinnedPages, MemoryError> {
            assert_eq!(end, 1u64 << 32);
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(MemoryError::Unavailable)
        }
    }
    let source = Refusing {
        calls: AtomicUsize::new(0),
    };
    let domain = Domain::new(Model::default());
    domain.passthrough.store(true, Ordering::Relaxed);
    // SAFETY: model has no devices, and this provider refuses before creating
    // any pin or mapping; the test grants no native passthrough admission.
    let mut allocator = unsafe { DomainAllocator::new(&source, domain.clone(), u32::MAX.into()) };
    assert!(matches!(
        allocator.allocate(4096, 4096),
        Err(BlockError::Dma(AllocationError::Region(
            region::Error::Memory(MemoryError::Unavailable)
        )))
    ));
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    assert_eq!(domain.next.load(Ordering::Relaxed), 0);
}

#[test]
fn separate_domains_can_reuse_iovas() {
    let (source, first) = fixture();
    let second = Domain::new(Model::default());
    // SAFETY: both synchronous model domains use independently kept,
    // coherent CPU allocations; no device receives either symbolic address.
    let mut a = unsafe { DomainAllocator::new(&source, first, u32::MAX.into()) };
    // SAFETY: same independent model ownership and execution context.
    let mut b = unsafe { DomainAllocator::new(&source, second, u32::MAX.into()) };
    let mut x = a.allocate(4096, 4096).unwrap();
    let y = b.allocate(4096, 4096).unwrap();
    assert_eq!(x.bus_address(), y.bus_address());
    assert_ne!(x.as_ptr(), y.as_ptr());
    x.write(0, 0x1234u32);
    assert_eq!(y.read::<u32>(0), 0);
    drop((x, y));
    // SAFETY: both buffers and all modeled device users ended.
    unsafe { a.retire() }.unwrap();
    // SAFETY: same complete modeled quiescence for the other domain.
    unsafe { b.retire() }.unwrap();
}
