extern crate std;

use super::*;
use crate::bus::dma::{
    mapping::DomainMapping,
    memory::{PageBacking, PageGeometry, PinnedPages},
    pages::DmaPages,
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    vec::Vec,
};
use core::{
    alloc::Layout,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::sync::Mutex;

#[derive(Debug, Eq, PartialEq)]
enum Event {
    Allocate(usize),
    Map(usize, u64),
    Sync(u64, usize),
    Unmap(u64),
}
#[derive(Default)]
struct Model {
    events: Mutex<Vec<Event>>,
    expected: Mutex<Vec<u8>>,
    released: AtomicUsize,
    geometry_unavailable: AtomicBool,
    allocation_failure: AtomicBool,
    bad_logical: AtomicBool,
    mapping_failure: AtomicBool,
    sync_failure: AtomicBool,
    unmap_failure: AtomicBool,
}
struct Allocation {
    pointer: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
    model: Arc<Model>,
}
// SAFETY: exclusively owned, aligned, zeroed model RAM; physical labels are
// symbolic and never used for an actual native translation or dereference.
unsafe impl Send for Allocation {}
// SAFETY: immutable metadata and no concurrent model/device access to the RAM.
unsafe impl Sync for Allocation {}
// SAFETY: retains its exact zeroed allocation and immutable page inventory until
// every CPU/DMA pin ends; Drop frees only that same model allocation.
unsafe impl PageBacking for Allocation {
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
        CacheAttribute::WriteBack
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        self.model.released.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the last canonical pin releases this allocation exactly once.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
impl PageSource for Arc<Model> {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        if self.geometry_unavailable.load(Ordering::Relaxed) {
            Err(MemoryError::Unavailable)
        } else {
            PageGeometry::base_only(12)
        }
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(alignment, PAGE_BYTES);
        assert_eq!(attribute, CacheAttribute::WriteBack);
        self.events.lock().unwrap().push(Event::Allocate(bytes));
        if self.allocation_failure.load(Ordering::Relaxed) {
            return Err(MemoryError::OutOfMemory);
        }
        let layout = Layout::from_size_align(bytes, PAGE_BYTES).unwrap();
        // SAFETY: nonzero validated test layout; the resulting model owner
        // retains/frees this allocation and does not expose safe Rust aliases.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        PinnedPages::new(
            Box::new(Allocation {
                pointer,
                layout,
                physical: (0..bytes / PAGE_BYTES)
                    .map(|index| 0x400000 + (index * PAGE_BYTES) as u64)
                    .collect(),
                model: self.clone(),
            }),
            bytes - usize::from(self.bad_logical.load(Ordering::Relaxed)),
            alignment,
        )
    }
}
// SAFETY: isolated synchronous ownership peer. It supplies no physical IOMMU or
// hardware proof, retains exact symbolic tokens and refuses programmed faults.
unsafe impl DmaDomain for Model {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        address_limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        assert_eq!(direction, Direction::ToDevice);
        let pages = pages.as_single().unwrap();
        assert_eq!(pages.physical_pages()[0], 0x400000);
        let cpu = pages.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let pointer = cpu.address(0, pages.bytes()).unwrap();
        assert_ne!(pointer.as_ptr() as u64, 0x80000000);
        // SAFETY: observe the completed actual copy while the canonical pin
        // is retained; this synchronous peer has no device/concurrent writer.
        let copied = unsafe { core::slice::from_raw_parts(pointer.as_ptr(), pages.bytes()) };
        let expected = self.expected.lock().unwrap();
        assert_eq!(&copied[..expected.len()], expected.as_slice());
        assert!(copied[expected.len()..].iter().all(|byte| *byte == 0));
        self.events
            .lock()
            .unwrap()
            .push(Event::Map(pages.bytes(), address_limit));
        if self.mapping_failure.load(Ordering::Relaxed) {
            return Err(DmaError::MappingFailed);
        }
        Ok(DomainMapping {
            id: 0x51,
            address: 0x80000000,
            bytes: pages.bytes(),
        })
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        assert_eq!(mapping.address, 0x80000000);
        self.events.lock().unwrap().push(Event::Unmap(mapping.id));
        if self.unmap_failure.load(Ordering::Relaxed) {
            Err(DmaError::InvalidationFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        assert_eq!(range, 0..mapping.bytes);
        assert_eq!(direction, Direction::ToDevice);
        self.events
            .lock()
            .unwrap()
            .push(Event::Sync(mapping.id, range.len()));
        if self.sync_failure.load(Ordering::Relaxed) {
            Err(DmaError::MappingFailed)
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
        panic!("firmware preparation must not invent hardware completion")
    }
}

fn allocate(bytes: &[u8], model: &Arc<Model>) -> Result<Backing, Error> {
    *model.expected.lock().unwrap() = bytes.to_vec();
    let domain: Arc<dyn DmaDomain> = model.clone();
    Backing::allocate(bytes, model, domain, u64::MAX)
}

#[test]
fn complete_image_copy_zero_tail_visibility_and_distinct_iova() {
    for length in [1usize, 128, 4095, 4096, 4097, 8193] {
        let model = Arc::new(Model::default());
        let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        let mut backing = allocate(&bytes, &model).unwrap();
        let rounded = length.next_multiple_of(PAGE_BYTES);
        backing.publish().unwrap();
        assert_eq!(backing.mapping.address(), Ok(0x80000000));
        assert_eq!(
            *model.events.lock().unwrap(),
            [
                Event::Allocate(rounded),
                Event::Map(rounded, u64::MAX),
                Event::Sync(0x51, rounded)
            ]
        );
        // SAFETY: the model has no hardware/GGTT/IRQ/submission users.
        unsafe { backing.retire() }.unwrap();
        assert_eq!(model.released.load(Ordering::Relaxed), 1);
        drop(backing);
        assert_eq!(model.released.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn allocation_and_mapping_faults_do_not_publish_or_leak_completed_pins() {
    for stage in 0..4 {
        let model = Arc::new(Model::default());
        match stage {
            0 => model.geometry_unavailable.store(true, Ordering::Relaxed),
            1 => model.allocation_failure.store(true, Ordering::Relaxed),
            2 => model.bad_logical.store(true, Ordering::Relaxed),
            _ => model.mapping_failure.store(true, Ordering::Relaxed),
        }
        assert!(allocate(&[0x5a; 5000], &model).is_err());
        let events = model.events.lock().unwrap();
        assert!(!events.iter().any(|event| matches!(event, Event::Sync(..))));
        assert_eq!(events.is_empty(), stage == 0);
        assert_eq!(
            model.released.load(Ordering::Relaxed),
            usize::from(stage >= 2)
        );
    }
}

#[test]
fn failed_visibility_or_invalidation_retains_exact_mapping_for_retry() {
    let model = Arc::new(Model::default());
    let mut backing = allocate(&[0xa5; 5000], &model).unwrap();
    model.sync_failure.store(true, Ordering::Relaxed);
    assert_eq!(backing.publish(), Err(Error::Dma(DmaError::MappingFailed)));
    assert_eq!(backing.mapping.address(), Ok(0x80000000));
    assert_eq!(model.released.load(Ordering::Relaxed), 0);
    model.sync_failure.store(false, Ordering::Relaxed);
    backing.publish().unwrap();
    model.unmap_failure.store(true, Ordering::Relaxed);
    // SAFETY: no actual hardware/GGTT/user exists in this synchronous model.
    assert_eq!(
        unsafe { backing.retire() },
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(backing.mapping.address(), Ok(0x80000000));
    assert_eq!(model.released.load(Ordering::Relaxed), 0);
    model.unmap_failure.store(false, Ordering::Relaxed);
    // SAFETY: unchanged model quiescence and the same still-retained token.
    unsafe { backing.retire() }.unwrap();
    drop(backing);
    assert_eq!(model.released.load(Ordering::Relaxed), 1);
    let events = model.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Map(..)))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Sync(0x51, 8192)))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Unmap(0x51)))
            .count(),
        2
    );
}
