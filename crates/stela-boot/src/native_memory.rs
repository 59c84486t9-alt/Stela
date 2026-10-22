//! Native system-RAM pins backed by the mount's existing reusable heap.
//!
//! Allocation and the final release of any pin/CPU/DMA mapping must occur in
//! process or deferred-work context. The existing heap does not exclude hard
//! IRQ reentry. This service is not a VRAM allocator or an IOMMU.
use alloc::{boxed::Box, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use stela_drivers::bus::dma::memory::{
    CacheAttribute, MemoryError, PageBacking, PageGeometry, PageSource, PinnedPages,
};

#[cfg(not(test))]
use crate::ALLOCATOR;
#[cfg(test)]
#[path = "heap.rs"]
#[allow(dead_code)]
mod test_heap;
#[cfg(test)]
static ALLOCATOR: test_heap::Heap = test_heap::Heap::new();

const PAGE_SHIFT: u8 = 12;
const PAGE: usize = 1 << PAGE_SHIFT;

#[cfg_attr(test, path = "native_memory/cache.rs")]
pub(crate) mod cache;

pub static SOURCE: NativeMemory = NativeMemory {
    cpu: AtomicUsize::new(0),
    physical: AtomicU64::new(0),
    bytes: AtomicUsize::new(0),
    table_offset: AtomicU64::new(0),
};

pub struct NativeMemory {
    cpu: AtomicUsize,
    physical: AtomicU64,
    bytes: AtomicUsize,
    table_offset: AtomicU64,
}

/// Register the existing heap's true CPU/physical mapping once in each phase.
///
/// # Safety
/// The heap has just been initialized over exactly this firmware-reserved,
/// exclusively owned, page-aligned RAM extent. It is excluded from every guest
/// and free-memory inventory. Its writable WB mapping and all aliases remain
/// valid and compatible across every root change until the final allocation
/// release. There are no allocations from a previous registered heap still
/// alive, nor concurrent users of this registration. Only process/deferred
/// context may allocate or perform the last release, including Arc/lease Drop.
/// Adding `table_offset` to each current CR3-reachable table PA must yield a
/// readable retained mapping of that complete page (zero for identity, the
/// explicit physmap offset in the engine). Root changes, migration and cache
/// policy changes are excluded during allocation/cache qualification.
pub unsafe fn initialize(cpu: usize, physical: u64, bytes: usize, table_offset: u64) {
    assert!(cpu != 0 && cpu.is_multiple_of(PAGE));
    assert!(physical.is_multiple_of(PAGE as u64));
    assert!(bytes != 0 && bytes.is_multiple_of(PAGE));
    assert!(cpu.checked_add(bytes).is_some());
    assert!(physical.checked_add(bytes as u64).is_some());
    SOURCE.cpu.store(cpu, Ordering::Relaxed);
    SOURCE.physical.store(physical, Ordering::Relaxed);
    SOURCE.table_offset.store(table_offset, Ordering::Relaxed);
    SOURCE.bytes.store(bytes, Ordering::Release);
}

/// Qualify an existing loader reservation through the SAME current mapping
/// and vendor-specific effective-memory-type decoder used by native pages.
/// This does not allocate/copy RAM or authorize a new physical alias.
///
/// # Safety
/// The exact reservation/CPU mapping is retained for the boot lifetime; root,
/// cache controls and physical ownership cannot change during this check.
#[cfg(not(test))]
pub(crate) unsafe fn qualify_reserved_writeback(
    cpu: u64,
    physical: u64,
    bytes: usize,
) -> Result<(), MemoryError> {
    cache::verify_writeback(
        cpu,
        physical,
        bytes,
        SOURCE.table_offset.load(Ordering::Acquire),
    )
}

/// Exercise the actual registered mapping and allocator, including retained
/// CPU lifetime and zeroed page-tail access. Called by the mount's host check.
pub fn verify() -> Result<(), MemoryError> {
    let before = ALLOCATOR.usage().live;
    if !matches!(
        SOURCE.allocate(PAGE, PAGE, CacheAttribute::WriteCombining),
        Err(MemoryError::CacheAttributeUnavailable)
    ) || !matches!(
        SOURCE.allocate(PAGE, 3, CacheAttribute::WriteBack),
        Err(MemoryError::InvalidAlignment)
    ) {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    let pages = SOURCE.allocate(PAGE + 1, PAGE, CacheAttribute::WriteBack)?;
    if pages.logical_bytes() != PAGE + 1 || pages.bytes() != 2 * PAGE {
        return Err(MemoryError::InvalidSize);
    }
    let mapping = pages.cpu_mapping(CacheAttribute::WriteBack)?;
    if !matches!(
        pages.cpu_mapping(CacheAttribute::Uncached),
        Err(MemoryError::CacheAttributeUnavailable)
    ) || mapping.address(usize::MAX, 1) != Err(MemoryError::InvalidSize)
        || mapping.address(mapping.bytes(), 1) != Err(MemoryError::InvalidSize)
    {
        return Err(MemoryError::InvalidSize);
    }
    let pointer = mapping.address(0, mapping.bytes())?.as_ptr();
    let offset = (pointer as usize)
        .checked_sub(SOURCE.cpu.load(Ordering::Relaxed))
        .ok_or(MemoryError::OutsideReservation)?;
    let physical = SOURCE.physical.load(Ordering::Relaxed) + offset as u64;
    if pages.physical_pages() != [physical, physical + PAGE as u64] {
        return Err(MemoryError::InvalidPageList);
    }
    drop(pages);
    for index in 0..mapping.bytes() {
        // SAFETY: CPU-exclusive owned RAM with the retained mapping live.
        if unsafe { pointer.add(index).read_volatile() } != 0 {
            return Err(MemoryError::InvalidPageList);
        }
    }
    // SAFETY: this exclusive CPU mapping includes its full last-page tail.
    unsafe {
        pointer.add(2 * PAGE - 1).write_volatile(0x5a);
        if pointer.add(2 * PAGE - 1).read_volatile() != 0x5a {
            return Err(MemoryError::OutsideReservation);
        }
    }
    drop(mapping);
    if ALLOCATOR.usage().live != before {
        return Err(MemoryError::OutsideReservation);
    }
    Ok(())
}

impl PageSource for NativeMemory {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        if self.bytes.load(Ordering::Acquire) == 0 {
            return Err(MemoryError::Unavailable);
        }
        // This allocator records PAGE_SHIFT for every real returned backing.
        // A large byte capacity/alignment does not establish a larger granule.
        PageGeometry::base_only(PAGE_SHIFT)
    }

    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        if attribute != CacheAttribute::WriteBack {
            return Err(MemoryError::CacheAttributeUnavailable);
        }
        if !alignment.is_power_of_two() {
            return Err(MemoryError::InvalidAlignment);
        }
        if bytes == 0 {
            return Err(MemoryError::InvalidSize);
        }
        let capacity = self.bytes.load(Ordering::Acquire);
        if capacity == 0 {
            return Err(MemoryError::Unavailable);
        }
        let logical_bytes = bytes;
        let bytes = bytes
            .checked_next_multiple_of(PAGE)
            .ok_or(MemoryError::InvalidSize)?;
        let layout = Layout::from_size_align(bytes, alignment.max(PAGE))
            .map_err(|_| MemoryError::InvalidAlignment)?;
        let cpu = self.cpu.load(Ordering::Relaxed);
        let physical_base = self.physical.load(Ordering::Relaxed);
        // A linear heap cannot satisfy simultaneous CPU/PA alignment when
        // their registered bases have incompatible residues. Refuse it.
        if ((cpu as u64) ^ physical_base) & (layout.align() as u64 - 1) != 0 {
            return Err(MemoryError::InvalidAlignment);
        }
        // SAFETY: initialize registered the live heap; this service's users
        // exclude IRQ allocation/final release, as does the mount allocator.
        let pointer = NonNull::new(unsafe { ALLOCATOR.alloc_zeroed(layout) })
            .ok_or(MemoryError::OutOfMemory)?;
        let start = pointer.as_ptr() as usize;
        let offset = start
            .checked_sub(cpu)
            .filter(|offset| offset.checked_add(bytes).is_some_and(|end| end <= capacity));
        let Some(offset) = offset else {
            // SAFETY: this exact heap allocation was not published.
            unsafe { ALLOCATOR.dealloc(pointer.as_ptr(), layout) };
            return Err(MemoryError::OutsideReservation);
        };
        let physical = physical_base + offset as u64;
        #[cfg(not(test))]
        if let Err(error) = cache::verify_writeback(
            start as u64,
            physical,
            bytes,
            self.table_offset.load(Ordering::Relaxed),
        ) {
            // SAFETY: unpublished allocation, with its exact original layout.
            unsafe { ALLOCATOR.dealloc(pointer.as_ptr(), layout) };
            return Err(error);
        }
        let pages: Vec<u64> = (0..bytes / PAGE)
            .map(|index| physical + (index * PAGE) as u64)
            .collect();
        PinnedPages::new(
            Box::new(HeapAllocation {
                pointer,
                layout,
                pages,
            }),
            logical_bytes,
            layout.align(),
        )
    }
}

struct HeapAllocation {
    pointer: NonNull<u8>,
    layout: Layout,
    pages: Vec<u64>,
}

// SAFETY: the pointer is an owned, immovable allocation. No safe CPU data
// references are exposed. Consumers synchronize raw CPU/device accesses and
// never do final release in hard IRQ context; metadata is immutable.
unsafe impl Send for HeapAllocation {}
// SAFETY: shared access exposes immutable metadata and raw pointers only.
unsafe impl Sync for HeapAllocation {}

// SAFETY: initialize proves the native heap's actual contiguous PA mapping;
// allocate retains a full aligned/zeroed extent and records every real page.
// Drop returns it to the same allocator only after the last Arc-backed lease.
unsafe impl PageBacking for HeapAllocation {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }

    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }

    fn page_shift(&self) -> u8 {
        PAGE_SHIFT
    }

    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}

impl Drop for HeapAllocation {
    fn drop(&mut self) {
        // SAFETY: this owner is released only after every pin/mapping ends,
        // using the exact allocation and layout, in process/deferred context.
        unsafe { ALLOCATOR.dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;
    #[test]
    fn unregistered_native_memory_does_not_attest_a_provider() {
        let source = NativeMemory {
            cpu: AtomicUsize::new(0),
            physical: AtomicU64::new(0),
            bytes: AtomicUsize::new(0),
            table_offset: AtomicU64::new(0),
        };
        assert_eq!(source.page_geometry(), Err(MemoryError::Unavailable));
    }

    #[test]
    fn actual_heap_pages_stay_pinned_through_cpu_mapping_and_reclaim() {
        let layout = Layout::from_size_align(128 * 4096, 8192).unwrap();
        // SAFETY: this separate RAM allocation is kept alive until every test pin
        // ends. Its PA relation is a model; privileged CPU mappings run in QEMU.
        let ram = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ram.is_null());
        // SAFETY: one dedicated extent, no users before initialization.
        unsafe {
            ALLOCATOR.initialize(ram, layout.size());
            initialize(ram as usize, 0x4000_0000, layout.size(), 0);
        }
        let source = &SOURCE;
        let geometry = source.page_geometry().unwrap();
        assert_eq!(geometry, PageGeometry::base_only(PAGE_SHIFT).unwrap());
        assert!(!geometry.supports(PAGE_SHIFT + 1));
        verify().unwrap();
        assert!(matches!(
            source.allocate(0, 4096, CacheAttribute::WriteBack),
            Err(MemoryError::InvalidSize)
        ));
        assert!(matches!(
            source.allocate(1, 3, CacheAttribute::WriteBack),
            Err(MemoryError::InvalidAlignment)
        ));
        assert!(matches!(
            source.allocate(4096, 4096, CacheAttribute::WriteCombining),
            Err(MemoryError::CacheAttributeUnavailable)
        ));
        let before = ALLOCATOR.usage().live;
        let pin = source
            .allocate(4097, 8192, CacheAttribute::WriteBack)
            .unwrap();
        assert_eq!(pin.bytes(), 8192);
        assert_eq!(pin.logical_bytes(), 4097);
        assert_eq!(pin.alignment(), 8192);
        assert_eq!(pin.page_shift(), 12);
        assert!(geometry.supports(pin.page_shift()));
        assert!(matches!(
            pin.cpu_mapping(CacheAttribute::Uncached),
            Err(MemoryError::CacheAttributeUnavailable)
        ));
        let mapping = pin.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let tail = pin
            .cpu_mapping_range(CacheAttribute::WriteBack, 4097..8192)
            .unwrap();
        assert_eq!(tail.bytes(), 4095);
        assert_eq!(tail.range(), 4097..8192);
        assert_eq!(tail.address(4095, 1), Err(MemoryError::InvalidSize));
        assert!(matches!(
            pin.cpu_mapping_range(CacheAttribute::WriteBack, 8191..8193),
            Err(MemoryError::InvalidSize)
        ));
        drop(tail);
        let pointer = mapping.address(0, mapping.bytes()).unwrap().as_ptr();
        assert!((pointer as usize).is_multiple_of(8192));
        let physical = 0x4000_0000 + (pointer as usize - ram as usize) as u64;
        assert_eq!(pin.physical_pages(), &[physical, physical + 4096]);
        // SAFETY: CPU-exclusive test memory; the mapping retains the whole pin.
        assert!(
            unsafe { core::slice::from_raw_parts(pointer, mapping.bytes()) }
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            mapping.address(usize::MAX, 1),
            Err(MemoryError::InvalidSize)
        );
        assert_eq!(mapping.address(8192, 1), Err(MemoryError::InvalidSize));
        let clone = pin.clone();
        drop(pin);
        drop(clone);
        assert_eq!(ALLOCATOR.usage().live, before + 8192);
        // SAFETY: the retained CPU mapping still owns these pages.
        unsafe { pointer.add(8191).write_volatile(0x5a) };
        drop(mapping);
        assert_eq!(ALLOCATOR.usage().live, before);
        // Exercise a domain's failure ordering while the real native allocation
        // stays pinned. The IOMMU/register transport here is explicitly a model.
        use std::sync::{Arc, Mutex};
        use stela_drivers::bus::dma::mapping::{
            Direction, DmaDomain, DmaError, DmaMapping, DomainMapping,
        };
        #[derive(Default)]
        struct ModelDomain(Mutex<(bool, Vec<&'static str>)>);
        // SAFETY: deterministic model of a single translation with no device;
        // native hardware invalidation is a separate QEMU/platform requirement.
        unsafe impl DmaDomain for ModelDomain {
            unsafe fn map(
                &self,
                pages: &stela_drivers::bus::dma::memory::PinnedPages,
                _: Direction,
                _: u64,
            ) -> Result<DomainMapping, DmaError> {
                self.0.lock().unwrap().1.push("map-publish-iotlb-ack");
                Ok(DomainMapping {
                    id: 1,
                    address: 0x8_0000_0000,
                    bytes: pages.bytes(),
                })
            }
            unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
                let mut state = self.0.lock().unwrap();
                state.1.push("unmap-iotlb-ack");
                if state.0 {
                    Err(DmaError::InvalidationFailed)
                } else {
                    Ok(())
                }
            }
            unsafe fn sync_for_device(
                &self,
                _: DomainMapping,
                _: core::ops::Range<usize>,
                _: Direction,
            ) -> Result<(), DmaError> {
                self.0.lock().unwrap().1.push("device-visible");
                Ok(())
            }
            unsafe fn sync_for_cpu(
                &self,
                _: DomainMapping,
                _: core::ops::Range<usize>,
                _: Direction,
            ) -> Result<(), DmaError> {
                self.0.lock().unwrap().1.push("cpu-visible");
                Ok(())
            }
        }
        let domain = Arc::new(ModelDomain::default());
        let pin = source
            .allocate(4096, 4096, CacheAttribute::WriteBack)
            .unwrap();
        let keep = pin.clone();
        let mut dma =
            DmaMapping::map(domain.clone(), pin, Direction::Bidirectional, u64::MAX).unwrap();
        assert_ne!(dma.address().unwrap(), keep.physical_pages()[0]);
        assert_eq!(dma.sync_for_device(0..4097), Err(DmaError::InvalidRange));
        assert_eq!(
            dma.sync_for_device(core::ops::Range {
                start: 4096,
                end: 4095
            }),
            Err(DmaError::InvalidRange)
        );
        dma.sync_for_device(0..4096).unwrap();
        // SAFETY: the model has no asynchronous DMA; completion is quiescent.
        unsafe { dma.sync_for_cpu(0..4096) }.unwrap();
        drop(keep);
        domain.0.lock().unwrap().0 = true;
        // SAFETY: same quiescent model; failed invalidation must retain real pins.
        assert_eq!(unsafe { dma.unmap() }, Err(DmaError::InvalidationFailed));
        assert_eq!(ALLOCATOR.usage().live, before + 4096);
        domain.0.lock().unwrap().0 = false;
        // SAFETY: retry has the same stopped model and unreused mapping.
        unsafe { dma.unmap() }.unwrap();
        assert_eq!(dma.address(), Err(DmaError::Unmapped));
        assert_eq!(dma.sync_for_device(0..4096), Err(DmaError::Unmapped));
        // SAFETY: hardware remains quiescent, but the retired token must be
        // rejected by the wrapper before any backend cache operation.
        assert_eq!(
            unsafe { dma.sync_for_cpu(0..4096) },
            Err(DmaError::Unmapped)
        );
        assert_eq!(ALLOCATOR.usage().live, before);
        assert_eq!(
            domain.0.lock().unwrap().1,
            [
                "map-publish-iotlb-ack",
                "device-visible",
                "cpu-visible",
                "unmap-iotlb-ack",
                "unmap-iotlb-ack"
            ]
        );
        let pin = source
            .allocate(4096, 4096, CacheAttribute::WriteBack)
            .unwrap();
        assert!(matches!(
            DmaMapping::map(domain, pin, Direction::ToDevice, u32::MAX as u64),
            Err(DmaError::AddressLimit)
        ));
        assert_eq!(ALLOCATOR.usage().live, before);
        let second = source
            .allocate(8192, 8192, CacheAttribute::WriteBack)
            .unwrap();
        let second_mapping = second.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        assert_eq!(second_mapping.address(0, 8192).unwrap().as_ptr(), pointer);
        // SAFETY: CPU-exclusive mapping; reclaimed RAM was actually zeroed again.
        assert_eq!(unsafe { pointer.add(8191).read_volatile() }, 0);
        drop(second_mapping);
        drop(second);
        assert_eq!(ALLOCATOR.usage().live, before);
        // SAFETY: no allocation remains from the test RAM.
        unsafe { std::alloc::dealloc(ram, layout) };
    }
}
