//! Retained page sequences for device-domain mappings. Scatter metadata never
//! manufactures a contiguous CPU view or a new physical reservation.
use super::memory::{CacheAttribute, MemoryError, PinnedPages};
use alloc::vec::Vec;
use core::ops::Range;
use triomphe::Arc;

/// Whole-native-page subrange of an actual retained allocation. Padding within
/// the reserved final page is mappable; this does not change logical byte size.
#[derive(Clone)]
pub struct PageRange {
    pages: PinnedPages,
    range: Range<usize>,
}

impl PageRange {
    pub fn new(pages: PinnedPages, range: Range<usize>) -> Result<Self, MemoryError> {
        let granule = 1usize << pages.page_shift();
        if range.start >= range.end
            || range.end > pages.bytes()
            || !range.start.is_multiple_of(granule)
            || !range.end.is_multiple_of(granule)
        {
            return Err(MemoryError::InvalidSize);
        }
        Ok(Self { pages, range })
    }

    fn physical_pages(&self) -> &[u64] {
        let shift = self.pages.page_shift();
        &self.pages.physical_pages()[self.range.start >> shift..self.range.end >> shift]
    }
}

struct Scatter {
    // Retain every original owner until all mappings/quarantines release it.
    _ranges: Vec<PageRange>,
    physical: Vec<u64>,
    shift: u8,
    attribute: CacheAttribute,
}

#[derive(Clone)]
enum Backing {
    Single(PinnedPages),
    Scatter(Arc<Scatter>),
}

/// An ordered native-page sequence with retained ownership. Cloning allocates
/// nothing. Device addresses still require a real attached DmaDomain.
#[derive(Clone)]
pub struct DmaPages {
    backing: Backing,
}

impl From<PinnedPages> for DmaPages {
    fn from(pages: PinnedPages) -> Self {
        Self {
            backing: Backing::Single(pages),
        }
    }
}

impl DmaPages {
    /// Preserve caller order, including repeated pages, without copying data or
    /// creating a CPU mapping. Every range must share actual geometry/cache
    /// policy. An error releases all consumed ranges and metadata.
    pub fn from_ranges(ranges: Vec<PageRange>) -> Result<Self, MemoryError> {
        let first = ranges.first().ok_or(MemoryError::InvalidSize)?;
        let shift = first.pages.page_shift();
        let attribute = first.pages.cache_attribute();
        let mut count = 0usize;
        for range in &ranges {
            if range.pages.page_shift() != shift {
                return Err(MemoryError::InvalidPageList);
            }
            if range.pages.cache_attribute() != attribute {
                return Err(MemoryError::CacheAttributeUnavailable);
            }
            count = count
                .checked_add(range.physical_pages().len())
                .ok_or(MemoryError::InvalidSize)?;
        }
        count
            .checked_mul(1usize << shift)
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or(MemoryError::InvalidSize)?;
        let mut physical = Vec::new();
        physical
            .try_reserve_exact(count)
            .map_err(|_| MemoryError::OutOfMemory)?;
        for range in &ranges {
            physical.extend_from_slice(range.physical_pages());
        }
        let scatter = Arc::try_new(Scatter {
            _ranges: ranges,
            physical,
            shift,
            attribute,
        })
        .map_err(|_| MemoryError::OutOfMemory)?;
        Ok(Self {
            backing: Backing::Scatter(scatter),
        })
    }

    /// Return the original single allocation when this sequence has one.
    /// Scatter sequences never fabricate a contiguous CPU view.
    pub fn as_single(&self) -> Option<&PinnedPages> {
        match &self.backing {
            Backing::Single(pages) => Some(pages),
            Backing::Scatter(_) => None,
        }
    }

    pub fn physical_pages(&self) -> &[u64] {
        match &self.backing {
            Backing::Single(pages) => pages.physical_pages(),
            Backing::Scatter(scatter) => &scatter.physical,
        }
    }

    /// Granule of every retained page in this sequence, not a larger allocation
    /// or hardware-support claim inferred from total bytes or IOVA alignment.
    pub fn page_shift(&self) -> u8 {
        match &self.backing {
            Backing::Single(pages) => pages.page_shift(),
            Backing::Scatter(scatter) => scatter.shift,
        }
    }

    pub fn cache_attribute(&self) -> CacheAttribute {
        match &self.backing {
            Backing::Single(pages) => pages.cache_attribute(),
            Backing::Scatter(scatter) => scatter.attribute,
        }
    }

    pub fn bytes(&self) -> usize {
        self.physical_pages().len() << self.page_shift()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::memory::PageBacking;
    use alloc::{boxed::Box, sync::Arc as Shared};
    use core::{
        ptr::NonNull,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[repr(align(8192))]
    struct Buffer([u8; 8192]);
    struct Model {
        buffer: Box<Buffer>,
        physical: Vec<u64>,
        shift: u8,
        attribute: CacheAttribute,
        drops: Shared<AtomicUsize>,
    }
    impl Drop for Model {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: actual aligned zeroed test CPU storage, with immutable symbolic
    // physical labels never dereferenced or submitted to hardware.
    unsafe impl PageBacking for Model {
        fn cpu_base(&self) -> NonNull<u8> {
            NonNull::from(&self.buffer.0[0])
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            self.shift
        }
        fn cache_attribute(&self) -> CacheAttribute {
            self.attribute
        }
    }
    fn pin(
        base: u64,
        shift: u8,
        attribute: CacheAttribute,
        drops: &Shared<AtomicUsize>,
    ) -> PinnedPages {
        let granule = 1usize << shift;
        PinnedPages::new(
            Box::new(Model {
                buffer: Box::new(Buffer([0; 8192])),
                physical: (0..8192 / granule)
                    .map(|index| base + (index * granule) as u64)
                    .collect(),
                shift,
                attribute,
                drops: drops.clone(),
            }),
            8192,
            granule,
        )
        .unwrap()
    }

    #[test]
    fn scatter_preserves_order_aliases_and_original_owners() {
        let drops = Shared::new(AtomicUsize::new(0));
        let first = pin(0x80000, 12, CacheAttribute::WriteBack, &drops);
        let second = pin(0x20000, 12, CacheAttribute::WriteBack, &drops);
        let retained_cpu = second.cpu_mapping(CacheAttribute::WriteBack).unwrap();
        let pages = DmaPages::from_ranges(vec![
            PageRange::new(first.clone(), 4096..8192).unwrap(),
            PageRange::new(second.clone(), 0..8192).unwrap(),
            PageRange::new(first.clone(), 4096..8192).unwrap(),
        ])
        .unwrap();
        drop(first);
        drop(second);
        assert_eq!(pages.physical_pages(), [0x81000, 0x20000, 0x21000, 0x81000]);
        assert_eq!(pages.page_shift(), 12);
        assert_eq!(pages.bytes(), 16384);
        assert_eq!(pages.cache_attribute(), CacheAttribute::WriteBack);
        let cloned = pages.clone();
        drop(pages);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(cloned);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        // The original per-allocation CPU view still retains only its own pin.
        // SAFETY: retained mapping owns this initialized byte; no DMA exists.
        assert_eq!(
            // SAFETY: the pointer addresses this test's own live pages, and the stopped model
            // writes nothing concurrently.
            unsafe { retained_cpu.address(8191, 1).unwrap().as_ptr().read() },
            0
        );
        drop(retained_cpu);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn range_and_geometry_validation_never_invents_smaller_native_pages() {
        let drops = Shared::new(AtomicUsize::new(0));
        let first = pin(0x80000, 12, CacheAttribute::WriteBack, &drops);
        for range in [
            0..0,
            1..4096,
            0..8193,
            Range {
                start: 4096,
                end: 0,
            },
        ] {
            assert!(matches!(
                PageRange::new(first.clone(), range),
                Err(MemoryError::InvalidSize)
            ));
        }
        assert!(matches!(
            DmaPages::from_ranges(Vec::new()),
            Err(MemoryError::InvalidSize)
        ));
        let large = pin(0xa0000, 13, CacheAttribute::WriteBack, &drops);
        assert!(matches!(
            DmaPages::from_ranges(vec![
                PageRange::new(first.clone(), 0..4096).unwrap(),
                PageRange::new(large.clone(), 0..8192).unwrap(),
            ]),
            Err(MemoryError::InvalidPageList)
        ));
        let wc = pin(0xc0000, 12, CacheAttribute::WriteCombining, &drops);
        assert!(matches!(
            DmaPages::from_ranges(vec![
                PageRange::new(first.clone(), 0..4096).unwrap(),
                PageRange::new(wc, 0..4096).unwrap(),
            ]),
            Err(MemoryError::CacheAttributeUnavailable)
        ));
        let single = DmaPages::from(large);
        assert_eq!(single.page_shift(), 13);
        assert_eq!(single.physical_pages(), [0xa0000]);
        assert_eq!(single.bytes(), 8192);
        drop(single);
        drop(first);
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }
}
