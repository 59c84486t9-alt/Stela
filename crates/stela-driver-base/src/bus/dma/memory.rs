//! Owned native RAM pins and CPU mappings. Device addresses come from a DMA
//! domain, never from the CPU address or this allocation's physical page list.
use alloc::{boxed::Box, vec::Vec};
use core::{ops::Range, ptr::NonNull};
use triomphe::Arc;

/// The CPU mapping's cache policy. RAM and VRAM are not interchangeable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheAttribute {
    WriteBack,
    WriteCombining,
    Uncached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    InvalidSize,
    InvalidAlignment,
    OutOfMemory,
    OutsideReservation,
    InvalidPageList,
    CacheAttributeUnavailable,
    Unavailable,
}

/// The native allocation granules attested by one [`PageSource`].
///
/// Every power-of-two granule in the inclusive range is supported. A provider
/// with holes must select a smaller complete profile or report unavailable.
/// This is independent of allocation byte capacity, requested alignment, MMIO
/// pages and the translated guest's page size. It grants no reservation,
/// mapping, cache policy or firmware-memory import permission.
///
/// Constructing this description does not establish physical support. Only a
/// successful query of the allocation provider attests its profile;
/// consumers must also check each returned [`PinnedPages::page_shift`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageGeometry {
    base_shift: u8,
    max_shift: u8,
}

impl PageGeometry {
    /// A conservative provider profile with exactly one native granule.
    pub fn base_only(shift: u8) -> Result<Self, MemoryError> {
        Self::contiguous(shift, shift)
    }

    /// Describe a complete inclusive range of power-of-two native granules.
    /// Invalid or unrepresentable page extents return `InvalidPageList`.
    pub fn contiguous(base_shift: u8, max_shift: u8) -> Result<Self, MemoryError> {
        if base_shift < 12 || base_shift > max_shift || u32::from(max_shift) >= usize::BITS - 1 {
            return Err(MemoryError::InvalidPageList);
        }
        Ok(Self {
            base_shift,
            max_shift,
        })
    }

    pub fn base_shift(self) -> u8 {
        self.base_shift
    }

    pub fn max_shift(self) -> u8 {
        self.max_shift
    }

    pub fn base_bytes(self) -> usize {
        1usize << self.base_shift
    }

    pub fn max_bytes(self) -> usize {
        1usize << self.max_shift
    }

    pub fn supports(self, shift: u8) -> bool {
        (self.base_shift..=self.max_shift).contains(&shift)
    }
}

/// The platform's real allocator; implementations must keep the reservation
/// and the CPU mapping until the last pin or mapping is released.
pub trait PageSource {
    /// Query this provider's immutable supported-granule profile.
    ///
    /// Providers must attest every granule in the range and keep the profile
    /// stable while users or allocations can keep it. Allocations made through
    /// this provider must return a page shift in that profile. A contiguous byte
    /// allocation or a large alignment alone does not establish a larger granule.
    /// Legacy/unknown providers remain explicitly unavailable; there is no
    /// inferred 4 KiB default. The native owner supplies any concrete override.
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        Err(MemoryError::Unavailable)
    }

    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError>;

    /// Allocate with every byte of every returned native page below this
    /// exclusive physical end, including the complete rounded payload tail.
    /// CPU addresses, logical length and a DMA/IOVA limit cannot stand in for
    /// this physical constraint. All ordinary ownership/cache/alignment rules
    /// still apply. No additional RAM or DMA permission is acquired.
    ///
    /// Providers must select from their eligible free memory, rather
    /// than repeatedly allocating and discarding unsuitable pins. An admitted
    /// reservation with no eligible capacity returns `OutOfMemory`; a provider
    /// without constrained selection returns `Unavailable`, without trying an
    /// ordinary allocation or inferring support from one successful result.
    fn allocate_below(
        &self,
        _bytes: usize,
        _alignment: usize,
        _attribute: CacheAttribute,
        _physical_end_exclusive: u64,
    ) -> Result<PinnedPages, MemoryError> {
        Err(MemoryError::Unavailable)
    }
}

/// A borrowed provider, such as the mount's `&'static dyn PageSource`.
impl<T: PageSource + ?Sized> PageSource for &T {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        (**self).page_geometry()
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        (**self).allocate(bytes, alignment, attribute)
    }
    fn allocate_below(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        physical_end_exclusive: u64,
    ) -> Result<PinnedPages, MemoryError> {
        (**self).allocate_below(bytes, alignment, attribute, physical_end_exclusive)
    }
}

/// The unique owner of an allocation and its established CPU mapping.
///
/// # Safety
/// Every physical page must be real, exclusively reserved RAM, excluded from
/// guest/free inventories and pinned against migration/reuse until `Drop`.
/// `cpu_base` must map those pages consecutively, with `cache_attribute`, for
/// the full allocation lifetime in every address space in which it is used.
/// All aliases must have compatible cache attributes. The pages must initially
/// be zeroed. Metadata and addresses must remain immutable. `Drop` ends the CPU
/// mapping/reservation and returns the real pages only after all users end.
/// Implementations must obey their platform's interrupt/context locking rules.
pub unsafe trait PageBacking: Send + Sync {
    fn cpu_base(&self) -> NonNull<u8>;
    fn physical_pages(&self) -> &[u64];
    fn page_shift(&self) -> u8;
    fn cache_attribute(&self) -> CacheAttribute;
}

/// A kept pin on a real allocation. Cloning a pin never allocates new pages.
#[derive(Clone)]
pub struct PinnedPages {
    backing: Arc<Box<dyn PageBacking>>,
    logical_bytes: usize,
    bytes: usize,
    alignment: usize,
}

impl PinnedPages {
    /// Accept a platform reservation. Validation does not manufacture
    /// physical addresses or change the established cache policy. Scratch and
    /// shared-owner allocation are fallible; any error releases the backing.
    pub fn new(
        backing: Box<dyn PageBacking>,
        logical_bytes: usize,
        alignment: usize,
    ) -> Result<Self, MemoryError> {
        let size = 1usize
            .checked_shl(u32::from(backing.page_shift()))
            .filter(|size| *size >= 4096)
            .ok_or(MemoryError::InvalidPageList)?;
        let pages = backing.physical_pages();
        let bytes = pages
            .len()
            .checked_mul(size)
            .filter(|bytes| *bytes != 0 && *bytes <= isize::MAX as usize)
            .ok_or(MemoryError::InvalidPageList)?;
        let cpu = backing.cpu_base().as_ptr() as usize;
        if logical_bytes == 0 || logical_bytes > bytes {
            return Err(MemoryError::InvalidSize);
        }
        if !alignment.is_power_of_two()
            || alignment < size
            || !cpu.is_multiple_of(alignment)
            || !pages[0].is_multiple_of(alignment as u64)
        {
            return Err(MemoryError::InvalidAlignment);
        }
        let duplicate = if pages.is_sorted() {
            pages.windows(2).any(|pair| pair[0] == pair[1])
        } else {
            let mut sorted = Vec::new();
            sorted
                .try_reserve_exact(pages.len())
                .map_err(|_| MemoryError::OutOfMemory)?;
            sorted.extend_from_slice(pages);
            sorted.sort_unstable();
            sorted.windows(2).any(|pair| pair[0] == pair[1])
        };
        if !cpu.is_multiple_of(size)
            || cpu.checked_add(bytes).is_none()
            || pages
                .iter()
                .any(|pa| !pa.is_multiple_of(size as u64) || pa.checked_add(size as u64).is_none())
            || duplicate
        {
            return Err(MemoryError::InvalidPageList);
        }
        Ok(Self {
            backing: Arc::try_new(backing).map_err(|_| MemoryError::OutOfMemory)?,
            logical_bytes,
            bytes,
            alignment,
        })
    }

    /// Additional actual pin/mapping views prevent native epoch disposal.
    /// False is not proof that raw/C/DMA aliases retired; those are separate
    /// unsafe producer obligations. This observes no external backing callback.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn has_other_views(&self) -> bool {
        Arc::strong_count(&self.backing) != 1
    }

    /// Exact requested payload length, independently of whole-page padding.
    pub fn logical_bytes(&self) -> usize {
        self.logical_bytes
    }

    /// Reserved/mappable bytes, including the final whole-page tail.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Native CPU/DMA page size; never the translated guest granule.
    pub fn page_shift(&self) -> u8 {
        self.backing.page_shift()
    }

    pub fn physical_pages(&self) -> &[u64] {
        self.backing.physical_pages()
    }

    pub fn cache_attribute(&self) -> CacheAttribute {
        self.backing.cache_attribute()
    }

    /// Keep the established CPU mapping. Creating an incompatible alias is
    /// refused; this does not reinterpret WB system RAM as WC VRAM.
    pub fn cpu_mapping(&self, attribute: CacheAttribute) -> Result<CpuMapping, MemoryError> {
        self.cpu_mapping_range(attribute, 0..self.bytes())
    }

    /// Bounded view into the full-page CPU mapping. Padding may be
    /// mapped explicitly without changing the allocation's logical length.
    pub fn cpu_mapping_range(
        &self,
        attribute: CacheAttribute,
        range: Range<usize>,
    ) -> Result<CpuMapping, MemoryError> {
        if attribute != self.cache_attribute() {
            return Err(MemoryError::CacheAttributeUnavailable);
        }
        if range.start > range.end || range.end > self.bytes() {
            return Err(MemoryError::InvalidSize);
        }
        Ok(CpuMapping {
            pages: self.clone(),
            range,
        })
    }
}

/// The CPU mapping keeps its page pin independently of the caller's handle.
/// Raw pointers require the consumer's reservation/fence synchronization; no
/// Rust slice is exposed while a device can modify the allocation.
pub struct CpuMapping {
    pages: PinnedPages,
    range: Range<usize>,
}

impl CpuMapping {
    pub fn bytes(&self) -> usize {
        self.range.end - self.range.start
    }

    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub fn cache_attribute(&self) -> CacheAttribute {
        self.pages.cache_attribute()
    }

    pub fn address(&self, offset: usize, bytes: usize) -> Result<NonNull<u8>, MemoryError> {
        offset
            .checked_add(bytes)
            .filter(|end| *end <= self.bytes())
            .ok_or(MemoryError::InvalidSize)?;
        // SAFETY: the backing's mapping is live and the range was checked.
        Ok(unsafe { self.pages.backing.cpu_base().add(self.range.start + offset) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_rejects_unrepresentable_ranges_and_preserves_every_advertised_granule() {
        for base in 0..=u8::MAX {
            for max in 0..=u8::MAX {
                let result = PageGeometry::contiguous(base, max);
                let representable = base >= 12 && base <= max && u32::from(max) < usize::BITS - 1;
                if !representable {
                    assert_eq!(result, Err(MemoryError::InvalidPageList));
                    continue;
                }
                let geometry = result.unwrap();
                assert_eq!(geometry.base_shift(), base);
                assert_eq!(geometry.max_shift(), max);
                assert_eq!(geometry.base_bytes().trailing_zeros(), u32::from(base));
                assert_eq!(geometry.max_bytes().trailing_zeros(), u32::from(max));
                for shift in 0..=u8::MAX {
                    assert_eq!(geometry.supports(shift), base <= shift && shift <= max);
                }
            }
        }
    }

    // Hosted mapping fixture only. Symbolic physical labels
    // differ from the owned CPU buffer; this attests no native RAM.
    #[repr(align(8192))]
    struct Buffer([u8; 8192]);
    struct Backing {
        buffer: Box<Buffer>,
        pages: [u64; 2],
    }
    // SAFETY: the model owns its aligned zeroed buffer until the final pin or
    // mapping ends. Its immutable two-page model inventory is never dereferenced.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            NonNull::from(&self.buffer.0[0])
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

    #[test]
    fn page_inventory_validation_accepts_order_without_accepting_aliases() {
        for pages in [[0x10000, 0x11000], [0x11000, 0x10000]] {
            let pin = PinnedPages::new(
                Box::new(Backing {
                    buffer: Box::new(Buffer([0; 8192])),
                    pages,
                }),
                8192,
                4096,
            )
            .unwrap();
            assert_eq!(pin.physical_pages(), pages);
        }
        let result = PinnedPages::new(
            Box::new(Backing {
                buffer: Box::new(Buffer([0; 8192])),
                pages: [0x10000; 2],
            }),
            8192,
            4096,
        );
        assert!(matches!(result, Err(MemoryError::InvalidPageList)));
    }

    struct LegacySource;
    impl PageSource for LegacySource {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            if attribute != CacheAttribute::WriteBack {
                return Err(MemoryError::CacheAttributeUnavailable);
            }
            if bytes == 0 || bytes > 8192 {
                return Err(MemoryError::InvalidSize);
            }
            PinnedPages::new(
                Box::new(Backing {
                    buffer: Box::new(Buffer([0; 8192])),
                    pages: [0x10000, 0x11000],
                }),
                bytes,
                alignment,
            )
        }
    }
    struct AttestedSource;
    impl PageSource for AttestedSource {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            PageGeometry::base_only(12)
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            LegacySource.allocate(bytes, alignment, attribute)
        }
    }

    #[test]
    fn successful_allocation_does_not_invent_a_legacy_provider_geometry() {
        let source: &dyn PageSource = &LegacySource;
        let pages = source
            .allocate(5001, 8192, CacheAttribute::WriteBack)
            .unwrap();
        assert_eq!(pages.bytes(), 8192);
        assert_eq!(pages.alignment(), 8192);
        assert_eq!(pages.page_shift(), 12);
        assert_eq!(source.page_geometry(), Err(MemoryError::Unavailable));
    }

    #[test]
    fn constrained_support_is_not_inferred_or_implemented_by_trial_allocation() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        struct Source(AtomicUsize);
        impl PageSource for Source {
            fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
                PageGeometry::base_only(12)
            }
            fn allocate(
                &self,
                _: usize,
                _: usize,
                _: CacheAttribute,
            ) -> Result<PinnedPages, MemoryError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(MemoryError::OutOfMemory)
            }
        }
        let owner = Source(AtomicUsize::new(0));
        let source: &dyn PageSource = &owner;
        for end in [0, 1, 1 << 32, u64::MAX] {
            assert!(matches!(
                source.allocate_below(4096, 4096, CacheAttribute::WriteBack, end),
                Err(MemoryError::Unavailable)
            ));
        }
        assert_eq!(owner.0.load(Ordering::Relaxed), 0);
        let attested: &dyn PageSource = &AttestedSource;
        let ordinary = attested
            .allocate(4096, 4096, CacheAttribute::WriteBack)
            .unwrap();
        assert!(
            ordinary
                .physical_pages()
                .iter()
                .all(|pa| *pa + 4096 <= 0x20000)
        );
        assert!(matches!(
            attested.allocate_below(4096, 4096, CacheAttribute::WriteBack, 0x20000),
            Err(MemoryError::Unavailable)
        ));
    }

    #[test]
    fn base_only_profile_accepts_larger_allocations_without_claiming_larger_granules() {
        let source: &dyn PageSource = &AttestedSource;
        let geometry = source.page_geometry().unwrap();
        let pages = source
            .allocate(8192, 8192, CacheAttribute::WriteBack)
            .unwrap();
        assert_eq!(geometry.base_bytes(), 4096);
        assert_eq!(geometry.max_bytes(), 4096);
        assert!(geometry.supports(pages.page_shift()));
        assert!(!geometry.supports(13));
        assert!(pages.bytes() > geometry.max_bytes());
        assert!(pages.alignment() > geometry.max_bytes());
        assert_eq!(
            pages
                .cpu_mapping(CacheAttribute::WriteBack)
                .unwrap()
                .bytes(),
            8192
        );
    }
}
