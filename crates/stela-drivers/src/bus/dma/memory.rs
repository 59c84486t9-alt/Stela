//! Owned native RAM pins and CPU mappings. Device addresses come from a DMA
//! domain, never from the CPU address or this allocation's physical page list.
use alloc::{boxed::Box, sync::Arc};
use core::{ops::Range, ptr::NonNull};

/// The CPU mapping's actual cache policy. RAM and VRAM are not interchangeable.
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

/// The platform's real allocator; implementations must retain the reservation
/// and the CPU mapping until the last pin or mapping is released.
pub trait PageSource {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError>;
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

/// A retained pin on a real allocation. Cloning a pin never allocates new pages.
#[derive(Clone)]
pub struct PinnedPages {
    backing: Arc<dyn PageBacking>,
    logical_bytes: usize,
    bytes: usize,
    alignment: usize,
}

impl PinnedPages {
    /// Accept an actual platform reservation. Validation does not manufacture
    /// physical addresses or change the established cache policy.
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
            let mut sorted = pages.to_vec();
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
            backing: Arc::from(backing),
            logical_bytes,
            bytes,
            alignment,
        })
    }

    /// Exact requested payload length, independently of whole-page padding.
    pub fn logical_bytes(&self) -> usize {
        self.logical_bytes
    }

    /// Actual reserved/mappable bytes, including the final whole-page tail.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Actual native CPU/DMA page size; never the translated guest granule.
    pub fn page_shift(&self) -> u8 {
        self.backing.page_shift()
    }

    pub fn physical_pages(&self) -> &[u64] {
        self.backing.physical_pages()
    }

    pub fn cache_attribute(&self) -> CacheAttribute {
        self.backing.cache_attribute()
    }

    /// Retain the established CPU mapping. Creating an incompatible alias is
    /// refused; this does not reinterpret WB system RAM as WC VRAM.
    pub fn cpu_mapping(&self, attribute: CacheAttribute) -> Result<CpuMapping, MemoryError> {
        self.cpu_mapping_range(attribute, 0..self.bytes())
    }

    /// Bounded view into the retained full-page CPU mapping. Padding may be
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

/// The CPU mapping retains its page pin independently of the caller's handle.
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
