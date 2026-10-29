//! One real RAM reservation, its CPU view and its original device-domain lease.
//! Device alignment is selected from the IOVA after mapping. The same
//! byte offset is applied to the CPU view; no identity address is inferred.
use super::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource, PinnedPages},
};
use alloc::sync::{Arc, Weak};
use core::{fmt, ops::Range, ptr::NonNull};

// DmaMapping validates this minimum IOVA alignment independently of native
// page geometry, physical placement or the CPU mapping's alignment.
const IOVA_GRANULE: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    InvalidSize,
    InvalidAlignment,
    AddressOverflow,
    InsufficientBacking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Layout(LayoutError),
    Memory(MemoryError),
    Dma(DmaError),
    /// A fresh unpublished mapping was rejected, and acknowledged removal
    /// also failed. Its complete lease is quarantined by DmaMapping::Drop.
    Cleanup {
        rejected: LayoutError,
        failure: DmaError,
    },
}
impl From<MemoryError> for Error {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}
impl From<DmaError> for Error {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

/// A bounded logical subview of one complete mapping. The private CPU
/// and device leases are always derived from the same consumed pins. Padding
/// remains owned/mapped until the original whole token is removed.
///
/// CPU pointers grant no DMA completion or permission to race a device. No
/// safe slices are exposed. Consumers keep their original requester, root,
/// configuration, IRQ/work and execution-context owners independently.
/// Dropping an active region quarantines its domain and backing through the
/// canonical DmaMapping path; Drop never invents stop or drain completion.
pub struct DmaRegion {
    cpu: CpuMapping,
    dma: DmaMapping,
    domain: Weak<dyn DmaDomain>,
    offset: usize,
    bytes: usize,
}
impl fmt::Debug for DmaRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmaRegion")
            .field("bytes", &self.bytes)
            .field("reserved_bytes", &self.dma.bytes())
            .field("offset", &self.offset)
            .field("lease_active", &self.dma.address().is_ok())
            .finish()
    }
}

fn allocation_bytes(bytes: usize, alignment: usize) -> Result<usize, LayoutError> {
    if bytes == 0 || bytes > isize::MAX as usize {
        return Err(LayoutError::InvalidSize);
    }
    if !alignment.is_power_of_two() {
        return Err(LayoutError::InvalidAlignment);
    }
    // Every accepted IOVA already has 4 KiB alignment. Larger power-of-two
    // device alignment needs at most alignment-4KiB bytes of leading space.
    bytes
        .checked_add(alignment.saturating_sub(IOVA_GRANULE))
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(LayoutError::InvalidSize)
}

fn window(
    base: u64,
    capacity: usize,
    bytes: usize,
    alignment: usize,
) -> Result<usize, LayoutError> {
    let mask = alignment as u64 - 1;
    let address = base.checked_add(mask).ok_or(LayoutError::AddressOverflow)? & !mask;
    let offset = usize::try_from(address - base).map_err(|_| LayoutError::AddressOverflow)?;
    if offset.checked_add(bytes).is_none_or(|end| end > capacity) {
        return Err(LayoutError::InsufficientBacking);
    }
    Ok(offset)
}

impl DmaRegion {
    /// Allocate real native pages, including bounded device-alignment padding,
    /// then derive CPU/IOMMU views from that same reservation. This changes no
    /// physical alignment/granule and creates no additional CPU/cache alias.
    /// Allocation has the source's initialization policy; this operation does
    /// not claim the payload is zero or touch bytes without CPU ownership.
    pub fn allocate(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        direction: Direction,
        address_limit: u64,
    ) -> Result<Self, Error> {
        let capacity = allocation_bytes(bytes, alignment).map_err(Error::Layout)?;
        let geometry = source.page_geometry()?;
        let pages = source.allocate(capacity, geometry.base_bytes(), attribute)?;
        if pages.logical_bytes() < capacity || pages.bytes() < capacity {
            return Err(MemoryError::InvalidSize.into());
        }
        if !geometry.supports(pages.page_shift()) {
            return Err(MemoryError::InvalidPageList.into());
        }
        if pages.cache_attribute() != attribute {
            return Err(MemoryError::CacheAttributeUnavailable.into());
        }
        Self::map(pages, domain, bytes, alignment, direction, address_limit)
    }

    /// Map these original pins and use their established CPU cache
    /// policy. The complete reserved pages are mapped, including padding.
    /// Callers supplying pins directly must provide sufficient leading space
    /// unless the allocated IOVA already meets the requested alignment.
    /// Nothing is published to a device until the caller programs that device.
    pub fn map(
        pages: PinnedPages,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        alignment: usize,
        direction: Direction,
        address_limit: u64,
    ) -> Result<Self, Error> {
        allocation_bytes(bytes, alignment).map_err(Error::Layout)?;
        if bytes > pages.bytes() {
            return Err(Error::Layout(LayoutError::InsufficientBacking));
        }
        let cpu = pages.cpu_mapping(pages.cache_attribute())?;
        let original_domain = Arc::downgrade(&domain);
        let mut dma = DmaMapping::map(domain, pages, direction, address_limit)?;
        let base = dma.address()?;
        let offset = match window(base, cpu.bytes(), bytes, alignment) {
            Ok(offset) => offset,
            Err(rejected) => {
                // SAFETY: no caller/device has received this fresh IOVA or
                // any pointer into it. Remove the original full mapping.
                return match unsafe { dma.unmap() } {
                    Ok(()) => Err(Error::Layout(rejected)),
                    Err(failure) => Err(Error::Cleanup { rejected, failure }),
                };
            }
        };
        Ok(Self {
            cpu,
            dma,
            domain: original_domain,
            offset,
            bytes,
        })
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
    /// Complete kept mapping capacity, including invisible leading/tail
    /// space and native page rounding. This is never a larger logical payload.
    pub fn reserved_bytes(&self) -> usize {
        self.dma.bytes()
    }
    pub fn cache_attribute(&self) -> CacheAttribute {
        self.cpu.cache_attribute()
    }

    /// Compare the original domain allocation, never a numeric device
    /// or IOVA. A retired region refuses membership. This proves no controller
    /// epoch, payload completion or caller-specific allocation ownership.
    pub fn belongs_to_domain(&self, domain: &Arc<dyn DmaDomain>) -> bool {
        self.dma.address().is_ok() && self.domain.ptr_eq(&Arc::downgrade(domain))
    }

    fn range(&self, range: Range<usize>) -> Result<Range<usize>, Error> {
        if range.start > range.end || range.end > self.bytes {
            return Err(DmaError::InvalidRange.into());
        }
        Ok(self.offset + range.start..self.offset + range.end)
    }

    /// An IOVA range from this live lease, never a CPU or physical
    /// address. Unmapping permanently revokes device-address queries.
    pub fn device_address(&self, offset: usize, bytes: usize) -> Result<u64, Error> {
        let end = offset
            .checked_add(bytes)
            .ok_or(Error::Dma(DmaError::InvalidRange))?;
        let range = self.range(offset..end)?;
        self.dma
            .address()?
            .checked_add(range.start as u64)
            .ok_or(Error::Layout(LayoutError::AddressOverflow))
    }

    /// The corresponding CPU range from the SAME original pin and
    /// byte offset. Dereferencing it requires the caller's CPU/DMA ownership,
    /// device completion/cache visibility and original execution-context proof.
    pub fn cpu_address(&self, offset: usize, bytes: usize) -> Result<NonNull<u8>, Error> {
        let end = offset
            .checked_add(bytes)
            .ok_or(Error::Dma(DmaError::InvalidRange))?;
        let range = self.range(offset..end)?;
        Ok(self.cpu.address(range.start, bytes)?)
    }

    pub fn sync_for_device(&self, range: Range<usize>) -> Result<(), Error> {
        self.dma.sync_for_device(self.range(range)?)?;
        Ok(())
    }

    /// # Safety
    /// Device completion and stopped access establish CPU ownership of
    /// this exact range; do not invalidate live neighboring device buffers.
    pub unsafe fn sync_for_cpu(&self, range: Range<usize>) -> Result<(), Error> {
        // SAFETY: original token and translated subrange remain private; the
        // caller supplies real completion and CPU ownership, never a timeout.
        unsafe {
            self.dma.sync_for_cpu(self.range(range)?)?;
        }
        Ok(())
    }

    /// Domain-checked coherent observation. WB pages or a CPU fence
    /// alone cannot enable it. No multiword snapshot/freshness is inferred.
    pub fn read_coherent_u32(&self, offset: usize) -> Result<u32, Error> {
        let end = offset
            .checked_add(4)
            .ok_or(Error::Dma(DmaError::InvalidRange))?;
        let range = self.range(offset..end)?;
        Ok(self.dma.read_coherent_u32(range.start)?)
    }

    /// Retire the ORIGINAL complete mapping token, including every padding
    /// page. Failure leaves this same region/IOVA/pins kept for retry.
    /// The CPU pin remains valid until this region is dropped.
    ///
    /// # Safety
    /// Engines/submissions are stopped, all payload/posted DMA has
    /// completed/drained and IRQ/work/callback users cannot resume access.
    /// Keep the original requester/configuration/root/IRQ/context owners
    /// throughout removal; BME-clear or a replacement domain proves none of it.
    pub unsafe fn unmap(&mut self) -> Result<(), Error> {
        // SAFETY: caller supplies complete original-path quiescence;
        // DmaMapping keeps its private whole token through invalidation.
        unsafe {
            self.dma.unmap()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
