//! The DMA domain a requester gets when no IOMMU unit translates for it: the
//! device addresses the host's physical pages directly. It confines no DMA;
//! it maps a request only when the pages are one physically contiguous run
//! inside the region handed to the drivers and below the device's address
//! limit, and gives that run's physical address as its IOVA. The host's
//! caches snoop device DMA to write-back memory, so a sync is the full fence
//! that drains write-combining buffers before the device reads.
use core::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering, fence},
};
use stela_drivers::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DomainMapping},
    pages::DmaPages,
};

pub struct Passthrough {
    region: Range<u64>,
    next: AtomicU64,
}

impl Passthrough {
    /// Device DMA to the pages of `region`.
    pub fn new(region: Range<u64>) -> Self {
        Self {
            region,
            next: AtomicU64::new(1),
        }
    }

    /// The one contiguous physical run `physical` (pages of `1 << shift`
    /// bytes) covers, when it lies in the region and below `limit`.
    fn span(&self, physical: &[u64], shift: u8, limit: u64) -> Result<Range<u64>, DmaError> {
        let page = 1u64
            .checked_shl(u32::from(shift))
            .ok_or(DmaError::InvalidRange)?;
        let (&first, rest) = physical.split_first().ok_or(DmaError::InvalidRange)?;
        let mut end = first.checked_add(page).ok_or(DmaError::InvalidRange)?;
        for &address in rest {
            if address != end {
                return Err(DmaError::MappingFailed);
            }
            end = end.checked_add(page).ok_or(DmaError::InvalidRange)?;
        }
        if first < self.region.start || end > self.region.end {
            return Err(DmaError::InvalidRange);
        }
        if end - 1 > limit {
            return Err(DmaError::AddressLimit);
        }
        Ok(first..end)
    }
}

// SAFETY: there is no translation to install or invalidate: the IOVA is the
// pages' physical address, which the caller's pin keeps for the mapping's
// life. Identifiers are unique by a monotonic counter. Syncs are full
// fences, which order CPU stores (including write-combining ones) before the
// device's reads and the device's completed writes before CPU reads on x86.
unsafe impl DmaDomain for Passthrough {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _direction: Direction,
        address_limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let span = self.span(pages.physical_pages(), pages.page_shift(), address_limit)?;
        let bytes = usize::try_from(span.end - span.start).map_err(|_| DmaError::InvalidRange)?;
        Ok(DomainMapping {
            id: self.next.fetch_add(1, Ordering::Relaxed),
            address: span.start,
            bytes,
        })
    }

    unsafe fn unmap(&self, _mapping: DomainMapping) -> Result<(), DmaError> {
        Ok(())
    }

    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _direction: Direction,
    ) -> Result<(), DmaError> {
        check(mapping, &range)?;
        fence(Ordering::SeqCst);
        Ok(())
    }

    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        _direction: Direction,
    ) -> Result<(), DmaError> {
        check(mapping, &range)?;
        fence(Ordering::SeqCst);
        Ok(())
    }
}

fn check(mapping: DomainMapping, range: &Range<usize>) -> Result<(), DmaError> {
    if range.start > range.end || range.end > mapping.bytes {
        return Err(DmaError::InvalidRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;

    fn domain() -> Passthrough {
        Passthrough::new(0x10_0000..0x20_0000)
    }

    #[test]
    fn a_contiguous_run_in_the_region_maps_at_its_physical_address() {
        let pages = [0x10_0000, 0x10_1000, 0x10_2000];
        assert_eq!(
            domain().span(&pages, 12, u64::MAX),
            Ok(0x10_0000..0x10_3000)
        );
    }

    #[test]
    fn scattered_pages_outside_pages_and_high_runs_refuse() {
        let domain = domain();
        assert_eq!(
            domain.span(&[0x10_0000, 0x10_2000], 12, u64::MAX),
            Err(DmaError::MappingFailed)
        );
        assert_eq!(
            domain.span(&[0x1f_f000, 0x20_0000], 12, u64::MAX),
            Err(DmaError::InvalidRange)
        );
        assert_eq!(
            domain.span(&[0xf_f000], 12, u64::MAX),
            Err(DmaError::InvalidRange)
        );
        assert_eq!(
            domain.span(&[0x1f_f000], 12, 0x1f_ffff - PAGE),
            Err(DmaError::AddressLimit)
        );
        assert_eq!(domain.span(&[], 12, u64::MAX), Err(DmaError::InvalidRange));
    }

    #[test]
    fn syncs_stay_inside_the_mapping() {
        let mapping = DomainMapping {
            id: 1,
            address: 0x10_0000,
            bytes: 0x2000,
        };
        assert_eq!(check(mapping, &(0..0x2000)), Ok(()));
        assert_eq!(
            check(mapping, &(0x1000..0x2001)),
            Err(DmaError::InvalidRange)
        );
    }
}
