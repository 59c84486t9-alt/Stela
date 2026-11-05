//! Geometry of a relocated image inside an independently owned allocation.
//! This describes byte ranges only; it creates no allocation, code or root pin.
use core::ops::Range;

const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Geometry,
    Overflow,
    OutsideAllocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    allocation: (u64, u64),
    physical: u64,
    bytes: u64,
    virtual_base: u64,
}
impl Layout {
    pub fn within(
        allocation: Range<u64>,
        image_bytes: usize,
        alignment: u64,
        virtual_base: u64,
    ) -> Result<Self, Error> {
        if allocation.start == 0
            || allocation.start >= allocation.end
            || !allocation.start.is_multiple_of(PAGE)
            || !allocation.end.is_multiple_of(PAGE)
            || image_bytes == 0
            || image_bytes > isize::MAX as usize
            || alignment < PAGE
            || !alignment.is_power_of_two()
            || !virtual_base.is_multiple_of(PAGE)
        {
            return Err(Error::Geometry);
        }
        let bytes = (image_bytes as u64)
            .checked_next_multiple_of(PAGE)
            .ok_or(Error::Overflow)?;
        let physical = allocation
            .start
            .checked_next_multiple_of(alignment)
            .ok_or(Error::Overflow)?;
        let end = physical.checked_add(bytes).ok_or(Error::Overflow)?;
        virtual_base.checked_add(bytes).ok_or(Error::Overflow)?;
        if end > allocation.end {
            return Err(Error::OutsideAllocation);
        }
        Ok(Self {
            allocation: (allocation.start, allocation.end),
            physical,
            bytes,
            virtual_base,
        })
    }
    pub fn allocation(self) -> Range<u64> {
        self.allocation.0..self.allocation.1
    }
    pub fn physical(self) -> Range<u64> {
        self.physical..self.physical + self.bytes
    }
    pub fn virtual_range(self) -> Range<u64> {
        self.virtual_base..self.virtual_base + self.bytes
    }
    pub fn overlaps(self, other: Range<u64>) -> bool {
        self.allocation.0 < other.end && other.start < self.allocation.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rounded_copy_stays_in_original_allocation() {
        let image =
            Layout::within(0x101000..0x501000, 0x200001, 0x200000, 0xffff800000000000).unwrap();
        assert_eq!(image.physical(), 0x200000..0x401000);
        assert_eq!(image.allocation(), 0x101000..0x501000);
        assert_eq!(
            image.virtual_range(),
            0xffff800000000000..0xffff800000201000
        );
    }
    #[test]
    fn allocation_padding_remains_excluded_from_reuse() {
        let image = Layout::within(0x101000..0x501000, 4096, 0x200000, 0x10000000).unwrap();
        assert!(image.overlaps(0x101000..0x102000));
        assert!(image.overlaps(0x500000..0x501000));
        assert!(!image.overlaps(0x100000..0x101000));
        assert!(!image.overlaps(0x501000..0x502000));
    }
    #[test]
    fn malformed_allocations_and_virtual_extents_refuse() {
        for (allocation, bytes, alignment, virtual_base, error) in [
            (0..0x100000, 1, 4096, 0x1000, Error::Geometry),
            (0x1000..0x1000, 1, 4096, 0x1000, Error::Geometry),
            (0x1001..0x3000, 1, 4096, 0x1000, Error::Geometry),
            (0x1000..0x3001, 1, 4096, 0x1000, Error::Geometry),
            (0x1000..0x3000, 0, 4096, 0x1000, Error::Geometry),
            (0x1000..0x3000, 1, 8191, 0x1000, Error::Geometry),
            (0x1000..0x3000, 1, 4096, 0x1001, Error::Geometry),
            (0x1000..0x3000, 8193, 4096, 0x1000, Error::OutsideAllocation),
            (0x1000..0x3000, 1, 4096, u64::MAX - 4095, Error::Overflow),
        ] {
            assert_eq!(
                Layout::within(allocation, bytes, alignment, virtual_base),
                Err(error)
            );
        }
    }
}
