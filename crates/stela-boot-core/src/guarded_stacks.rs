//! Geometry for distinct page-backed stacks with an unmapped page on each side.
//!
//! These records describe layout only. They confer no allocation, CPU, mapping,
//! initialization, or invocation permission; the native owner proves those.
pub mod mappings;
mod mixed;
use core::ops::Range;
pub use mixed::{Geometry, MixedLayout};
const PAGE: u64 = 4096;
const MAX_STACKS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    Alignment,
    Overflow,
    Slot,
}
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    bytes: u64,
    count: usize,
    stride: u64,
    physical: u64,
    virtual_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Slot {
    pub lower_guard: Range<u64>,
    pub usable: Range<u64>,
    pub upper_guard: Range<u64>,
}
impl Layout {
    pub fn new(bytes: u64, count: usize) -> Result<Self, Error> {
        if count == 0 || count > MAX_STACKS {
            return Err(Error::Capacity);
        }
        if bytes == 0 || !bytes.is_multiple_of(PAGE) {
            return Err(Error::Alignment);
        }
        let stride = bytes.checked_add(2 * PAGE).ok_or(Error::Overflow)?;
        Ok(Self {
            bytes,
            count,
            stride,
            physical: bytes.checked_mul(count as u64).ok_or(Error::Overflow)?,
            virtual_bytes: stride.checked_mul(count as u64).ok_or(Error::Overflow)?,
        })
    }
    pub fn physical_bytes(&self) -> u64 {
        self.physical
    }
    pub fn virtual_bytes(&self) -> u64 {
        self.virtual_bytes
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn slot(&self, base: u64, index: usize) -> Result<Slot, Error> {
        if index >= self.count {
            return Err(Error::Slot);
        }
        if !base.is_multiple_of(PAGE) {
            return Err(Error::Alignment);
        }
        // Validate the complete reservation, including the last upper guard.
        base.checked_add(self.virtual_bytes)
            .ok_or(Error::Overflow)?;
        let guard = base + self.stride * index as u64;
        let first = guard + PAGE;
        let end = first + self.bytes;
        Ok(Slot {
            lower_guard: guard..first,
            usable: first..end,
            upper_guard: end..end + PAGE,
        })
    }
    pub fn physical_offset(&self, index: usize) -> Result<u64, Error> {
        if index >= self.count {
            return Err(Error::Slot);
        }
        Ok(self.bytes * index as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guards_and_backings_are_distinct_at_every_supported_capacity() {
        for count in 1..=MAX_STACKS {
            let layout = Layout::new(128 * 1024, count).unwrap();
            let mut previous = 0;
            for index in 0..count {
                let slot = layout.slot(0, index).unwrap();
                assert_eq!(slot.lower_guard.start, previous);
                assert_eq!(
                    (slot.lower_guard.end - slot.lower_guard.start) as usize,
                    PAGE as usize
                );
                assert_eq!(
                    (slot.upper_guard.end - slot.upper_guard.start) as usize,
                    PAGE as usize
                );
                assert_eq!((slot.usable.end - slot.usable.start) as usize, 128 * 1024);
                assert_eq!(
                    layout.physical_offset(index).unwrap(),
                    index as u64 * 128 * 1024
                );
                previous = slot.upper_guard.end;
            }
            assert_eq!(previous, layout.virtual_bytes());
            assert_eq!(layout.physical_bytes(), count as u64 * 128 * 1024);
            assert!(layout.slot(0, count).is_err());
        }
    }
    #[test]
    fn zero_unaligned_and_wrapping_reservations_refuse() {
        for count in [0, MAX_STACKS + 1] {
            assert_eq!(Layout::new(PAGE, count).unwrap_err(), Error::Capacity);
        }
        for bytes in [0, 1, PAGE - 1, PAGE + 1] {
            assert_eq!(Layout::new(bytes, 1).unwrap_err(), Error::Alignment);
        }
        assert_eq!(Layout::new(!(PAGE - 1), 1).unwrap_err(), Error::Overflow);
        assert_eq!(Layout::new(1 << 63, 2).unwrap_err(), Error::Overflow);
        let layout = Layout::new(PAGE, 1).unwrap();
        assert_eq!(layout.slot(1, 0).unwrap_err(), Error::Alignment);
        assert_eq!(layout.slot(!(PAGE - 1), 0).unwrap_err(), Error::Overflow);
    }
}
