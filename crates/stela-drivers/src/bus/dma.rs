//! Host-physical memory that devices read and write.
use crate::block::BlockError;
use core::ops::Range;

pub mod mapping;
pub mod memory;

/// Zeroed, physically contiguous memory a device may access, at the same
/// address in Stela's identity tables. It lives for the rest of the boot.
#[derive(Debug)]
pub struct DmaBuffer {
    physical: u64,
    bytes: usize,
}

impl DmaBuffer {
    pub fn physical(&self) -> u64 {
        self.physical
    }

    pub fn len(&self) -> usize {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.physical as *mut u8
    }

    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the allocator handed this range out once, identity-mapped.
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.bytes) }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `bytes`, and `&mut self` is the only reference.
        unsafe { core::slice::from_raw_parts_mut(self.as_ptr(), self.bytes) }
    }

    /// Volatile access for structures the device updates while the CPU polls.
    pub fn read<T: Copy>(&self, offset: usize) -> T {
        assert!(offset + size_of::<T>() <= self.bytes);
        // SAFETY: in bounds; the caller picks a naturally aligned offset.
        unsafe { (self.as_ptr().add(offset) as *const T).read_volatile() }
    }

    pub fn write<T: Copy>(&mut self, offset: usize, value: T) {
        assert!(offset + size_of::<T>() <= self.bytes);
        // SAFETY: as in `read`.
        unsafe { (self.as_ptr().add(offset) as *mut T).write_volatile(value) }
    }
}

/// A source of DMA buffers.
pub trait DmaAllocator {
    /// `bytes` of zeroed memory aligned to `align`, a power of two.
    fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError>;
}

/// Hands out a fixed range of identity-mapped pages front to back.
pub struct RegionAllocator {
    next: u64,
    end: u64,
}

impl RegionAllocator {
    /// # Safety
    ///
    /// `region` must be RAM that only this allocator hands out, mapped
    /// writable at the same address, and reachable by every device's DMA.
    pub unsafe fn new(region: Range<u64>) -> Self {
        Self {
            next: region.start,
            end: region.end,
        }
    }

    pub fn remaining(&self) -> u64 {
        self.end - self.next
    }
}

impl DmaAllocator for RegionAllocator {
    fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
        assert!(align.is_power_of_two());
        let start = self
            .next
            .checked_next_multiple_of(align as u64)
            .ok_or(BlockError::NoDmaMemory)?;
        let end = start
            .checked_add(bytes as u64)
            .filter(|end| *end <= self.end)
            .ok_or(BlockError::NoDmaMemory)?;
        self.next = end;
        let mut buffer = DmaBuffer {
            physical: start,
            bytes,
        };
        buffer.bytes_mut().fill(0);
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn region_allocations_are_aligned_zeroed_and_bounded() {
        let mut backing: Vec<u64> = vec![u64::MAX; 4096];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: the vector outlives the allocator and nothing else uses it.
        let mut allocator = unsafe { RegionAllocator::new(start..start + 32768) };
        let first = allocator.allocate(100, 8).unwrap();
        assert_eq!(first.physical(), start);
        assert!(first.bytes().iter().all(|byte| *byte == 0));
        let page = allocator.allocate(4096, 4096).unwrap();
        assert!(page.physical().is_multiple_of(4096));
        assert!(page.physical() >= start + 100);
        assert_eq!(
            allocator.allocate(32768, 8).unwrap_err(),
            BlockError::NoDmaMemory
        );
        let mut word = allocator.allocate(8, 8).unwrap();
        word.write(0, 0x1234u32);
        assert_eq!(word.read::<u32>(0), 0x1234);
    }
}
