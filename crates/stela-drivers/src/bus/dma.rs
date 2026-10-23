//! Host-physical memory that devices read and write.
use crate::block::BlockError;
use core::ops::Range;

pub mod amd;
pub mod mapping;
pub mod memory;
pub mod pages;

mod sealed {
    pub trait DmaValue {}
}

/// Integer words whose every bit pattern is valid when written by a device.
/// Sealed so safe reads cannot manufacture a reference, `bool` or Rust enum
/// from arbitrary DMA bytes.
pub trait DmaValue: Copy + sealed::DmaValue {}

macro_rules! dma_values {
    ($($word:ty),+ $(,)?) => {$(
        impl sealed::DmaValue for $word {}
        impl DmaValue for $word {}
    )+};
}
dma_values!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

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

    fn word<T: DmaValue>(&self, offset: usize) -> *mut T {
        assert!(
            offset <= self.bytes && size_of::<T>() <= self.bytes - offset,
            "DMA word outside buffer"
        );
        // SAFETY: bounds were checked without overflow. The allocator grants
        // this live RAM range for the rest of the boot.
        let pointer = unsafe { self.as_ptr().add(offset) }.cast::<T>();
        assert!(
            (pointer as usize).is_multiple_of(align_of::<T>()),
            "unaligned DMA word"
        );
        pointer
    }

    /// Volatile access for structures the device updates while the CPU polls.
    /// This checks both the complete word's bounds and its actual alignment.
    ///
    /// ```compile_fail
    /// use stela_drivers::bus::dma::DmaBuffer;
    /// fn invalid_boolean(buffer: &DmaBuffer) -> bool {
    ///     buffer.read(0)
    /// }
    /// ```
    pub fn read<T: DmaValue>(&self, offset: usize) -> T {
        // SAFETY: word checks bounds/alignment; every T bit pattern is valid.
        unsafe { self.word::<T>(offset).read_volatile() }
    }

    pub fn write<T: DmaValue>(&mut self, offset: usize, value: T) {
        // SAFETY: same checked word; &mut self owns this CPU write.
        unsafe { self.word::<T>(offset).write_volatile(value) }
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
    extern crate std;

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

    #[test]
    fn integer_words_preserve_device_bits_and_neighbor_bytes() {
        let mut backing = [0u64; 4];
        let mut buffer = DmaBuffer {
            physical: backing.as_mut_ptr() as u64,
            bytes: size_of_val(&backing),
        };
        buffer.bytes_mut().fill(0xa5);
        buffer.write(2, 0x1234u16);
        buffer.write(8, -2i32);
        buffer.write(24, u64::MAX);
        assert_eq!(buffer.read::<u16>(2), 0x1234);
        assert_eq!(buffer.read::<i32>(8), -2);
        assert_eq!(buffer.read::<u64>(24), u64::MAX);
        assert_eq!(&buffer.bytes()[..2], &[0xa5; 2]);
        assert_eq!(&buffer.bytes()[4..8], &[0xa5; 4]);
        assert_eq!(&buffer.bytes()[12..24], &[0xa5; 12]);
    }

    #[test]
    fn invalid_word_ranges_and_actual_alignment_refuse_before_access() {
        let mut backing = [0xa5a5_a5a5_a5a5_a5a5u64; 4];
        let original = backing;
        let mut buffer = DmaBuffer {
            physical: backing.as_mut_ptr() as u64,
            bytes: size_of_val(&backing),
        };
        for offset in [1, 29, 32, usize::MAX - 1, usize::MAX] {
            assert!(std::panic::catch_unwind(|| buffer.read::<u32>(offset)).is_err());
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    buffer.write(offset, 0u32)
                }))
                .is_err()
            );
        }
        // Aligned offsets do not repair an allocator's unaligned base.
        let unaligned = DmaBuffer {
            physical: buffer.physical() + 1,
            bytes: buffer.len() - 1,
        };
        assert!(std::panic::catch_unwind(|| unaligned.read::<u32>(0)).is_err());
        assert_eq!(backing, original);
    }
}
