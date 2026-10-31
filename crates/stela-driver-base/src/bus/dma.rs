//! Device-visible memory with distinct CPU mappings and bus addresses.
use crate::block::BlockError;
use core::ops::Range;

mod allocator;
pub mod amd;
pub use allocator::{AllocationError, DomainAllocator};
pub mod mapping;
pub mod memory;
pub mod pages;
pub mod region;

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

/// A zeroed DMA allocation. The CPU view and device address may differ, and
/// physical pages need not be contiguous when a requester domain maps them.
pub struct DmaBuffer {
    memory: BufferMemory,
    bytes: usize,
}

enum BufferMemory {
    // Compatibility with RegionAllocator's explicitly unsafe identity contract.
    Identity(u64),
    Domain(triomphe::Arc<allocator::Allocation>),
}

impl core::fmt::Debug for DmaBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaBuffer")
            .field("bus_address", &self.bus_address())
            .field("cpu_address", &self.as_ptr())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl DmaBuffer {
    /// The address programmed into this requester's device, never a CPU pointer.
    pub fn bus_address(&self) -> u64 {
        match &self.memory {
            BufferMemory::Identity(address) => *address,
            BufferMemory::Domain(allocation) => allocation.bus_address(),
        }
    }

    /// Historical spelling of the device address. This need not be physical
    /// RAM and must never be converted into a CPU pointer; use `as_ptr`.
    pub fn physical(&self) -> u64 {
        self.bus_address()
    }

    pub fn len(&self) -> usize {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    pub fn as_ptr(&self) -> *mut u8 {
        match &self.memory {
            BufferMemory::Identity(address) => *address as *mut u8,
            BufferMemory::Domain(allocation) => allocation.cpu_address(self.bytes),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the allocator keeps this exclusive CPU mapping for this buffer.
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
    /// This checks both the complete word's bounds and its alignment.
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

/// Zeroed heap memory a test fixture hands out front to back, aligned to
/// [`TestRegion::ALIGN`] so that whether an aligned allocation fits never
/// depends on where the heap placed the region. Freed on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct TestRegion {
    layout: core::alloc::Layout,
    start: *mut u8,
    allocator: RegionAllocator,
}

#[cfg(any(test, feature = "test-support"))]
impl TestRegion {
    /// The largest alignment a driver requests: a 64 KiB transfer buffer.
    pub const ALIGN: usize = 64 * 1024;

    pub fn new(bytes: usize) -> Self {
        assert_ne!(bytes, 0, "an empty test DMA region");
        let layout = core::alloc::Layout::from_size_align(bytes, Self::ALIGN)
            .expect("test DMA region layout");
        // SAFETY: the layout has a non-zero size.
        let start = unsafe { alloc::alloc::alloc_zeroed(layout) };
        assert!(!start.is_null(), "test DMA region allocation");
        let base = start as u64;
        // SAFETY: the region owns this allocation until it drops, and test
        // peers reach it at the CPU's address.
        let allocator = unsafe { RegionAllocator::new(base..base + bytes as u64) };
        Self {
            layout,
            start,
            allocator,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl core::ops::Deref for TestRegion {
    type Target = RegionAllocator;
    fn deref(&self) -> &RegionAllocator {
        &self.allocator
    }
}

#[cfg(any(test, feature = "test-support"))]
impl core::ops::DerefMut for TestRegion {
    fn deref_mut(&mut self) -> &mut RegionAllocator {
        &mut self.allocator
    }
}

#[cfg(any(test, feature = "test-support"))]
impl DmaAllocator for TestRegion {
    fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
        self.allocator.allocate(bytes, align)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for TestRegion {
    fn drop(&mut self) {
        // SAFETY: `start` came from `alloc_zeroed` with this layout.
        unsafe { alloc::alloc::dealloc(self.start, self.layout) }
    }
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
            memory: BufferMemory::Identity(start),
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
            memory: BufferMemory::Identity(backing.as_mut_ptr() as u64),
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
    fn invalid_word_ranges_and_alignment_refuse_before_access() {
        let mut backing = [0xa5a5_a5a5_a5a5_a5a5u64; 4];
        let original = backing;
        let mut buffer = DmaBuffer {
            memory: BufferMemory::Identity(backing.as_mut_ptr() as u64),
            bytes: size_of_val(&backing),
        };
        for offset in [1, 29, 32, usize::MAX - 1, usize::MAX] {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || buffer.read::<u32>(offset)
                ))
                .is_err()
            );
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    buffer.write(offset, 0u32)
                }))
                .is_err()
            );
        }
        // Aligned offsets do not repair an allocator's unaligned base.
        let unaligned = DmaBuffer {
            memory: BufferMemory::Identity(buffer.physical() + 1),
            bytes: buffer.len() - 1,
        };
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unaligned.read::<u32>(0)))
                .is_err()
        );
        assert_eq!(backing, original);
    }
}
