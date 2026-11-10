//! Volatile device-register access and owned native physical mappings.
pub mod owned;
use core::ptr::{read_volatile, write_volatile};

/// A device's register window: every access must lie inside it. An offset
/// beyond it panics instead of reaching other memory.
#[derive(Clone, Copy, Debug)]
pub struct Mmio {
    base: usize,
    bytes: usize,
}

impl Mmio {
    /// # Safety
    ///
    /// `base..base + bytes` must address mapped, uncached registers of one
    /// device that nothing else drives.
    pub unsafe fn new(base: u64, bytes: usize) -> Self {
        Self {
            base: base as usize,
            bytes,
        }
    }

    /// The window's size in bytes.
    pub fn len(&self) -> usize {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// The address of the `size`-byte register at `offset`, which must lie
    /// inside the window.
    fn at(&self, offset: usize, size: usize) -> usize {
        assert!(
            offset
                .checked_add(size)
                .is_some_and(|end| end <= self.bytes),
            "MMIO access of {size} bytes at {offset:#x} outside a {:#x}-byte register window",
            self.bytes
        );
        self.base + offset
    }

    pub fn read8(&self, offset: usize) -> u8 {
        // SAFETY: `new`'s contract, for a register `at` checked in the window.
        unsafe { read_volatile(self.at(offset, 1) as *const u8) }
    }

    pub fn write8(&self, offset: usize, value: u8) {
        // SAFETY: as for `read8`.
        unsafe { write_volatile(self.at(offset, 1) as *mut u8, value) }
    }

    pub fn read16(&self, offset: usize) -> u16 {
        // SAFETY: as for `read8`.
        unsafe { read_volatile(self.at(offset, 2) as *const u16) }
    }

    pub fn write16(&self, offset: usize, value: u16) {
        // SAFETY: as for `read8`.
        unsafe { write_volatile(self.at(offset, 2) as *mut u16, value) }
    }

    pub fn read32(&self, offset: usize) -> u32 {
        // SAFETY: as for `read8`.
        unsafe { read_volatile(self.at(offset, 4) as *const u32) }
    }

    pub fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as for `read8`.
        unsafe { write_volatile(self.at(offset, 4) as *mut u32, value) }
    }

    /// A 64-bit register as two 32-bit accesses, low half first, which every
    /// device here accepts.
    pub fn read64(&self, offset: usize) -> u64 {
        u64::from(self.read32(offset)) | u64::from(self.read32(offset + 4)) << 32
    }

    pub fn write64(&self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
}

#[cfg(test)]
mod tests;
