//! Volatile access to identity-mapped, uncached device registers.
use core::ptr::{read_volatile, write_volatile};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Mmio {
    base: usize,
}

impl Mmio {
    /// # Safety
    ///
    /// `base` and every offset used with it must address mapped, uncached
    /// registers of one device that nothing else drives.
    pub(crate) unsafe fn new(base: u64) -> Self {
        Self {
            base: base as usize,
        }
    }

    pub(crate) fn read8(&self, offset: usize) -> u8 {
        // SAFETY: `new`'s contract.
        unsafe { read_volatile((self.base + offset) as *const u8) }
    }

    pub(crate) fn write8(&self, offset: usize, value: u8) {
        // SAFETY: `new`'s contract.
        unsafe { write_volatile((self.base + offset) as *mut u8, value) }
    }

    pub(crate) fn read16(&self, offset: usize) -> u16 {
        // SAFETY: `new`'s contract.
        unsafe { read_volatile((self.base + offset) as *const u16) }
    }

    pub(crate) fn write16(&self, offset: usize, value: u16) {
        // SAFETY: `new`'s contract.
        unsafe { write_volatile((self.base + offset) as *mut u16, value) }
    }

    pub(crate) fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `new`'s contract.
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    pub(crate) fn write32(&self, offset: usize, value: u32) {
        // SAFETY: `new`'s contract.
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// A 64-bit register as two 32-bit accesses, low half first, which every
    /// device here accepts.
    pub(crate) fn read64(&self, offset: usize) -> u64 {
        u64::from(self.read32(offset)) | u64::from(self.read32(offset + 4)) << 32
    }

    pub(crate) fn write64(&self, offset: usize, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
}
