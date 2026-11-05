//! Actual retained UC BAR0 and original configuration mapping permission.
use super::super::ring::{CAPABILITIES, Registers};
use super::Error;
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{
        ConfigSpace, Function,
        owned::{ConfigRetention, OwnedConfig},
    },
};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{AtomicBool, Ordering},
};

/// Every register access uses the actual owned mapping/context check. No raw
/// pointer is lent, and default Drop retains the original mapping/config pin.
pub struct MappedRegisters {
    mapping: ManuallyDrop<Mapping>,
    retained: ManuallyDrop<ConfigRetention>,
    failed: AtomicBool,
    bytes: usize,
    bar_words: [u32; 6],
}
impl MappedRegisters {
    pub(super) fn new(mapping: Mapping, retained: ConfigRetention, bar_words: [u32; 6]) -> Self {
        Self {
            bytes: mapping.bytes().unwrap_or(0),
            mapping: ManuallyDrop::new(mapping),
            retained: ManuallyDrop::new(retained),
            failed: AtomicBool::new(false),
            bar_words,
        }
    }
    /// Observe the same actual original config/BAR/provider, without granting
    /// engine, payload or IRQ completion.
    pub fn check(&self, function: &mut Function<OwnedConfig>) -> Result<(), Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Registers);
        }
        self.mapping.check_current().map_err(Error::Mapping)?;
        if self.mapping.attribute().map_err(Error::Mapping)? != CacheAttribute::Uncached
            || self.mapping.protection().map_err(Error::Mapping)? != Protection::ReadWrite
            || self.bytes < 0x39948
        {
            return Err(Error::Registers);
        }
        if !function
            .config()
            .matches_retention(&self.retained)
            .map_err(Error::Mapping)?
            || !self
                .retained
                .shares_authority(&self.mapping)
                .map_err(Error::Mapping)?
        {
            return Err(Error::ForeignOwner);
        }
        let command = function.config().read16(4)?;
        if command == u16::MAX || command & 2 == 0 {
            return Err(Error::Registers);
        }
        for (index, expected) in self.bar_words.iter().enumerate() {
            if function.config().read32(0x10 + 4 * index as u16)? != *expected {
                return Err(Error::ForeignOwner);
            }
        }
        let caps = self.read32(CAPABILITIES);
        if caps == u32::MAX || caps & 0x3ff == 0 {
            return Err(Error::Registers);
        }
        Ok(())
    }
    pub(super) fn reset_rings(&self) -> Result<(), Error> {
        let caps = self.read32(CAPABILITIES);
        if caps == u32::MAX || caps & 0x3ff == 0 {
            return Err(Error::Registers);
        }
        for hop in 0..(caps & 0x3ff) as usize {
            for base in [0x19800, 0x29800] {
                let options = self.read32(base + hop * 32);
                if options == u32::MAX || options & (1 << 31) != 0 {
                    return Err(Error::Registers);
                }
            }
            for base in [0, 0x8000] {
                // Ring::new requires no inherited hardware-owned index. Reset
                // must actually discard it; we do not zero it to fake readiness.
                if self.read32(base + hop * 16 + 8) != 0 {
                    return Err(Error::Registers);
                }
            }
        }
        Ok(())
    }
}
// SAFETY: Mapping/ConfigRetention pin actual original resource/platform owners.
// Mapping checks each access context; controller/channel serialize all protocol
// calls. Failure is sticky and represented by the bus-read failure sentinel;
// source operations check a non-sentinel final state before reporting success.
unsafe impl Registers for MappedRegisters {
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn read32(&self, offset: usize) -> u32 {
        if self.failed.load(Ordering::Acquire) {
            return u32::MAX;
        }
        match self.mapping.read32(offset) {
            Ok(value) => value,
            Err(_) => {
                self.failed.store(true, Ordering::Release);
                u32::MAX
            }
        }
    }
    fn write32(&self, offset: usize, value: u32) {
        if !self.failed.load(Ordering::Acquire) && self.mapping.write32(offset, value).is_err() {
            self.failed.store(true, Ordering::Release);
        }
    }
}
