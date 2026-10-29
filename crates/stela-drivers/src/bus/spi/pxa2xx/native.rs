// SPDX-License-Identifier: GPL-2.0-only
//! Original native UC mapping and platform/device resource retention.
use super::{Description, IoError, Registers};
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};

pub struct NativeRegisters<P> {
    mapping: Mapping,
    platform: P,
    description: Description,
    bytes: usize,
}
impl<P: 'static> NativeRegisters<P> {
    /// # Safety
    /// `platform` keeps the original unique physical LPSS SSP PCI/ACPI device,
    /// clock/power/reset epoch, board pins and native CS/firmware arbitration.
    /// `mapping` is its complete exclusive register resource. Reset/remap
    /// and the enabled SSP input clock have been established by that real owner;
    /// Description is observed from those same resources, not guessed from IDs.
    /// Prior DMA, IRQ and deferred users are stopped/drained and cannot restart.
    /// No other owner can reset, revoke or relocate this epoch; deliberate leak
    /// keeps all grants. A short-lived external guard is insufficient.
    pub unsafe fn claim(
        mapping: Mapping,
        platform: P,
        description: Description,
    ) -> Result<Self, (IoError, Mapping, P)> {
        let bytes = mapping.bytes().unwrap_or(0);
        if bytes < description.profile.register_bytes()
            || mapping.attribute() != Ok(CacheAttribute::Uncached)
            || mapping.protection() != Ok(Protection::ReadWrite)
            || !mapping
                .address(0, 4)
                .is_ok_and(|p| p.as_ptr() as usize & 3 == 0)
        {
            return Err((IoError, mapping, platform));
        }
        Ok(Self {
            mapping,
            platform,
            description,
            bytes,
        })
    }
    /// # Safety
    /// The original Controller successfully released and all register users,
    /// callbacks and posted writes are drained. No extracted pointer may be
    /// accessed again. Failure returns this exact remaining mapping/platform
    /// owner for acknowledged retry; no inferred native unmap completion.
    pub unsafe fn retire(mut self) -> Result<P, Self> {
        // SAFETY: caller supplies the original successful controller/user drain.
        if unsafe { self.mapping.retire() }.is_err() {
            return Err(self);
        }
        Ok(self.platform)
    }
}
// SAFETY: claim binds immutable device/clock/pin ownership to its
// original aligned UC mapping. Every DWORD checks bounds and ordered volatility;
// failed accesses may follow effects. The controller serializes all users.
unsafe impl<P: 'static> Registers for NativeRegisters<P> {
    fn description(&self) -> Description {
        self.description
    }
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        self.mapping.read32(offset).map_err(|_| IoError)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        self.mapping.write32(offset, value).map_err(|_| IoError)
    }
}
