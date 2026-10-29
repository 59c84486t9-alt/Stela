// SPDX-License-Identifier: GPL-2.0-only
//! Original UC link mapping and platform grants, kept together.
use super::{IoError, Layout, Registers};
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};

pub struct NativeRegisters<P> {
    mapping: Mapping,
    platform: P,
    layout: Layout,
    bytes: usize,
}
impl<P: 'static> NativeRegisters<P> {
    /// # Safety
    /// `platform` keeps this exact Cadence link's original audio/DSP/SHIM
    /// device, mapping reservation, enabled frame/reference clocks,
    /// power/reset/pins, firmware arbitration and command/IRQ/work exclusion.
    /// Initialization/frame shape is acknowledged and no clock-stop/reset or
    /// deferred user can intervene. `layout` is observed from that same owner.
    /// Leaking this object must keep every grant, not its description.
    pub unsafe fn claim(
        mapping: Mapping,
        platform: P,
        layout: Layout,
    ) -> Result<Self, (IoError, Mapping, P)> {
        let bytes = mapping.bytes().unwrap_or(0);
        if bytes < layout.register_bytes()
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
            layout,
            bytes,
        })
    }
    /// # Safety
    /// The original controller released and all parent frame/stream/DMA/IRQ/
    /// work users and posted MMIO are stopped/drained. No extracted pointer
    /// remains usable. Failed unmap keeps exact remaining original owners.
    pub unsafe fn retire(mut self) -> Result<P, Self> {
        // SAFETY: original parent producer proves complete users' retirement.
        if unsafe { self.mapping.retire() }.is_err() {
            return Err(self);
        }
        Ok(self.platform)
    }
}
// SAFETY: claim binds original link/platform lifetime to its complete
// bounded aligned UC register aperture; volatile accesses preserve DWORD width.
unsafe impl<P: 'static> Registers for NativeRegisters<P> {
    fn layout(&self) -> Layout {
        self.layout
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
