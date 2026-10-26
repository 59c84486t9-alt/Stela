// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
//! Original ACP mapping and actual retained SoundWire sublink grants.
use super::{IoError, Manager, Registers};
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};

pub struct NativeRegisters<P> {
    mapping: Mapping,
    platform: P,
    manager: Manager,
    bytes: usize,
}
impl<P: 'static> NativeRegisters<P> {
    /// # Safety
    /// `platform` is the actual original ACP parent/sublink grant. It retains
    /// the original device/mapping reservation, active initialized frame/link
    /// clocks, pins, reset/power and firmware/IRQ/work/sibling exclusion for
    /// this observed manager. Leaking it must retain every real resource.
    #[allow(clippy::type_complexity)]
    pub unsafe fn claim(
        mapping: Mapping,
        platform: P,
        manager: Manager,
    ) -> Result<Self, (IoError, Mapping, P)> {
        let bytes = mapping.bytes().unwrap_or(0);
        if bytes < manager.register_bytes()
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
            manager,
            bytes,
        })
    }
    /// # Safety
    /// Original command owner released and every parent/sibling stream, DMA,
    /// IRQ, wake/work and posted access is stopped and drained. No pointer may
    /// survive successful retirement. Failed unmap retains remaining owners.
    pub unsafe fn retire(mut self) -> Result<P, Self> {
        // SAFETY: caller retains/proves all original users' full retirement.
        if unsafe { self.mapping.retire() }.is_err() {
            return Err(self);
        }
        Ok(self.platform)
    }
}
// SAFETY: claim retains original manager grants and bounded aligned UC memory;
// checked address formation and volatile accesses preserve exact DWORD width.
unsafe impl<P: 'static> Registers for NativeRegisters<P> {
    fn manager(&self) -> Manager {
        self.manager
    }
    fn bytes(&self) -> usize {
        self.bytes
    }
    fn read32(&mut self, at: usize) -> Result<u32, IoError> {
        if at & 3 != 0 {
            return Err(IoError);
        }
        let ptr = self.mapping.address(at, 4).map_err(|_| IoError)?;
        // SAFETY: aligned checked live original manager DWORD.
        Ok(u32::from_le(unsafe {
            ptr.as_ptr().cast::<u32>().read_volatile()
        }))
    }
    fn write32(&mut self, at: usize, value: u32) -> Result<(), IoError> {
        if at & 3 != 0 {
            return Err(IoError);
        }
        let ptr = self.mapping.address(at, 4).map_err(|_| IoError)?;
        // SAFETY: aligned checked live original manager DWORD.
        unsafe { ptr.as_ptr().cast::<u32>().write_volatile(value.to_le()) };
        Ok(())
    }
}
