// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
//! Native accesses through the original exclusively owned UC mapping.
use super::{IoError, Profile, Registers};
use crate::bus::mmio::owned::{CacheAttribute, Mapping, Protection};

/// Retains both the real mapping and its original platform/device owner. No
/// numeric MMIO address is admitted. Automatic ACPI resource/power attachment
/// still needs a real producer of the ownership in `claim`'s contract.
pub struct NativeRegisters<P> {
    mapping: Mapping,
    platform: P,
    profile: Profile,
}
impl<P: 'static> NativeRegisters<P> {
    /// # Safety
    /// `platform` is the original unique actual AMDI0061/0062 ACPI controller,
    /// `_CRS` reservation, clock/reset/power and board pin/firmware ownership,
    /// including every single/dual/quad lane described to memory operations.
    /// It retains the entire stopped controller epoch even when leaked. The
    /// supplied mapping covers that exact resource, not another controller or
    /// RAM. No firmware/AML/IRQ/DMA/other CPU accesses it; no reset, relocation,
    /// power removal or pin reuse occurs while retained. `profile` is from that
    /// actual hardware session. The grant must outlive every register access.
    pub unsafe fn claim(
        mapping: Mapping,
        platform: P,
        profile: Profile,
    ) -> Result<Self, (IoError, Mapping, P)> {
        let valid = mapping.bytes().is_ok_and(|bytes| bytes >= 0x80 + 70)
            && mapping.attribute() == Ok(CacheAttribute::Uncached)
            && mapping.protection() == Ok(Protection::ReadWrite)
            && mapping
                .address(0, 4)
                .is_ok_and(|address| address.as_ptr() as usize & 3 == 0);
        if !valid {
            return Err((IoError, mapping, platform));
        }
        Ok(Self {
            mapping,
            platform,
            profile,
        })
    }

    /// # Safety
    /// The original Controller was successfully released, all other accesses
    /// stopped and its last completed opcode/posted-write readbacks drained.
    /// No access may begin through any extracted pointer. Failure returns and
    /// retains this complete native owner; no fabricated unmap acknowledgement.
    pub unsafe fn retire(mut self) -> Result<P, Self> {
        // SAFETY: caller supplies the original controller/user drain above.
        if unsafe { self.mapping.retire() }.is_err() {
            return Err(self);
        }
        Ok(self.platform)
    }
}
// SAFETY: claim retains the original unique platform grant and checked live UC
// mapping; every volatile access checks width/bounds, and failures may follow
// effects. Controller serializes access and deliberately retains faulted owners.
unsafe impl<P: 'static> Registers for NativeRegisters<P> {
    fn profile(&self) -> Profile {
        self.profile
    }
    fn read8(&mut self, offset: usize) -> Result<u8, IoError> {
        let pointer = self.mapping.address(offset, 1).map_err(|_| IoError)?;
        // SAFETY: exclusive live owned UC byte; address checked actual bounds.
        Ok(unsafe { pointer.as_ptr().read_volatile() })
    }
    fn write8(&mut self, offset: usize, value: u8) -> Result<(), IoError> {
        let pointer = self.mapping.address(offset, 1).map_err(|_| IoError)?;
        // SAFETY: exclusive live owned UC byte; address checked actual bounds.
        unsafe { pointer.as_ptr().write_volatile(value) };
        Ok(())
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        self.mapping.read32(offset).map_err(|_| IoError)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        self.mapping.write32(offset, value).map_err(|_| IoError)
    }
}
