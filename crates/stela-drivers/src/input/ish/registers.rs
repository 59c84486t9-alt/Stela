// SPDX-License-Identifier: GPL-2.0-only
//! Exact native UC accesses; the IRQ callback shares only defined fixed stores.
use super::{Error, Result};
use crate::bus::mmio::owned::{CacheAttribute, Mapping, PhysicalSpan, Protection};

pub(super) const PIMR: u32 = 0x08;
pub(super) const PISR: u32 = 0x0c;
pub(super) const FWSTS: u32 = 0x34;
pub(super) const HOST_COMM: u32 = 0x38;
pub(super) const H2I: u32 = 0x48;
pub(super) const I2H: u32 = 0x54;
pub(super) const RX: u32 = 0x60;
pub(super) const TX: u32 = 0xe0;
pub(super) const RMP2: u32 = 0x368;
pub(super) const BUSY: u32 = 1 << 31;
pub(super) const IN_DMA: u32 = 0xf << 16;
pub(super) const IRQ_ENABLE: u32 = 1;
pub(super) const BUSY_CLEAR: u32 = 1 << 8;

/// Actual retained native BAR0, or an explicit register peer used by controls.
/// # Safety
/// Span and accesses belong to the same exclusively reserved native endpoint,
/// reset/resource/root epoch as configuration and the actual isolated domain.
/// Reads/writes are exact bounded native DWORD effects. No raw alias or firmware
/// writer can revoke this owner. The hard IRQ callback may read PISR/I2H and
/// write only the immutable admitted PIMR mask; process owns every other effect.
/// Shared fixed-word PIMR stores preserve the same immutable unrelated bits.
/// No access, including fault handling, releases a mapping in IRQ context.
pub unsafe trait Registers: Send + Sync + 'static {
    fn span(&self) -> PhysicalSpan;
    fn read32(&self, offset: u32) -> Result<u32>;
    fn write32(&self, offset: u32, value: u32) -> Result<()>;
}

pub struct MappedRegisters {
    mapping: Mapping,
    span: PhysicalSpan,
}
impl MappedRegisters {
    /// # Safety
    /// This is the actual exclusive complete BAR0 resource for the retained PCI
    /// endpoint. The mapping and its real producer retain power, root/resource
    /// assignment and reset/firmware exclusion, with no escaped aliases/views.
    /// Metadata equality cannot establish those device ownership facts.
    pub unsafe fn new(mapping: Mapping) -> core::result::Result<Self, (Error, Mapping)> {
        let checked = (|| {
            let span = mapping.physical_span().map_err(Error::Mapping)?;
            if span.bytes() < 0x400
                || mapping.attribute().map_err(Error::Mapping)? != CacheAttribute::Uncached
                || mapping.protection().map_err(Error::Mapping)? != Protection::ReadWrite
                || !(mapping.address(0, 4).map_err(Error::Mapping)?.as_ptr() as usize)
                    .is_multiple_of(4)
            {
                return Err(Error::Requirement("complete aligned native UC/RW ISH BAR0"));
            }
            Ok(span)
        })();
        match checked {
            Ok(span) => Ok(Self { mapping, span }),
            Err(error) => Err((error, mapping)),
        }
    }
}
// SAFETY: original mapping retains the real native resource; every access
// rechecks live mapping state, alignment and complete bounds. No cached pointer.
unsafe impl Registers for MappedRegisters {
    fn span(&self) -> PhysicalSpan {
        self.span
    }
    fn read32(&self, offset: u32) -> Result<u32> {
        if !offset.is_multiple_of(4) || offset >= 0x400 {
            return Err(Error::Access(offset));
        }
        let p = self
            .mapping
            .address(offset as usize, 4)
            .map_err(Error::Mapping)?;
        // SAFETY: bounded aligned live UC DWORD, with defined register ownership.
        Ok(u32::from_le(unsafe {
            p.as_ptr().cast::<u32>().read_volatile()
        }))
    }
    fn write32(&self, offset: u32, value: u32) -> Result<()> {
        if !offset.is_multiple_of(4) || offset >= 0x400 {
            return Err(Error::Access(offset));
        }
        let p = self
            .mapping
            .address(offset as usize, 4)
            .map_err(Error::Mapping)?;
        // SAFETY: same retained exact-width access; no neighboring W1C replay.
        unsafe { p.as_ptr().cast::<u32>().write_volatile(value.to_le()) };
        Ok(())
    }
}

pub(super) fn read<R: Registers>(r: &R, at: u32) -> Result<u32> {
    let v = r.read32(at)?;
    if v == u32::MAX {
        Err(Error::Removed)
    } else {
        Ok(v)
    }
}
pub(super) fn store<R: Registers>(r: &R, at: u32, value: u32) -> Result<()> {
    r.write32(at, value)?;
    if read(r, at)? != value {
        Err(Error::Readback(at))
    } else {
        Ok(())
    }
}
