// SPDX-License-Identifier: GPL-2.0-only
//! HDA register encodings from Linux include/sound/hda_register.h.
use super::super::Error;
use super::{Config, ResetPolicy};
use crate::bus::mmio::Mmio;

pub(super) const GCAP: usize = 0x00;
pub(super) const VMIN: usize = 0x02;
pub(super) const VMAJ: usize = 0x03;
pub(super) const OUTPAY: usize = 0x04;
pub(super) const INPAY: usize = 0x06;
pub(super) const OUTSTRMPAY: usize = 0x18;
pub(super) const INSTRMPAY: usize = 0x1a;
pub(super) const GCTL: usize = 0x08;
pub(super) const WAKEEN: usize = 0x0c;
pub(super) const STATESTS: usize = 0x0e;
pub(super) const INTCTL: usize = 0x20;
pub(super) const CORBLBASE: usize = 0x40;
pub(super) const CORBUBASE: usize = 0x44;
pub(super) const CORBWP: usize = 0x48;
pub(super) const CORBRP: usize = 0x4a;
pub(super) const CORBCTL: usize = 0x4c;
pub(super) const CORBSTS: usize = 0x4d;
pub(super) const CORBSIZE: usize = 0x4e;
pub(super) const RIRBLBASE: usize = 0x50;
pub(super) const RIRBUBASE: usize = 0x54;
pub(super) const RIRBWP: usize = 0x58;
pub(super) const RINTCNT: usize = 0x5a;
pub(super) const RIRBCTL: usize = 0x5c;
pub(super) const RIRBSTS: usize = 0x5d;
pub(super) const RIRBSIZE: usize = 0x5e;
pub(super) const DPLBASE: usize = 0x70;
pub(super) const DPUBASE: usize = 0x74;
pub(super) const GCTL_RESET: u32 = 1;
pub(super) const GCTL_UNSOL: u32 = 1 << 8;
pub(super) const POINTER_RESET: u16 = 1 << 15;
pub(super) const COMMAND_RUN: u8 = 1 << 1;
pub(super) const RIRB_RESPONSE_ENABLE: u8 = 1;
pub(super) const RIRB_OVERRUN_ENABLE: u8 = 1 << 2;
pub(super) const RIRB_RUN_STATUS: u8 = COMMAND_RUN | RIRB_RESPONSE_ENABLE | RIRB_OVERRUN_ENABLE;
pub(super) const CORB_MEMORY: u8 = 1;
pub(super) const RIRB_RESPONSE: u8 = 1;
pub(super) const RIRB_OVERRUN: u8 = 1 << 2;
pub(super) const RESPONSE_UNSOL: u32 = 1 << 4;
pub(super) const CODEC_MASK: u16 = 0x7fff;
pub(super) const SD_CTL: usize = 0;
pub(super) const SD_STS: usize = 3;
pub(super) const SD_LPIB: usize = 4;
pub(super) const SD_CBL: usize = 8;
pub(super) const SD_LVI: usize = 0x0c;
pub(super) const SD_FORMAT: usize = 0x12;
pub(super) const SD_BDLPL: usize = 0x18;
pub(super) const SD_BDLPU: usize = 0x1c;
pub(super) const SD_RESET: u8 = 1;
pub(super) const SD_RUN: u8 = 2;
pub(super) const SD_COMPLETE: u8 = 4;
pub(super) const SD_FIFO_ERROR: u8 = 8;
pub(super) const SD_DESC_ERROR: u8 = 16;
pub(super) const SD_STATUS: u8 = SD_COMPLETE | SD_FIFO_ERROR | SD_DESC_ERROR;

pub(super) fn stream_base(index: u8) -> usize {
    0x80 + usize::from(index) * 0x20
}

/// Native access widths matter: SD_CTL occupies three bytes and the fourth
/// byte is W1C status. Never implement byte writes through a dword RMW.
pub trait Registers {
    /// Bytes actually mapped by this register implementation. The conventional
    /// contract already requires 0x440; extended capabilities need exact bounds.
    fn region_bytes(&self) -> usize {
        0x440
    }
    /// Generic mappings cannot perform an identity-required native PCI reset.
    fn validate_config(&self, config: &Config) -> Result<(), Error> {
        if config.reset_policy != ResetPolicy::Generic {
            return Err(Error::InvalidConfiguration);
        }
        Ok(())
    }
    fn reset_clock_gate(&mut self, _enabled: bool) -> Result<(), Error> {
        Err(Error::InvalidConfiguration)
    }
    fn read8(&mut self, offset: usize) -> u8;
    fn read16(&mut self, offset: usize) -> u16;
    fn read32(&mut self, offset: usize) -> u32;
    fn write8(&mut self, offset: usize, value: u8);
    fn write16(&mut self, offset: usize, value: u16);
    fn write32(&mut self, offset: usize, value: u32);
}

pub struct MmioRegisters {
    mmio: Mmio,
    bytes: usize,
}

impl MmioRegisters {
    /// # Safety
    /// `base..base+bytes` must be one exclusively owned, identity-mapped,
    /// uncached standard HDA BAR0. PCI D0, memory decode, bus mastering, DMA
    /// coherency/snoop, clocks and any vendor/DSP ownership setup are the
    /// caller's responsibility. Firmware/AML/SMM/other CPUs must not drive it.
    /// Keep the mapping alive until controller shutdown succeeds.
    pub unsafe fn claim(base: u64, bytes: u64) -> Result<Self, Error> {
        if base == 0 || base & 0x7f != 0 || bytes < 0x440 || base.checked_add(bytes).is_none() {
            return Err(Error::InvalidConfiguration);
        }
        let bytes = usize::try_from(bytes).map_err(|_| Error::InvalidConfiguration)?;
        Ok(Self {
            bytes,
            // SAFETY: covered by this function's own safety contract.
            mmio: unsafe { Mmio::new(base) },
        })
    }
}

impl Registers for MmioRegisters {
    fn region_bytes(&self) -> usize {
        self.bytes
    }
    fn read8(&mut self, offset: usize) -> u8 {
        self.mmio.read8(offset)
    }
    fn read16(&mut self, offset: usize) -> u16 {
        self.mmio.read16(offset)
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.mmio.read32(offset)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.mmio.write8(offset, value);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.mmio.write16(offset, value);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.mmio.write32(offset, value);
    }
}
