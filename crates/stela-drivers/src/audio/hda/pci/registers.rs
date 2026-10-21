// SPDX-License-Identifier: GPL-2.0-only
//! Native PCI reset clock bracket adapted from Linux intel.c::hda_intel_init_chip
//! at a804c5742bff224d4cb4d25dd383554d598be32b. PCI/MMIO association is Stela policy.
//! Copyright(c) 2004 Intel Corporation
//! Copyright (c) 2004 Takashi Iwai <tiwai@suse.de>
//!                     PeiSen Hou <pshou@realtek.com.tw>
use super::{
    AttachError, CGCTL, CGCTL_MISCBDCGE, CLASS, Config, Identity, MmioRegisters, PCI_BAR0,
    PCI_CLASS, PCI_ID, Prepared, Registers, ResetPolicy, bar_matches,
};
use crate::{
    audio::Error,
    bus::pci::{Address, ConfigSpace, Function},
};

/// One prepared PCI function retained exclusively throughout MMIO/reset use.
/// The mutable borrow prevents another typed owner from changing PCI state.
pub struct PciRegisters<'a, R, C> {
    inner: R,
    function: &'a mut Function<C>,
    identity: Identity,
    address: Address,
    base: u64,
}

fn associated<C: ConfigSpace>(
    function: &mut Function<C>,
    address: Address,
    identity: Identity,
    base: u64,
) -> bool {
    if function.address != address {
        return false;
    }
    let config = function.config();
    let id = config.read32(PCI_ID);
    let class = config.read32(PCI_CLASS);
    id == u32::from(identity.vendor) | (u32::from(identity.device) << 16)
        && [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8] == CLASS
        && bar_matches(config, base, config.read32(PCI_BAR0) & 4 != 0)
}

impl Prepared {
    /// Associate a prepared function with an exclusively owned BAR implementation.
    ///
    /// # Safety
    /// `inner` must access exactly this prepared BAR with native widths, and its
    /// mapping/DMA lifetime and exclusive platform prerequisites must hold until
    /// shutdown succeeds. PCI resources/power stay unchanged.
    pub unsafe fn bind_registers<'a, R: Registers, C: ConfigSpace>(
        self,
        function: &'a mut Function<C>,
        inner: R,
    ) -> Result<PciRegisters<'a, R, C>, AttachError> {
        if !associated(function, self.address, self.identity, self.base) {
            return Err(AttachError::IdentityChanged);
        }
        Ok(PciRegisters {
            inner,
            function,
            identity: self.identity,
            address: self.address,
            base: self.base,
        })
    }

    /// Claim native MMIO while retaining the exact prepared PCI function.
    ///
    /// # Safety
    /// The BAR must be identity mapped uncached with the lifetime/exclusive
    /// platform/DMA prerequisites of `claim_mmio` and `bind_registers`.
    pub unsafe fn claim_with_pci<'a, C: ConfigSpace>(
        self,
        function: &'a mut Function<C>,
    ) -> Result<PciRegisters<'a, MmioRegisters, C>, AttachError> {
        let inner = unsafe { MmioRegisters::claim(self.base, self.bytes) }
            .map_err(|_| AttachError::InvalidBar)?;
        unsafe { self.bind_registers(function, inner) }
    }
}

impl<R: Registers, C: ConfigSpace> Registers for PciRegisters<'_, R, C> {
    fn validate_config(&self, config: &Config) -> Result<(), Error> {
        let required = self.identity;
        if config.reset_policy != required.reset_policy
            || config.corb_reset != required.corb_reset
            || config.position_policy != required.position_policy
            || (required.probe_policy != super::ProbePolicy::Once
                && config.probe_policy != required.probe_policy)
            || config.stream_tag_policy != required.stream_tag_policy
            || config.dma_address_bits > required.dma_address_bits
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(())
    }
    fn reset_clock_gate(&mut self, enabled: bool) -> Result<(), Error> {
        if self.identity.reset_policy != ResetPolicy::IntelClockGate {
            return Err(Error::InvalidConfiguration);
        }
        let fault = Error::PciResetControl { offset: CGCTL };
        if !associated(self.function, self.address, self.identity, self.base) {
            return Err(fault);
        }
        let config = self.function.config();
        let previous = config.read32(CGCTL);
        if previous == u32::MAX {
            return Err(fault);
        }
        let value = if enabled {
            previous | CGCTL_MISCBDCGE
        } else {
            previous & !CGCTL_MISCBDCGE
        };
        config.write32(CGCTL, value);
        let observed = config.read32(CGCTL);
        if observed == u32::MAX || observed & CGCTL_MISCBDCGE != value & CGCTL_MISCBDCGE {
            return Err(fault);
        }
        Ok(())
    }
    fn read8(&mut self, offset: usize) -> u8 {
        self.inner.read8(offset)
    }
    fn read16(&mut self, offset: usize) -> u16 {
        self.inner.read16(offset)
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.inner.read32(offset)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.inner.write8(offset, value)
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.inner.write16(offset, value)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.inner.write32(offset, value)
    }
}
