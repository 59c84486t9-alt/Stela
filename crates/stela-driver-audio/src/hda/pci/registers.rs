// SPDX-License-Identifier: GPL-2.0-only
//! Native PCI reset clock bracket adapted from Linux intel.c::hda_intel_init_chip
//! at a804c5742bff224d4cb4d25dd383554d598be32b. PCI/MMIO association is Stela policy.
//! Copyright(c) 2004 Intel Corporation
//! Copyright (c) 2004 Takashi Iwai <tiwai@suse.de>
//!                     PeiSen Hou <pshou@realtek.com.tw>
use super::{
    AttachError, CGCTL, CGCTL_MISCBDCGE, CLASS, Config, Identity, MmioRegisters, Prepared,
    Registers, ResetPolicy, bar_matches,
};
use crate::bus::pci::regs;
use crate::{
    Error,
    bus::pci::{Address, ConfigSpace, Function},
};
use alloc::boxed::Box;
use core::ops::DerefMut;

/// One prepared PCI function kept exclusively throughout MMIO/reset use.
/// Storage is either a unique mutable borrow or the actual owning Box; both
/// use the same association and native-width access implementation.
pub struct PciRegisters<R, F> {
    pub(super) inner: R,
    pub(super) function: F,
    pub(super) identity: Identity,
    pub(super) address: Address,
    pub(super) base: u64,
    pub(super) bytes: usize,
    pub(super) suspended: Option<super::power::Snapshot>,
}

pub(super) fn associated<C: ConfigSpace>(
    function: &mut Function<C>,
    address: Address,
    identity: Identity,
    base: u64,
) -> Result<bool, crate::bus::pci::ConfigError> {
    if function.address != address {
        return Ok(false);
    }
    let config = function.config();
    let id = config.read32(regs::VENDOR_ID)?;
    let class = config.read32(regs::CLASS_REVISION)?;
    Ok(
        id == u32::from(identity.vendor) | (u32::from(identity.device) << 16)
            && [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8] == CLASS
            && bar_matches(config, base, config.read32(regs::BASE_ADDRESS_0)? & 4 != 0)?,
    )
}

impl Prepared {
    /// Associate a prepared function with an exclusively owned BAR implementation.
    ///
    /// # Safety
    /// `inner` must access exactly this prepared BAR with native widths, and its
    /// mapping/DMA lifetime and exclusive platform prerequisites must hold until
    /// shutdown succeeds. PCI resources/power stay unchanged.
    pub unsafe fn bind_registers<R: Registers, C: ConfigSpace>(
        self,
        function: &mut Function<C>,
        inner: R,
    ) -> Result<PciRegisters<R, &mut Function<C>>, AttachError> {
        if inner.region_bytes()
            > usize::try_from(self.bytes).map_err(|_| AttachError::InvalidBar)?
            || inner.region_bytes() < 0x440
        {
            return Err(AttachError::InvalidBar);
        }
        if !associated(function, self.address, self.identity, self.base)? {
            return Err(AttachError::IdentityChanged);
        }
        Ok(PciRegisters {
            inner,
            function,
            identity: self.identity,
            address: self.address,
            base: self.base,
            bytes: self.bytes as usize,
            suspended: None,
        })
    }

    /// Claim native MMIO while keeping the exact prepared PCI function.
    ///
    /// # Safety
    /// The BAR must be identity mapped uncached with the lifetime/exclusive
    /// platform/DMA prerequisites of `claim_mmio` and `bind_registers`.
    pub unsafe fn claim_with_pci<C: ConfigSpace>(
        self,
        function: &mut Function<C>,
    ) -> Result<PciRegisters<MmioRegisters, &mut Function<C>>, AttachError> {
        // SAFETY: the prepared range is the caller's exclusively owned,
        // identity-mapped uncached BAR. Its mapping and PCI power/decode remain
        // stable for the lifetime of the returned adapter.
        let inner = unsafe { MmioRegisters::claim(self.base, self.bytes) }
            .map_err(|_| AttachError::InvalidBar)?;
        // SAFETY: inner was just claimed from this prepared BAR. The caller
        // keeps its mapping/DMA lifetime and exclusive platform ownership;
        // bind_registers rechecks the function identity and BAR association.
        unsafe { self.bind_registers(function, inner) }
    }
}

/// A rejected owned association retains its original function and BAR provider.
pub struct BindingFailure<R, F> {
    pub error: AttachError,
    _owner: BindingOwner<R, F>,
}
struct BindingOwner<R, F>(Option<(F, R)>);
impl<R, F> Drop for BindingOwner<R, F> {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
/// An owning association returns its exact original function/BAR on refusal.
pub type OwnedBindingResult<R, C> =
    Result<PciRegisters<R, Box<Function<C>>>, BindingFailure<R, Box<Function<C>>>>;

impl Prepared {
    /// Bind the actual function owner without borrowing a leaked/self-referential
    /// function. Failure and unwind retain both original owners.
    ///
    /// # Safety
    /// Same PCI/BAR association and exclusion as bind_registers. All inherited
    /// engines and original IRQ/work/root users are retired before this owning
    /// post-bind association. No competing power/reset/config writer exists.
    pub unsafe fn bind_owned_registers<R: Registers, C: ConfigSpace>(
        self,
        function: Box<Function<C>>,
        inner: R,
    ) -> OwnedBindingResult<R, C> {
        let mut owner = BindingOwner(Some((function, inner)));
        let result = (|| {
            let (function, inner) = owner.0.as_mut().unwrap();
            if inner.region_bytes()
                > usize::try_from(self.bytes).map_err(|_| AttachError::InvalidBar)?
                || inner.region_bytes() < 0x440
            {
                return Err(AttachError::InvalidBar);
            }
            if !associated(function, self.address, self.identity, self.base)? {
                return Err(AttachError::IdentityChanged);
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err(BindingFailure {
                error,
                _owner: owner,
            });
        }
        let (function, inner) = owner.0.take().unwrap();
        Ok(PciRegisters {
            inner,
            function,
            identity: self.identity,
            address: self.address,
            base: self.base,
            bytes: self.bytes as usize,
            suspended: None,
        })
    }
}
impl<R, F> PciRegisters<R, F> {
    /// Return only PCI association metadata and its BAR provider. This grants
    /// no engine/IRQ/root completion; the function owner is returned explicitly.
    pub fn into_parts(self) -> (Prepared, F, R) {
        (
            Prepared {
                identity: self.identity,
                address: self.address,
                base: self.base,
                bytes: self.bytes as u64,
            },
            self.function,
            self.inner,
        )
    }
}
impl<R, C: ConfigSpace, F: DerefMut<Target = Function<C>>> PciRegisters<R, F> {
    /// Explicit BME transition for the paired function. A stopped controller,
    /// source/work exclusion and actual requester Attachment are prerequisites
    /// for enabling; clearing is not engine/payload completion.
    ///
    /// # Safety
    /// Caller keeps those exact original owners and supplies the stated stop
    /// and DMA-domain prerequisites; no independent power/config writer exists.
    pub unsafe fn set_bus_master(&mut self, enabled: bool) -> Result<(), AttachError> {
        if self.suspended.is_some()
            || !associated(&mut self.function, self.address, self.identity, self.base)?
        {
            return Err(AttachError::IdentityChanged);
        }
        let config = self.function.config();
        let old = config.read16(regs::COMMAND)?;
        if old == u16::MAX
            || old & (regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE)
                != regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE
        {
            return Err(AttachError::ConfigurationRejected);
        }
        let wanted = if enabled {
            old | regs::COMMAND_MASTER
        } else {
            old & !regs::COMMAND_MASTER
        };
        config.write16(regs::COMMAND, wanted)?;
        if config.read16(regs::COMMAND)? != wanted {
            return Err(AttachError::ConfigurationRejected);
        }
        Ok(())
    }
}

impl<R, F> PciRegisters<R, F> {
    /// Mandatory identity-selected configuration for this function.
    pub fn config(&self) -> Config {
        self.identity.config()
    }
}

impl<R: Registers, C: ConfigSpace, F: DerefMut<Target = Function<C>>> Registers
    for PciRegisters<R, F>
{
    fn region_bytes(&self) -> usize {
        self.inner.region_bytes().min(self.bytes)
    }
    fn validate_config(&self, config: &Config) -> Result<(), Error> {
        if self.suspended.is_some() {
            return Err(Error::Shutdown);
        }
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
    fn codec_pci_subsystem(&mut self) -> Result<Option<u32>, Error> {
        if self.suspended.is_some()
            || !associated(&mut self.function, self.address, self.identity, self.base)?
        {
            return Err(Error::InvalidConfiguration);
        }
        let subsystem = self.function.config().read32(regs::SUBSYSTEM_VENDOR_ID)?;
        if subsystem == u32::MAX {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Some(subsystem))
    }
    fn reset_clock_gate(&mut self, enabled: bool) -> Result<(), Error> {
        if self.suspended.is_some() || self.identity.reset_policy != ResetPolicy::IntelClockGate {
            return Err(Error::InvalidConfiguration);
        }
        let fault = Error::PciResetControl { offset: CGCTL };
        if !associated(&mut self.function, self.address, self.identity, self.base)? {
            return Err(fault);
        }
        let config = self.function.config();
        let previous = config.read32(CGCTL)?;
        if previous == u32::MAX {
            return Err(fault);
        }
        let value = if enabled {
            previous | CGCTL_MISCBDCGE
        } else {
            previous & !CGCTL_MISCBDCGE
        };
        config.write32(CGCTL, value)?;
        let observed = config.read32(CGCTL)?;
        if observed == u32::MAX || observed & CGCTL_MISCBDCGE != value & CGCTL_MISCBDCGE {
            return Err(fault);
        }
        Ok(())
    }
    fn read8(&mut self, offset: usize) -> u8 {
        if self.suspended.is_some() {
            u8::MAX
        } else {
            self.inner.read8(offset)
        }
    }
    fn read16(&mut self, offset: usize) -> u16 {
        if self.suspended.is_some() {
            u16::MAX
        } else {
            self.inner.read16(offset)
        }
    }
    fn read32(&mut self, offset: usize) -> u32 {
        if self.suspended.is_some() {
            u32::MAX
        } else {
            self.inner.read32(offset)
        }
    }
    fn write8(&mut self, offset: usize, value: u8) {
        if self.suspended.is_none() {
            self.inner.write8(offset, value)
        }
    }
    fn write16(&mut self, offset: usize, value: u16) {
        if self.suspended.is_none() {
            self.inner.write16(offset, value)
        }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        if self.suspended.is_none() {
            self.inner.write32(offset, value)
        }
    }
}

impl<R, F: core::ops::DerefMut<Target = Function<crate::bus::pci::owned::OwnedConfig>>>
    PciRegisters<R, F>
{
    /// Read-only epoch retention. This exposes no config or controller writer
    /// and correctly prevents actual mapping retirement while held.
    pub fn retain_config_epoch(
        &mut self,
    ) -> Result<crate::bus::pci::owned::ConfigRetention, crate::bus::mmio::owned::Error> {
        self.function.config().retain_epoch()
    }
}
