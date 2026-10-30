// SPDX-License-Identifier: GPL-2.0-only
//! Shared direct-PDM adapter over the canonical stopped PCI function and owned UC mapping.
//! AMD identity/register facts: Linux sound/soc/amd/{yc,renoir,ps} at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (C) 2020, 2021, 2022, 2023, 2025 Advanced Micro Devices, Inc. All rights reserved.
use super::{Error, Identity, Profile, Registers, registers::*};
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{
        Address, Bar, ConfigSpace, Function, capability, owned::OwnedConfig,
        requester::StoppedRequester,
    },
};

/// Failure preserves both original native resource owners for retirement or
/// retry. No PCI/MMIO write occurs on attachment rejection.
pub struct AttachFailure {
    pub error: Error,
    pub function: Function<OwnedConfig>,
    pub mapping: Mapping,
}

/// Owns ECAM/configuration and UC/RW BAR0 resource leases. No raw PA or
/// generic physical map is accepted, and no mutable function accessor escapes.
pub struct NativeRegisters<P: Profile> {
    _profile: core::marker::PhantomData<P>,
    pub(crate) function: Function<OwnedConfig>,
    mapping: Mapping,
    address: Address,
    identity: Identity,
    base: u64,
    wide: bool,
    master: Option<bool>,
}
impl<P: Profile> NativeRegisters<P> {
    /// Associate the original stopped owner and a real native BAR0 mapping.
    ///
    /// # Safety
    /// `bar` is this exact function's fully sized/reserved BAR0 in the kept
    /// assignment epoch. The mapping's real ResourceBacking reserves that BAR
    /// for this function (numeric equality alone is insufficient). The original
    /// stopped producer's engine/IRQ/work/firmware exclusion remains in force.
    /// The platform has selected direct ACP ownership and checked WB capture
    /// DMA coherency; attachment does not infer either from PCI or pin mode.
    /// No cloned view/raw pointer or other owner accesses these mappings.
    /// Keep the native owners kept until controller shutdown succeeds.
    pub unsafe fn attach(
        mut requester: StoppedRequester,
        mapping: Mapping,
        bar: Bar,
    ) -> Result<Self, AttachFailure> {
        let result = (|| {
            requester.check_stopped().map_err(|_| Error::PciAuthority)?;
            let Bar::Memory {
                address,
                size,
                wide,
                ..
            } = bar
            else {
                return Err(Error::InvalidBar);
            };
            let span = mapping.physical_span().map_err(|_| Error::InvalidBar)?;
            if address == 0
                || !address.is_multiple_of(4096)
                || size < REGION_BYTES as u64
                || !size.is_power_of_two()
                || !address.is_multiple_of(size)
                || address.checked_add(size).is_none()
                || span.start() != address
                || span.bytes() != size
                || mapping.bytes().map_err(|_| Error::InvalidBar)? as u64 != size
                || mapping.attribute().map_err(|_| Error::InvalidBar)? != CacheAttribute::Uncached
                || mapping.protection().map_err(|_| Error::InvalidBar)? != Protection::ReadWrite
                || !(mapping
                    .address(0, 4)
                    .map_err(|_| Error::InvalidBar)?
                    .as_ptr() as usize)
                    .is_multiple_of(4)
            {
                return Err(Error::InvalidBar);
            }
            Ok((address, wide))
        })();
        let address = requester.address();
        let mut function = requester.into_function();
        let (base, wide) = match result {
            Ok(parts) => parts,
            Err(error) => {
                return Err(AttachFailure {
                    error,
                    function,
                    mapping,
                });
            }
        };
        let result = pci_identity::<_, P>(&mut function, address, base, wide, Some(false));
        let identity = match result {
            Ok(identity) if P::supported(identity) => identity,
            result => {
                let error = result.err().unwrap_or(Error::UnsupportedController);
                return Err(AttachFailure {
                    error,
                    function,
                    mapping,
                });
            }
        };
        Ok(Self {
            _profile: core::marker::PhantomData,
            function,
            mapping,
            address,
            identity,
            base,
            wide,
            master: Some(false),
        })
    }
    fn associated(&mut self) -> Result<Identity, Error> {
        let identity = pci_identity::<_, P>(
            &mut self.function,
            self.address,
            self.base,
            self.wide,
            self.master,
        )?;
        if identity != self.identity {
            return Err(Error::PciAuthority);
        }
        Ok(identity)
    }
    /// Return native owners only after the controller acknowledged its
    /// shutdown and removed DMA. Failure keeps this register provider intact.
    pub fn into_stopped_resources(mut self) -> Result<(Function<OwnedConfig>, Mapping), Self> {
        if self.associated().is_err()
            || P::exclusive(&mut self).is_err()
            || self.master != Some(false)
            || self.read32(DMA_ENABLE) != 0
            || self.read32(PDM_ENABLE) != 0
            || self.read32(PAGE_BASE) & GROUP_ENABLE != 0
            || !P::parked_control(self.read32(CONTROL))
            || P::ZSC_CONTROL.is_some_and(|offset| self.read32(offset) != 1)
        {
            return Err(self);
        }
        Ok((self.function, self.mapping))
    }
}
impl<P: Profile> Registers for NativeRegisters<P> {
    fn region_bytes(&self) -> usize {
        self.mapping.bytes().unwrap_or(0)
    }
    fn identity(&mut self) -> Result<Identity, Error> {
        self.associated()
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.associated()?;
        self.master = None;
        if !self.function.set_bus_master(enabled) {
            return Err(Error::PciAuthority);
        }
        self.master = Some(enabled);
        Ok(())
    }
    /// An unmapped or misaligned register reads as all ones and ignores writes.
    fn read32(&mut self, offset: usize) -> u32 {
        self.mapping.read32(offset).unwrap_or(u32::MAX)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        let _ = self.mapping.write32(offset, value);
    }
}

fn pci_identity<C: ConfigSpace, P: Profile>(
    function: &mut Function<C>,
    address: Address,
    base: u64,
    wide: bool,
    master: Option<bool>,
) -> Result<Identity, Error> {
    if function.address != address {
        return Err(Error::PciAuthority);
    }
    let metadata = (function.vendor, function.device, function.class);
    let config = function.config();
    let id = config.read32(0);
    let revision_class = config.read32(8);
    if id == u32::MAX
        || (id as u16, (id >> 16) as u16) != (metadata.0, metadata.1)
        || [
            (revision_class >> 24) as u8,
            (revision_class >> 16) as u8,
            (revision_class >> 8) as u8,
        ] != metadata.2
        || !P::class_allowed(metadata.2)
        || revision_class == u32::MAX
        || config.read8(0x0e) & 0x7f != 0
    {
        return Err(Error::PciAuthority);
    }
    let identity = Identity {
        vendor: id as u16,
        device: (id >> 16) as u16,
        revision: revision_class as u8,
    };
    let command = config.read16(4);
    let status = config.read16(6);
    // INTx disabled; memory decode enabled by the platform. No PCI power
    // transition, BAR assignment or interrupt route is guessed here.
    if command == u16::MAX
        || status == u16::MAX
        || command & 0x402 != 0x402
        || master.is_some_and(|expected| (command & 4 != 0) != expected)
    {
        return Err(Error::PciAuthority);
    }
    let low = config.read32(0x10);
    if low == u32::MAX || low & 7 != if wide { 4 } else { 0 } {
        return Err(Error::InvalidBar);
    }
    let high = if wide { config.read32(0x14) } else { 0 };
    if u64::from(low & !15) | (u64::from(high) << 32) != base {
        return Err(Error::InvalidBar);
    }
    if !capability::stopped_in_d0(config) {
        return Err(Error::PciAuthority);
    }
    Ok(identity)
}

#[cfg(test)]
mod tests;
