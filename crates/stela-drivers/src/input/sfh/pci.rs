// SPDX-License-Identifier: GPL-2.0-or-later
//! Exclusive native PCI configuration and UC BAR2 attachment for AMD SFHv2.
use super::{Error, REGION_BYTES, Registers};
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{
        Address, Bar, ConfigSpace, Function, capability, owned::OwnedConfig,
        requester::StoppedRequester,
    },
};
use core::borrow::{Borrow, BorrowMut};
/// Rejected attachment returns the original owners, without writes.
pub struct AttachFailure {
    pub error: Error,
    pub function: Function<OwnedConfig>,
    pub mapping: Mapping,
}
/// Failed resource return keeps the same controller and precise denial.
pub struct RetirementFailure {
    pub error: Error,
    pub owner: NativeRegisters,
}
pub struct NativeRegisters<F = Function<OwnedConfig>, M = Mapping> {
    function: F,
    mapping: M,
    address: Address,
    base: u64,
    wide: bool,
    master: Option<bool>,
    quiescent: bool,
    revision: u8,
}
impl<'a> NativeRegisters<&'a mut Function<OwnedConfig>, &'a Mapping> {
    /// Borrow the actual original configuration and BAR, without consuming or
    /// granting a stopped requester. The caller keeps its original root owner.
    ///
    /// # Safety
    /// `bar` and `mapping` are this original function's reserved BAR2 in the
    /// same exclusive resource/reset epoch. Prior conflicting source writers
    /// are excluded. PCI IRQs/BME are gated independently, not engine stop.
    pub unsafe fn borrow_original(
        function: &'a mut Function<OwnedConfig>,
        mapping: &'a Mapping,
        bar: Bar,
    ) -> Result<Self, Error> {
        let (base, wide) = bar_layout(mapping, bar)?;
        let address = function.address;
        let revision = function.config().read8(8).map_err(Error::Config)?;
        let mut registers = Self {
            function,
            mapping,
            address,
            base,
            wide,
            master: Some(false),
            quiescent: false,
            revision,
        };
        registers.check_authority()?;
        Ok(registers)
    }
}
fn bar_layout(mapping: &Mapping, bar: Bar) -> Result<(u64, bool), Error> {
    let Bar::Memory {
        address,
        size,
        wide,
        prefetchable: false,
    } = bar
    else {
        return Err(Error::InvalidBar);
    };
    let span = mapping.physical_span().map_err(|_| Error::InvalidBar)?;
    if address == 0
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
}
impl NativeRegisters {
    /// # Safety
    /// `bar` is this function's sized/reserved BAR2; `mapping` keeps
    /// this same exclusive resource/reset/assignment epoch. Numeric span
    /// equality is insufficient. The stopped requester's firmware/IRQ/work and
    /// physical alias exclusion continues until successful explicit shutdown.
    /// No other raw access, cloned view or configuration writer may interfere.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub unsafe fn attach(
        mut requester: StoppedRequester,
        mapping: Mapping,
        bar: Bar,
    ) -> Result<Self, AttachFailure> {
        let checked = (|| {
            requester.check_stopped().map_err(Error::Claim)?;
            let (address, wide) = bar_layout(&mapping, bar)?;
            Ok((address, wide))
        })();
        let address = requester.address();
        let mut function = requester.into_function();
        let checked = checked.and_then(|(address, wide)| {
            let revision = function.config().read8(8).map_err(Error::Config)?;
            Ok((address, wide, revision))
        });
        let (base, wide, revision) = match checked {
            Ok(value) => value,
            Err(error) => {
                return Err(AttachFailure {
                    error,
                    function,
                    mapping,
                });
            }
        };
        let mut owner = Self {
            function,
            mapping,
            address,
            base,
            wide,
            master: Some(false),
            quiescent: true,
            revision,
        };
        if let Err(error) = owner.check_authority() {
            return Err(AttachFailure {
                error,
                function: owner.function,
                mapping: owner.mapping,
            });
        }
        Ok(owner)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn into_stopped_resources(
        mut self,
    ) -> Result<(Function<OwnedConfig>, Mapping), RetirementFailure> {
        let checked = (|| {
            if !self.quiescent || self.master != Some(false) {
                return Err(Error::NotReady);
            }
            self.check_authority()
        })();
        if let Err(error) = checked {
            return Err(RetirementFailure { error, owner: self });
        }
        Ok((self.function, self.mapping))
    }
}
impl<F: BorrowMut<Function<OwnedConfig>>, M: Borrow<Mapping>> Registers for NativeRegisters<F, M> {
    fn check_authority(&mut self) -> Result<(), Error> {
        let function = self.function.borrow_mut();
        if function.address != self.address || function.config().address() != self.address {
            return Err(Error::PciAuthority);
        }
        if (function.vendor, function.device) != (0x1022, 0x15e4) {
            return Err(Error::UnsupportedController);
        }
        let metadata = function.class;
        let config = function.config();
        let class = config.read32(8).map_err(Error::Config)?;
        if config.read32(0).map_err(Error::Config)? != 0x15e41022
            || class == u32::MAX
            || class as u8 != self.revision
            || [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8] != metadata
            || config.read8(0x0e).map_err(Error::Config)? & 0x7f != 0
        {
            return Err(Error::PciAuthority);
        }
        let command = config.read16(4).map_err(Error::Config)?;
        if command == u16::MAX
            || command & 0x402 != 0x402
            || self
                .master
                .is_some_and(|master| (command & 4 != 0) != master)
        {
            return Err(Error::PciAuthority);
        }
        // BAR0/1 may form a 64-bit pair. BAR2 itself begins at 0x18.
        let preceding = config.read32(0x14).map_err(Error::Config)?;
        let first = config.read32(0x10).map_err(Error::Config)?;
        if first & 7 != 4 && preceding & 7 == 4 {
            return Err(Error::InvalidBar);
        }
        let low = config.read32(0x18).map_err(Error::Config)?;
        let high = if self.wide {
            config.read32(0x1c).map_err(Error::Config)?
        } else {
            0
        };
        if low == u32::MAX
            || low & 15 != if self.wide { 4 } else { 0 }
            || u64::from(low & !15) | (u64::from(high) << 32) != self.base
        {
            return Err(Error::InvalidBar);
        }
        let status = config.read16(6).map_err(Error::Config)?;
        if status == u16::MAX {
            return Err(Error::PciAuthority);
        }
        if !capability::stopped_in_d0(config).map_err(Error::Capability)? {
            return Err(Error::PciAuthority);
        }
        Ok(())
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        self.mapping
            .borrow()
            .read32(offset)
            .map_err(|_| Error::RegisterUnavailable(offset))
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        if !offset.is_multiple_of(4) {
            return Err(Error::RegisterUnavailable(offset));
        }
        self.quiescent = false;
        self.mapping
            .borrow()
            .write32(offset, value)
            .map_err(|_| Error::RegisterUnavailable(offset))
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.check_authority()?;
        self.master = None;
        self.function
            .borrow_mut()
            .set_bus_master(enabled)
            .map_err(Error::Config)?;
        self.master = Some(enabled);
        Ok(())
    }
    unsafe fn mark_quiescent(&mut self) {
        self.quiescent = true;
    }
}

#[cfg(test)]
mod tests;
