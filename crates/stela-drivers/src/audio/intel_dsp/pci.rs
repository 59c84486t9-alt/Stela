// SPDX-License-Identifier: GPL-2.0-only
//! Actual ECAM and UC BAR0/BAR4 ownership for the cAVS2.5 SOF profile.
//! Intel PCI identities and register facts: pinned Linux pci-tgl.c/hda.h.
//! Copyright(c) 2020 Intel Corporation
use super::{Bar, Error, Identity, Registers};
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{
        Address, Bar as PciBar, ConfigSpace, Function, owned::OwnedConfig,
        requester::StoppedRequester,
    },
};

pub struct AttachFailure {
    pub error: Error,
    pub function: Function<OwnedConfig>,
    pub hda: Mapping,
    pub dsp: Mapping,
}
pub struct NativeRegisters {
    function: Function<OwnedConfig>,
    hda: Mapping,
    dsp: Mapping,
    address: Address,
    identity: Identity,
    bases: [u64; 2],
    master: Option<bool>,
}
fn mapping_bar(mapping: &Mapping, bar: PciBar, minimum: usize) -> Result<u64, Error> {
    let PciBar::Memory {
        address,
        size,
        wide: true,
        prefetchable: false,
    } = bar
    else {
        return Err(Error::InvalidBar);
    };
    let span = mapping.physical_span().map_err(|_| Error::InvalidBar)?;
    if size < minimum as u64
        || !size.is_power_of_two()
        || address == 0
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
    Ok(address)
}
impl NativeRegisters {
    /// # Safety
    /// Both fully sized/reserved BARs and their ResourceBacking belong to the
    /// exact stopped requester and assignment epoch. The platform owns D0,
    /// Intel snoop/TCSEL/reset clock configuration, power/clock dependencies,
    /// ACPI/SMM arbitration and SOF selection. Same-function coherent domains
    /// supplied to Controller must remain bound to this requester. Identity,
    /// BAR numbers or equal numeric addresses alone do not supply these grants.
    /// No aliases/firmware/other workers access these resources. Keep grants
    /// retained through acknowledged DMA/core shutdown and remapper drain.
    pub unsafe fn attach(
        mut requester: StoppedRequester,
        hda: Mapping,
        hda_bar: PciBar,
        dsp: Mapping,
        dsp_bar: PciBar,
    ) -> Result<Self, AttachFailure> {
        let result = (|| {
            requester.check_stopped().map_err(|_| Error::Authority)?;
            let hda_base = mapping_bar(&hda, hda_bar, 0x4000)?;
            let dsp_base = mapping_bar(&dsp, dsp_bar, 0x100000)?;
            let hda_end = hda_base + hda.bytes().map_err(|_| Error::InvalidBar)? as u64;
            let dsp_end = dsp_base + dsp.bytes().map_err(|_| Error::InvalidBar)? as u64;
            if hda_base < dsp_end && dsp_base < hda_end {
                return Err(Error::InvalidBar);
            }
            Ok([hda_base, dsp_base])
        })();
        let address = requester.address();
        let mut function = requester.into_function();
        let bases = match result {
            Ok(bases) => bases,
            Err(error) => {
                return Err(AttachFailure {
                    error,
                    function,
                    hda,
                    dsp,
                });
            }
        };
        let identity = match validate(&mut function, address, bases, Some(false)) {
            Ok(id) if id.supported() => id,
            result => {
                return Err(AttachFailure {
                    error: result.err().unwrap_or(Error::UnsupportedController),
                    function,
                    hda,
                    dsp,
                });
            }
        };
        Ok(Self {
            function,
            hda,
            dsp,
            address,
            identity,
            bases,
            master: Some(false),
        })
    }
    fn associated(&mut self) -> Result<Identity, Error> {
        let identity = validate(&mut self.function, self.address, self.bases, self.master)?;
        if identity != self.identity {
            return Err(Error::Authority);
        }
        Ok(identity)
    }
    fn mapping(&self, bar: Bar) -> &Mapping {
        match bar {
            Bar::Hda => &self.hda,
            Bar::Dsp => &self.dsp,
        }
    }
    /// The Controller must already be consumed after acknowledged shutdown.
    pub fn into_stopped_resources(
        mut self,
    ) -> Result<(Function<OwnedConfig>, Mapping, Mapping), Self> {
        if self.associated().is_err() || self.master != Some(false) {
            return Err(self);
        }
        match self.read32(Bar::Dsp, super::registers::ADSPCS) {
            Ok(value) if value & 0x0f0f0000 == 0 => (),
            _ => return Err(self),
        }
        let Ok(gcap) = self.read16(Bar::Hda, 0) else {
            return Err(self);
        };
        for index in 0..(((gcap >> 8) & 15) + ((gcap >> 12) & 15)) as u8 {
            if !matches!(self.read8(Bar::Hda, super::registers::stream_base(index)), Ok(value) if value & 2 == 0)
            {
                return Err(self);
            }
        }
        Ok((self.function, self.hda, self.dsp))
    }
}

// SAFETY: owns the canonical config owner and two actual UC/RW BAR leases,
// validates live assignment/IRQ/PM on managed entry and never exposes aliases.
// Active drop is quarantined by canonical Mapping/OwnedConfig ownership.
unsafe impl Registers for NativeRegisters {
    fn identity(&mut self) -> Result<Identity, Error> {
        self.associated()
    }
    fn bytes(&self, bar: Bar) -> usize {
        self.mapping(bar).bytes().unwrap_or(0)
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.associated()?;
        let config = self.function.config();
        let before = config.read16(4);
        let desired = if enabled { before | 4 } else { before & !4 };
        self.master = None;
        config.write16(4, desired);
        if config.read16(4) != desired {
            return Err(Error::Authority);
        }
        self.master = Some(enabled);
        Ok(())
    }
    fn misc_clock_gate(&mut self, enabled: bool) -> Result<(), Error> {
        self.associated()?;
        let config = self.function.config();
        let before = config.read32(0x48);
        if before == u32::MAX {
            return Err(Error::Authority);
        }
        let wanted = if enabled {
            before | (1 << 6)
        } else {
            before & !(1 << 6)
        };
        config.write32(0x48, wanted);
        if config.read32(0x48) != wanted {
            return Err(Error::Authority);
        }
        Ok(())
    }
    fn hold_d0(&mut self) -> Result<(), Error> {
        self.associated()?;
        let config = self.function.config();
        for (offset, mask, bits) in [(0x48, 1 << 1, 0), (0x44, 1 << 2, 1 << 2)] {
            let before = config.read32(offset);
            if before == u32::MAX {
                return Err(Error::Authority);
            }
            let wanted = (before & !mask) | bits;
            config.write32(offset, wanted);
            if config.read32(offset) != wanted {
                return Err(Error::Authority);
            }
        }
        Ok(())
    }
    fn read8(&mut self, bar: Bar, offset: usize) -> Result<u8, Error> {
        let pointer = self
            .mapping(bar)
            .address(offset, 1)
            .map_err(|_| Error::Register(bar, offset))?;
        // SAFETY: actual checked exclusive native UC register byte.
        Ok(unsafe { pointer.as_ptr().read_volatile() })
    }
    fn read16(&mut self, bar: Bar, offset: usize) -> Result<u16, Error> {
        if offset & 1 != 0 {
            return Err(Error::Register(bar, offset));
        }
        let pointer = self
            .mapping(bar)
            .address(offset, 2)
            .map_err(|_| Error::Register(bar, offset))?;
        // SAFETY: checked aligned native register word; no W1C adjacent RMW.
        Ok(unsafe { pointer.as_ptr().cast::<u16>().read_volatile() })
    }
    fn read32(&mut self, bar: Bar, offset: usize) -> Result<u32, Error> {
        if offset & 3 != 0 {
            return Err(Error::Register(bar, offset));
        }
        let pointer = self
            .mapping(bar)
            .address(offset, 4)
            .map_err(|_| Error::Register(bar, offset))?;
        // SAFETY: checked aligned exclusive register/SRAM dword.
        let value = unsafe { pointer.as_ptr().cast::<u32>().read_volatile() };
        if value == u32::MAX && !(bar == Bar::Dsp && offset >= 0x80000) {
            return Err(Error::Register(bar, offset));
        }
        Ok(value)
    }
    fn write8(&mut self, bar: Bar, offset: usize, value: u8) -> Result<(), Error> {
        let pointer = self
            .mapping(bar)
            .address(offset, 1)
            .map_err(|_| Error::Register(bar, offset))?;
        // SAFETY: checked native byte access preserves adjacent W1C status.
        unsafe { pointer.as_ptr().write_volatile(value) };
        Ok(())
    }
    fn write16(&mut self, bar: Bar, offset: usize, value: u16) -> Result<(), Error> {
        if offset & 1 != 0 {
            return Err(Error::Register(bar, offset));
        }
        let pointer = self
            .mapping(bar)
            .address(offset, 2)
            .map_err(|_| Error::Register(bar, offset))?;
        // SAFETY: checked natural register word width.
        unsafe { pointer.as_ptr().cast::<u16>().write_volatile(value) };
        Ok(())
    }
    fn write32(&mut self, bar: Bar, offset: usize, value: u32) -> Result<(), Error> {
        if offset & 3 != 0 {
            return Err(Error::Register(bar, offset));
        }
        let pointer = self
            .mapping(bar)
            .address(offset, 4)
            .map_err(|_| Error::Register(bar, offset))?;
        // SAFETY: checked natural register/SRAM dword width.
        unsafe { pointer.as_ptr().cast::<u32>().write_volatile(value) };
        Ok(())
    }
}

fn validate<C: ConfigSpace>(
    function: &mut Function<C>,
    address: Address,
    bases: [u64; 2],
    master: Option<bool>,
) -> Result<Identity, Error> {
    if function.address != address {
        return Err(Error::Authority);
    }
    let metadata = (function.vendor, function.device, function.class);
    let config = function.config();
    let id = config.read32(0);
    let rc = config.read32(8);
    if id == u32::MAX
        || rc == u32::MAX
        || (id as u16, (id >> 16) as u16) != (metadata.0, metadata.1)
        || [(rc >> 24) as u8, (rc >> 16) as u8, (rc >> 8) as u8] != metadata.2
        || !matches!(metadata.2, [4, 1, 0] | [4, 3, 0x80])
        || config.read8(0xe) & 0x7f != 0
    {
        return Err(Error::Authority);
    }
    let command = config.read16(4);
    let status = config.read16(6);
    if command == u16::MAX
        || status == u16::MAX
        || command & 0x402 != 0x402
        || master.is_some_and(|expected| (command & 4 != 0) != expected)
    {
        return Err(Error::Authority);
    }
    for (offset, base) in [(0x10, bases[0]), (0x20, bases[1])] {
        let lo = config.read32(offset);
        let hi = config.read32(offset + 4);
        if lo & 15 != 4 || (u64::from(lo & !15) | (u64::from(hi) << 32)) != base {
            return Err(Error::InvalidBar);
        }
    }
    let mut pm = false;
    for entry in config.capabilities() {
        let entry = entry.map_err(|_| Error::Authority)?;
        let offset = entry.offset;
        // This profile owns the vendor dwords 44/48. Refuse even an undecoded
        // capability body before them instead of guessing its extent and
        // corrupting PM/MSI/PCIe fields through an alias.
        if offset < 0x50 {
            return Err(Error::Authority);
        }
        let control = config.read16(offset + 2);
        if control == u16::MAX {
            return Err(Error::Authority);
        }
        match entry.id {
            1 => {
                if pm || config.read16(offset + 4) & 3 != 0 {
                    return Err(Error::Authority);
                }
                pm = true;
            }
            5 if control & 1 != 0 => return Err(Error::Authority),
            0x11 if control & 0x8000 != 0 => return Err(Error::Authority),
            _ => (),
        }
    }
    Ok(Identity {
        vendor: id as u16,
        device: (id >> 16) as u16,
        revision: rc as u8,
    })
}
