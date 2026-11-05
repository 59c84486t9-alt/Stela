// SPDX-License-Identifier: GPL-2.0-only
// Copyright 1993 -- 1997 Drew Eckhardt, Frederic Potter, David Mosberger-Tang
// Copyright 1997 -- 2000 Martin Mares <mj@ucw.cz>
// PCI register/reset sequence adapted from pinned Linux drivers/pci/pci.c and
// include/uapi/linux/pci_regs.h. See ../../THIRD_PARTY.md.
//! Supported endpoint FLR, D0 and native command/control writes.
use super::{Configuration, Error, Time};
use crate::bus::pci::regs;
use crate::bus::pci::{ConfigSpace, Function, Layout as Extent, msi::MsiError};

const FLR_SUPPORTED: u32 = 1 << 28;
const INITIATE_FLR: u16 = 1 << 15;
const TRANSACTION_PENDING: u16 = 1 << 5;
const FLR_QUIET_US: u64 = 100_000;
const OPERATION_US: u64 = 1_000_000;

#[derive(Clone, Copy)]
pub(super) struct Layout {
    express: u16,
    power: Option<u16>,
    bars: [u32; 6],
    id: u32,
    class: u32,
    subsystem: u32,
    msi: u16,
    msix: Option<u16>,
    headers: [Option<(u16, u16)>; 4],
}
fn read16<C: ConfigSpace>(c: &C, offset: u16) -> Result<u16, Error> {
    match c.read16(offset).map_err(Error::Config)? {
        u16::MAX => Err(Error::ConfigRead { offset, width: 2 }),
        value => Ok(value),
    }
}
fn read32<C: ConfigSpace>(c: &C, offset: u16) -> Result<u32, Error> {
    match c.read32(offset).map_err(Error::Config)? {
        u32::MAX => Err(Error::ConfigRead { offset, width: 4 }),
        value => Ok(value),
    }
}
fn write16<C: Configuration>(c: &mut C, offset: u16, value: u16) -> Result<(), Error> {
    c.write16(offset, value).map_err(Error::Config)?;
    let observed = read16(c, offset)?;
    if observed != value {
        return Err(Error::ConfigReadback {
            offset,
            observed: u32::from(observed),
        });
    }
    Ok(())
}
fn timely(time: &dyn Time, deadline: u64, requirement: &'static str) -> Result<(), Error> {
    if time.now_us() >= deadline {
        Err(Error::Timeout(requirement))
    } else {
        Ok(())
    }
}
impl Layout {
    /// Complete read-only preflight before FLR, PM, ASPM or command writes.
    pub(super) fn discover<C: Configuration>(f: &mut Function<C>) -> Result<Self, Error> {
        let expected = u32::from(f.vendor) | u32::from(f.device) << 16;
        let address = f.address;
        let c = f.config();
        if c.owned_address() != address
            || read32(c, regs::VENDOR_ID)? != expected
            || c.read8(regs::HEADER_TYPE).map_err(Error::Config)? & 0x7f != 0
        {
            return Err(Error::Requirement(
                "same actual owned type-zero PCI endpoint",
            ));
        }
        let command = read16(c, regs::COMMAND)?;
        if command & regs::COMMAND_MASTER != 0 || command & regs::COMMAND_INTX_DISABLE == 0 {
            return Err(Error::Requirement(
                "actual stopped requester with bus mastering and INTx disabled",
            ));
        }
        if read16(c, 6)? & (1 << 4) == 0 {
            return Err(Error::Requirement("actual PCIe/MSI capability list"));
        }
        let mut extents = alloc::vec::Vec::new();
        let (mut express, mut power, mut msi, mut msix) = (None, None, None, None);
        for entry in c.capabilities() {
            let entry = entry.map_err(Error::Capability)?;
            let offset = entry.offset;
            extents.push(offset..offset + entry.bytes);
            match entry.id {
                0x10 => {
                    if express.replace(offset).is_some() {
                        return Err(Error::Requirement("one native PCIe capability"));
                    }
                    let flags = read16(c, offset + 2)?;
                    if !matches!(flags & 15, 1 | 2) || (flags >> 4) & 15 != 0 || flags & 0x100 != 0
                    {
                        return Err(Error::Requirement("supported PCIe endpoint FLR layout"));
                    }
                    if read32(c, offset + 4)? & FLR_SUPPORTED == 0 {
                        return Err(Error::Requirement("actual supported PCIe FLR"));
                    }
                    if read16(c, offset + 8)? & INITIATE_FLR != 0 {
                        return Err(Error::Requirement("no in-progress native FLR"));
                    }
                }
                1 => {
                    if power.replace(offset).is_some()
                        || !matches!(read16(c, offset + 2)? & 7, 1..=3)
                    {
                        return Err(Error::Requirement("one supported native PCI PM capability"));
                    }
                    read16(c, offset + 4)?;
                }
                5 => {
                    let control = read16(c, offset + 2)?;
                    if msi.replace(offset).is_some()
                        || control & !0x1ff != 0
                        || control & 1 != 0
                        || (control >> 1) & 7 > 5
                        || (control >> 4) & 7 > (control >> 1) & 7
                    {
                        return Err(Error::Requirement(
                            "one actual inactive supported MSI capability",
                        ));
                    }
                }
                0x11 => {
                    if msix.replace(offset).is_some() || read16(c, offset + 2)? & (1 << 15) != 0 {
                        return Err(Error::Requirement("inactive MSI-X without fallback"));
                    }
                }
                _ if entry.layout == Extent::Unsupported => {
                    return Err(Error::Msi(MsiError::Unsupported));
                }
                _ => {}
            }
        }
        if msi.is_none() {
            return Err(Error::Requirement("source requires actual single MSI"));
        }
        for offset in [0x70u16, 0x74, 0x78, 0x80, 0x84, 0x88] {
            if extents
                .iter()
                .any(|extent| extent.start < offset + 4 && offset < extent.end)
            {
                return Err(Error::Requirement(
                    "vendor windows cannot alias native PCI capability bodies",
                ));
            }
        }
        let express = express.ok_or(Error::Requirement("supported native PCIe FLR"))?;
        let mut bars = [0; 6];
        for (index, value) in bars.iter_mut().enumerate() {
            *value = read32(c, 0x10 + index as u16 * 4)?;
        }
        let headers = [
            Some((express, read16(c, express)?)),
            Some((msi.unwrap(), read16(c, msi.unwrap())?)),
            power
                .map(|offset| read16(c, offset).map(|header| (offset, header)))
                .transpose()?,
            msix.map(|offset| read16(c, offset).map(|header| (offset, header)))
                .transpose()?,
        ];
        Ok(Self {
            express,
            power,
            bars,
            id: expected,
            class: read32(c, 8)?,
            subsystem: read32(c, 0x2c)?,
            msi: msi.unwrap(),
            msix,
            headers,
        })
    }
    pub(super) fn bar(self, index: usize) -> Result<(u64, bool), Error> {
        let low = self.bars[index];
        if low == u32::MAX || low & 1 != 0 || !matches!(low & 6, 0 | 4) {
            return Err(Error::Requirement("actual memory BAR assignment"));
        }
        let wide = low & 6 == 4;
        let high = if wide { self.bars[index + 1] } else { 0 };
        let address = u64::from(high) << 32 | u64::from(low & !15);
        if address == 0 {
            return Err(Error::Requirement("assigned native BAR base"));
        }
        Ok((address, wide))
    }
    pub(super) fn prepare<C: Configuration>(
        self,
        c: &mut C,
        time: &dyn Time,
        minimum: &dyn crate::bus::pci::power::Timer,
    ) -> Result<(), Error> {
        minimum.check().map_err(Error::Minimum)?;
        self.d0(c, time, minimum)?;
        self.stop(c, time, minimum)?;
        // FLR may clear BAR assignments/command. Restore only the admitted
        // original BARs; never restore old MSI or device-running control state.
        for (index, value) in self.bars.into_iter().enumerate() {
            let offset = 0x10 + index as u16 * 4;
            c.write32(offset, value).map_err(Error::Config)?;
            let observed = c.read32(offset).map_err(Error::Config)?;
            if observed != value {
                return Err(Error::ConfigReadback { offset, observed });
            }
        }
        self.d0(c, time, minimum)
    }
    pub(super) fn enable<C: Configuration>(self, c: &mut C) -> Result<(), Error> {
        let command = read16(c, regs::COMMAND)?;
        write16(
            c,
            regs::COMMAND,
            command | regs::COMMAND_MEMORY | regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE,
        )
    }
    fn d0<C: Configuration>(
        self,
        c: &mut C,
        time: &dyn Time,
        minimum: &dyn crate::bus::pci::power::Timer,
    ) -> Result<(), Error> {
        minimum.check().map_err(Error::Minimum)?;
        let Some(offset) = self.power.map(|offset| offset + 4) else {
            return Ok(());
        };
        let value = read16(c, offset)?;
        let state = value & 3;
        if state == 0 {
            return Ok(());
        }
        let deadline = time.now_us().saturating_add(OPERATION_US);
        // PME_Status is W1C. Do not replay a pending status when changing D0.
        let wanted = value & !(3 | (1 << 15));
        c.write16(offset, wanted).map_err(Error::Config)?;
        let delay = match state {
            3 => 10_000,
            2 => 200,
            _ => 0,
        };
        minimum.wait_us(delay).map_err(Error::Minimum)?;
        timely(time, deadline, "native PCI D0 acknowledgment")?;
        let observed = read16(c, offset)?;
        timely(time, deadline, "native PCI D0 acknowledgment")?;
        if observed & !(1 << 15) != wanted {
            return Err(Error::ConfigReadback {
                offset,
                observed: u32::from(observed),
            });
        }
        Ok(())
    }
    pub(super) fn stop<C: Configuration>(
        self,
        c: &mut C,
        time: &dyn Time,
        minimum: &dyn crate::bus::pci::power::Timer,
    ) -> Result<(), Error> {
        minimum.check().map_err(Error::Minimum)?;
        let deadline = time.now_us().saturating_add(OPERATION_US);
        let command = read16(c, regs::COMMAND)?;
        timely(time, deadline, "native bus-master stop")?;
        write16(
            c,
            regs::COMMAND,
            (command | regs::COMMAND_INTX_DISABLE) & !regs::COMMAND_MASTER,
        )?;
        timely(time, deadline, "native bus-master stop")?;
        // TRPND covers non-posted requests only. Neither it nor BM-clear/FLR
        // completion authorizes any DMA unmap or CPU vector retirement.
        loop {
            timely(time, deadline, "native PCI transactions pending")?;
            let status = read16(c, self.express + 10)?;
            timely(time, deadline, "native PCI transactions pending")?;
            if status & TRANSACTION_PENDING == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        // Revalidate support in this epoch immediately before reset.
        if read32(c, 0)? != self.id || read32(c, self.express + 4)? & FLR_SUPPORTED == 0 {
            return Err(Error::Requirement("same supported actual FLR endpoint"));
        }
        let control = read16(c, self.express + 8)?;
        timely(time, deadline, "native PCI FLR issue")?;
        c.write16(self.express + 8, control | INITIATE_FLR)
            .map_err(Error::Config)?;
        // FLR self-clears, so a readback of the reset bit cannot acknowledge
        // issue. Native write + required quiet period + identity/config-ready
        // and cleared FLR are the supported completion observation.
        minimum.wait_us(FLR_QUIET_US).map_err(Error::Minimum)?;
        loop {
            timely(time, deadline, "native FLR configuration ready")?;
            let id = c.read32(0).map_err(Error::Config)?;
            timely(time, deadline, "native FLR configuration ready")?;
            if id == self.id {
                for (offset, expected) in self.headers.iter().flatten().copied() {
                    let observed = read16(c, offset)?;
                    timely(time, deadline, "native FLR capability identity")?;
                    if observed != expected {
                        return Err(Error::ConfigReadback {
                            offset,
                            observed: u32::from(observed),
                        });
                    }
                }
                if read16(c, self.express + 8)? & INITIATE_FLR == 0 {
                    break;
                }
            } else if id != u32::MAX && id != 0xffff_0001 {
                return Err(Error::ConfigReadback {
                    offset: 0,
                    observed: id,
                });
            }
            core::hint::spin_loop();
        }
        timely(time, deadline, "native FLR configuration ready")?;
        for (offset, wanted) in [(8, self.class), (0x2c, self.subsystem)] {
            let observed = read32(c, offset)?;
            timely(time, deadline, "native FLR identity")?;
            if observed != wanted {
                return Err(Error::ConfigReadback { offset, observed });
            }
        }
        let command = read16(c, regs::COMMAND)?;
        if command & regs::COMMAND_MASTER != 0
            || read16(c, self.msi + 2)? & 1 != 0
            || self
                .msix
                .map(|offset| read16(c, offset + 2))
                .transpose()?
                .is_some_and(|control| control & (1 << 15) != 0)
        {
            return Err(Error::Requirement(
                "BM/MSI/MSI-X remain disabled after actual FLR",
            ));
        }
        // FLR can reset Command including INTxDisable. Reassert only that
        // narrow control while still inside the one terminal stop closure.
        timely(time, deadline, "native post-FLR INTx disable")?;
        write16(c, regs::COMMAND, command | regs::COMMAND_INTX_DISABLE)?;
        timely(time, deadline, "native FLR completion")
    }
}
