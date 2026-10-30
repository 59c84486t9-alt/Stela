// SPDX-License-Identifier: GPL-2.0-only
//! Intel SOF HDA/cAVS register definitions from pinned Linux hda.h.
//! Copyright(c) 2018 Intel Corporation
use super::{Error, Identity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    Hda,
    Dsp,
}
/// One exclusive stopped DSP/HDA assignment. Native implementations must keep
/// real mappings and requester permission; test models must be isolated.
///
/// # Safety
/// The provider must exclude firmware/other drivers, keep D0/power/clocks and
/// checked coherent DMA active, bind the same requester to all supplied DMA
/// domains, and perform accesses at exactly the named native widths. Errors
/// after writes can have effects and must keep ownership. No active Drop
/// may release registers, resource reservations, power or DMA isolation.
pub unsafe trait Registers {
    fn identity(&mut self) -> Result<Identity, Error>;
    fn bytes(&self, bar: Bar) -> usize;
    /// Clear/set the requester Command.BM and verify its posted native
    /// readback. A failed or ambiguous write must keep the complete owner.
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error>;
    fn misc_clock_gate(&mut self, enabled: bool) -> Result<(), Error>;
    fn hold_d0(&mut self) -> Result<(), Error>;
    fn read8(&mut self, bar: Bar, offset: usize) -> Result<u8, Error>;
    fn read16(&mut self, bar: Bar, offset: usize) -> Result<u16, Error>;
    fn read32(&mut self, bar: Bar, offset: usize) -> Result<u32, Error>;
    fn write8(&mut self, bar: Bar, offset: usize, value: u8) -> Result<(), Error>;
    fn write16(&mut self, bar: Bar, offset: usize, value: u16) -> Result<(), Error>;
    fn write32(&mut self, bar: Bar, offset: usize, value: u32) -> Result<(), Error>;
}
pub(super) const DPIB_BASE: usize = 0x1084;
pub(super) const DPIB_STRIDE: usize = 0x20;
pub(super) const GCAP: usize = 0;
pub(super) const GCTL: usize = 8;
pub(super) const INTCTL: usize = 0x20;
pub(super) const CORBCTL: usize = 0x4c;
pub(super) const RIRBCTL: usize = 0x5c;
pub(super) const PPCTL: usize = 4;
pub(super) const GPROCEN: u32 = 1 << 30;
pub(super) const PIE: u32 = 1 << 31;
pub(super) const EM2: usize = 0x1030;
pub(super) const L1SEN: u32 = 1 << 13;
pub(super) const LTRP: usize = 0x1048;
pub(super) const ADSPCS: usize = 4;
pub(super) const ADSPIC: usize = 8;
pub(super) const IPC_NOTIFY: usize = 0xc0;
pub(super) const IPC_NOTIFY_ACK: usize = 0xc4;
pub(super) const IPC_REQ: usize = 0xd0;
pub(super) const IPC_ACK: usize = 0xd4;
pub(super) const IPCCTL: usize = 0xe8;
pub(super) const BUSY: u32 = 1 << 31;
pub(super) const ROM_STATUS: usize = 0x80000;
pub(super) const READY_MAILBOX: usize = 0x81000;
pub(super) const BDLPL: usize = 0x18;
pub(super) const BDLPU: usize = 0x1c;
pub(super) const CBL: usize = 8;
pub(super) const LVI: usize = 0xc;
pub(super) const FORMAT: usize = 0x12;
pub(super) const RUN: u8 = 2;
pub(super) const SRST: u8 = 1;
pub(super) const STS: usize = 3;
pub(super) const FIFO_ERROR: u8 = 8;
pub(super) const DESC_ERROR: u8 = 16;
pub(super) const W1C: u8 = 0x1c;
pub(super) fn stream_base(index: u8) -> usize {
    0x80 + usize::from(index) * 0x20
}

/// Bounded, non-overlapping source capability extents. Never accepts caller
/// provided capability offsets as register ownership.
pub(super) fn capabilities<R: Registers>(
    registers: &mut R,
    streams: u8,
) -> Result<(usize, usize), Error> {
    let mut next = usize::from(registers.read16(Bar::Hda, 0x14)?);
    let mut ranges = [(0usize, 0usize); 32];
    let mut used = 0;
    let mut pp = None;
    let mut spib = None;
    let mut seen = [false; 6];
    while next != 0 {
        if used == ranges.len() || next < stream_base(streams) || next & 3 != 0 {
            return Err(Error::Capability);
        }
        let header = registers.read32(Bar::Hda, next)?;
        let id = ((header >> 16) & 0xfff) as usize;
        if header == u32::MAX || header >> 28 != 1 || !(1..=5).contains(&id) || seen[id] {
            return Err(Error::Capability);
        }
        seen[id] = true;
        let bytes = match id {
            1 => 0x40,
            2 => {
                let count = registers
                    .read32(Bar::Hda, next + 4)?
                    .checked_add(1)
                    .filter(|n| *n <= 8)
                    .ok_or(Error::Capability)?;
                0x40 + count as usize * 0x40
            }
            3 => 0x10 + usize::from(streams) * 0x20,
            4 | 5 => 8 + usize::from(streams) * 8,
            _ => return Err(Error::Capability),
        };
        let end = next
            .checked_add(bytes)
            .filter(|end| *end <= registers.bytes(Bar::Hda))
            .ok_or(Error::Capability)?;
        if ranges[..used]
            .iter()
            .any(|&(start, stop)| next < stop && start < end)
        {
            return Err(Error::Capability);
        }
        ranges[used] = (next, end);
        used += 1;
        if matches!(id, 3..=5) && registers.read32(Bar::Hda, next + 4)? != 0 {
            return Err(Error::Busy);
        }
        match id {
            3 => pp = Some(next),
            4 => spib = Some(next),
            _ => {}
        }
        next = (header & 0xffff) as usize;
    }
    Ok((pp.ok_or(Error::Capability)?, spib.ok_or(Error::Capability)?))
}
