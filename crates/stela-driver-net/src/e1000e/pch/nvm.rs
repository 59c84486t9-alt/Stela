// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Read-only PCH NVM banks and the hardware flash sequencing engine.
//! No erase/program/checksum-repair command is issued. Missing valid banks and
//! family-required checksums fail explicitly instead of falling back to bank
//! zero. ID-selected TGP/ADP validation follows its source marker policy.
use super::Delay;
use alloc::{boxed::Box, vec::Vec};

const GFPREG: u32 = 0;
const HSFSTS: u32 = 4;
const HSFCTL: u32 = 6;
const FADDR: u32 = 8;
const FDATA: u32 = 16;
const STRAP: u32 = 0xc;
const FWSM: u32 = 0x5b54;
const DONE: u16 = 1;
const CYCLE_ERROR: u16 = 1 << 1;
const ACCESS_ERROR: u16 = 1 << 2;
const IN_PROGRESS: u16 = 1 << 5;
const DESCRIPTOR_VALID: u16 = 1 << 14;
const GO: u16 = 1;
const CYCLE_MASK: u16 = 3 << 1;
const SIZE_MASK: u16 = 3 << 8;
const POLLS: usize = 10_000_000;
const REPEATS: usize = 10;
const WORD_LIMIT: u32 = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    Pch2,
    Lpt,
    Spt,
}
/// Private PCI-family policies selected by the cold I219 constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum I219Validation {
    Tgp,
    Adp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CycleFailure {
    Timeout,
    Status(u16),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Removed,
    FirmwareOwned,
    InvalidGeometry,
    InvalidDescriptor,
    Bounds,
    Allocation,
    Busy,
    Timeout,
    Cycle(u16),
    Followup {
        primary: CycleFailure,
        observation: Box<Error>,
    },
    NoValidBank,
    Checksum(u16),
    RepairRequired,
    InvalidStation,
    Poisoned,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PCH NVM: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Serialized access to this PCH MAC and its flash-register window.
///
/// # Safety
/// The implementation keeps the real exclusive powered PCI reservation and
/// UC mappings, excluding firmware/SMM, other drivers, workers and resets from
/// the complete hardware sequencer and NVM for its entire lifetime. MAC reads
/// and flash width-specific accesses are real bounded/aligned little-endian
/// volatile operations; reads flush this function's posted writes. Errors do
/// not invent observations or acknowledged stores. Existing native DMA/IRQs
/// are drained before granting access. The flash window is the separate
/// flash BAR on PCH2/LPT or MAC BAR+0xe000 on SPT, not a guessed physical cast.
pub unsafe trait Registers: 'static {
    fn read_mac32(&mut self, offset: u32) -> Result<u32, Error>;
    fn read16(&mut self, offset: u32) -> Result<u16, Error>;
    fn read32(&mut self, offset: u32) -> Result<u32, Error>;
    fn write16(&mut self, offset: u32, value: u16) -> Result<(), Error>;
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub base: u32,
    pub bank_words: u32,
}
impl Geometry {
    fn from_register(layout: Layout, value: u32) -> Result<Self, Error> {
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        let (base, bytes) = if layout == Layout::Spt {
            (0, (((value >> 1) & 31) + 1) * 4096)
        } else {
            let first = value & 0x1fff;
            let end = ((value >> 16) & 0x1fff) + 1;
            if end <= first {
                return Err(Error::InvalidGeometry);
            }
            (first << 12, (end - first) << 12)
        };
        let bank_words = bytes / 4;
        if bank_words < 64 || base.checked_add(bytes).is_none_or(|end| end > 0x0100_0000) {
            return Err(Error::InvalidGeometry);
        }
        Ok(Self { base, bank_words })
    }
}

pub struct Nvm<R: Registers, D: Delay> {
    io: Option<R>,
    delay: D,
    layout: Layout,
    geometry: Geometry,
    bank: Option<u8>,
    poisoned: bool,
}
impl<R: Registers, D: Delay> Nvm<R, D> {
    /// # Safety
    /// `layout` comes from the live PCH PCI generation, not a guessed
    /// family match. `io` and `delay` satisfy the device/resource and
    /// minimum elapsed-time contracts; the caller has a fresh exclusive reset
    /// epoch. NVM is immutable except for this owner's read-only sequencing.
    /// No failed access epoch is reconstructed without real reset/recovery.
    pub unsafe fn new(layout: Layout, io: R, delay: D) -> Result<Self, Error> {
        let mut this = Self {
            io: Some(io),
            delay,
            layout,
            geometry: Geometry {
                base: 0,
                bank_words: 0,
            },
            bank: None,
            poisoned: false,
        };
        let result = (|| {
            let fw = this.io().read_mac32(FWSM)?;
            if fw == u32::MAX {
                return Err(Error::Removed);
            }
            if fw & (1 << 15) != 0 {
                return Err(Error::FirmwareOwned);
            }
            let value = if layout == Layout::Spt {
                this.io().read_mac32(STRAP)?
            } else {
                this.io().read32(GFPREG)?
            };
            this.geometry = Geometry::from_register(layout, value)?;
            Ok(())
        })();
        if let Err(error) = result {
            this.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
    fn io(&mut self) -> &mut R {
        self.io.as_mut().expect("retained NVM register owner")
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn selected_bank(&self) -> Option<u8> {
        self.bank
    }
    fn status(&mut self) -> Result<u16, Error> {
        let value = self.io().read16(HSFSTS)?;
        if value == u16::MAX {
            Err(Error::Removed)
        } else {
            Ok(value)
        }
    }
    fn status_write(&mut self, value: u16) -> Result<(), Error> {
        if self.layout == Layout::Spt {
            self.io().write32(HSFSTS, u32::from(value))
        } else {
            self.io().write16(HSFSTS, value)
        }
    }
    fn control(&mut self) -> Result<u16, Error> {
        let value = if self.layout == Layout::Spt {
            self.io().read32(HSFSTS)? >> 16
        } else {
            u32::from(self.io().read16(HSFCTL)?)
        };
        if value == u32::from(u16::MAX) {
            Err(Error::Removed)
        } else {
            Ok(value as u16)
        }
    }
    fn control_write(&mut self, value: u16) -> Result<(), Error> {
        if self.layout == Layout::Spt {
            self.io().write32(HSFSTS, u32::from(value) << 16)
        } else {
            self.io().write16(HSFCTL, value)
        }
    }
    fn initialize_cycle(&mut self) -> Result<(), Error> {
        let mut status = self.status()?;
        if status & DESCRIPTOR_VALID == 0 {
            return Err(Error::InvalidDescriptor);
        }
        status |= CYCLE_ERROR | ACCESS_ERROR;
        self.status_write(status)?;
        if status & IN_PROGRESS != 0 {
            let mut idle = false;
            for _ in 0..POLLS {
                status = self.status()?;
                if status & IN_PROGRESS == 0 {
                    idle = true;
                    break;
                }
                self.delay.delay(1);
            }
            if !idle {
                return Err(Error::Busy);
            }
        }
        self.status_write(status | DONE)
    }
    fn start_cycle(&mut self) -> Result<(), Error> {
        let control = self.control()?;
        self.control_write(control | GO)?;
        for _ in 0..=POLLS {
            let status = self.status()?;
            if status & DONE != 0 {
                return if status & (CYCLE_ERROR | ACCESS_ERROR) == 0 {
                    Ok(())
                } else {
                    Err(Error::Cycle(status))
                };
            }
            self.delay.delay(1);
        }
        Err(Error::Timeout)
    }
    fn read_cycle(&mut self, offset: u32, size: u8) -> Result<u32, Error> {
        let region_bytes = self
            .geometry
            .bank_words
            .checked_mul(4)
            .ok_or(Error::Bounds)?;
        if !matches!(size, 1 | 2 | 4)
            || (self.layout == Layout::Spt) != (size == 4)
            || offset
                .checked_add(u32::from(size))
                .is_none_or(|end| end > region_bytes)
        {
            return Err(Error::Bounds);
        }
        let address = self
            .geometry
            .base
            .checked_add(offset)
            .ok_or(Error::Bounds)?;
        for attempt in 0..=REPEATS {
            self.delay.delay(1);
            self.initialize_cycle()?;
            let control =
                (self.control()? & !(CYCLE_MASK | SIZE_MASK)) | (u16::from(size - 1) << 8);
            self.control_write(control)?;
            self.io().write32(FADDR, address)?;
            match self.start_cycle() {
                Ok(()) => {
                    return self.io().read32(FDATA).map(|value| match size {
                        1 => value & 0xff,
                        2 => value & 0xffff,
                        _ => value,
                    });
                }
                Err(error @ (Error::Cycle(_) | Error::Timeout)) => {
                    let status = self.status().map_err(|observation| Error::Followup {
                        primary: match &error {
                            Error::Timeout => CycleFailure::Timeout,
                            Error::Cycle(status) => CycleFailure::Status(*status),
                            _ => unreachable!("matched cycle failure"),
                        },
                        observation: Box::new(observation),
                    })?;
                    if status & CYCLE_ERROR != 0 && attempt < REPEATS {
                        continue;
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded retry loop always returns")
    }
    fn bank(&mut self) -> Result<u8, Error> {
        if let Some(bank) = self.bank {
            return Ok(bank);
        }
        let bank_bytes = self.geometry.bank_words * 2;
        for bank in 0..2 {
            let signature = if self.layout == Layout::Spt {
                (self.read_cycle(bank * bank_bytes + 0x13 * 2, 4)? >> 8) as u8
            } else {
                self.read_cycle(bank * bank_bytes + 0x13 * 2 + 1, 1)? as u8
            };
            if signature & 0xc0 == 0x80 {
                self.bank = Some(bank as u8);
                return Ok(bank as u8);
            }
        }
        Err(Error::NoValidBank)
    }
    fn read_inner(&mut self, offset: u16, output: &mut [u16]) -> Result<(), Error> {
        let bank = u32::from(self.bank()?);
        let first = bank * self.geometry.bank_words + u32::from(offset);
        if self.layout == Layout::Spt {
            for i in (0..output.len()).step_by(2) {
                let at = first + i as u32;
                if output.len() - i == 1 {
                    let data = self.read_cycle((at & !1) * 2, 4)?;
                    output[i] = (data >> ((at & 1) * 16)) as u16;
                } else {
                    let data = self.read_cycle(at * 2, 4)?;
                    output[i] = data as u16;
                    output[i + 1] = (data >> 16) as u16;
                }
            }
        } else {
            for (index, value) in output.iter_mut().enumerate() {
                *value = self.read_cycle((first + index as u32) * 2, 2)? as u16;
            }
        }
        Ok(())
    }
    pub fn read(&mut self, offset: u16, output: &mut [u16]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let limit = self.geometry.bank_words.min(WORD_LIMIT) as usize;
        if output.is_empty()
            || usize::from(offset)
                .checked_add(output.len())
                .is_none_or(|end| end > limit)
        {
            return Err(Error::Bounds);
        }
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(output.len())
            .map_err(|_| Error::Allocation)?;
        staged.resize(output.len(), 0);
        match self.read_inner(offset, &mut staged) {
            Ok(()) => {
                output.copy_from_slice(&staged);
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
    /// Validate the factory checksum and source generation's validity marker.
    /// An image needing persistent repair is an explicit unsupported profile.
    pub fn validate(&mut self) -> Result<(), Error> {
        let mut words = [0u16; 64];
        self.read(0, &mut words)?;
        let sum = words.iter().copied().fold(0u16, u16::wrapping_add);
        let (at, mask) = if self.layout == Layout::Pch2 {
            (0x19, 0x40)
        } else {
            (3, 1)
        };
        let result = if words[at] & mask == 0 {
            Err(Error::RepairRequired)
        } else if sum != 0xbaba {
            Err(Error::Checksum(sum))
        } else {
            Ok(())
        };
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Source TGP/ADP checksum policy after PCI family selection. The
    /// selected bank is still observed by `read`; station validity is separate.
    /// TGP alone skips the checksum when its NVM compatibility marker
    /// is clear, or accepts its successfully read uninitialized checksum word.
    /// ADP always checks the checksum and does not demand repair.
    pub(super) fn validate_i219(&mut self, family: I219Validation) -> Result<(), Error> {
        if self.layout != Layout::Spt {
            self.poisoned = true;
            return Err(Error::InvalidGeometry);
        }
        let mut marker = [0u16; 1];
        self.read(3, &mut marker)?;
        if family == I219Validation::Tgp && marker[0] & 1 == 0 {
            return Ok(());
        }
        let mut words = [0u16; 64];
        self.read(0, &mut words)?;
        // The unchanged generic source validator also exempts an explicitly
        // uninitialized TGP checksum word. No other family gets that rule.
        if family == I219Validation::Tgp && words[63] == u16::MAX {
            return Ok(());
        }
        let sum = words.iter().copied().fold(0u16, u16::wrapping_add);
        if sum != 0xbaba {
            self.poisoned = true;
            return Err(Error::Checksum(sum));
        }
        Ok(())
    }
    pub fn station(&mut self) -> Result<crate::Mac, Error> {
        let mut words = [0u16; 3];
        self.read(0, &mut words)?;
        let mut bytes = [0u8; 6];
        for (to, word) in bytes.as_chunks_mut::<2>().0.iter_mut().zip(words) {
            *to = word.to_le_bytes();
        }
        let mac = crate::Mac(bytes);
        if bytes == [0; 6] || bytes == [0xff; 6] || mac.is_multicast() {
            self.poisoned = true;
            Err(Error::InvalidStation)
        } else {
            Ok(mac)
        }
    }
}
impl<R: Registers, D: Delay> Drop for Nvm<R, D> {
    fn drop(&mut self) {
        if self.poisoned
            && let Some(owner) = self.io.take()
        {
            // Keep the claim and mappings after uncertain flash state.
            core::mem::forget(owner);
        }
    }
}

#[cfg(test)]
mod tests;
