// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
// Copyright (c) 2020, Advanced Micro Devices, Inc.
// Author: Sanjay R Mehta <sanju.mehta@amd.com>
// Adapted from Linux drivers/spi/spi-amd.c at
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8; see ../THIRD_PARTY.md.
//! Serialized AMD opcode/FIFO PIO, mode 0, eight-bit words, one data line.
//!
//! A command sends one opcode, optional TX bytes, then optional RX bytes in
//! one hardware execution. There is no synthetic chunking or command replay.
//! RX is published only after completion and selector cleanup. Every hardware
//! access shares one deadline, including payload and final readback. Errors
//! quarantine the original controller owner; this protocol has no generic
//! abort/reset primitive. The hardware has no peripheral-ACK/error indication:
//! BUSY clear establishes engine completion, not successful device semantics.
//! [`memory`] adds bounded index-mode address/dummy and opcode-defined read
//! formats through this same owner; HID2 DMA remains a separate controller.
use crate::Clock;

pub mod memory;
mod native;
pub use native::NativeRegisters;

const CONTROL: usize = 0;
const EXECUTE: u32 = 1 << 16;
const FIFO_CLEAR: u32 = 1 << 20;
const BUSY: u32 = 1 << 31;
const SELECT: usize = 0x1d;
const ENABLE: usize = 0x20;
const OPCODE: usize = 0x45;
const TRIGGER: usize = 0x47;
const TX_COUNT: usize = 0x48;
const RX_COUNT: usize = 0x4b;
const STATUS: usize = 0x4c;
const SPEED: usize = 0x6c;
const FIFO: usize = 0x80;
const ALT_SPEED: u32 = 15 << 20;
const SPI100: u32 = 1;
const SPD7: u32 = 63 << 8;

/// Pinned Linux max_message_size, including the separately encoded opcode.
pub const MAX_MESSAGE: usize = 70;

/// Shared microsecond timer with an explicit usable-clock admission check.
/// `calibrated` must reflect the actual clock service, not controller clock
/// power. While admitted, time is monotonic and eventually advances, including
/// during `relax`; an unavailable/uncalibrated clock must return false.
pub trait Timer: crate::bus::i2c::Timer {
    fn calibrated(&self) -> bool;
}
impl Timer for Clock {
    fn calibrated(&self) -> bool {
        self.ticks_per_microsecond != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    V1,
    V2,
}
impl Profile {
    pub fn from_acpi_id(id: &str) -> Option<Self> {
        match id {
            "AMDI0061" => Some(Self::V1),
            "AMDI0062" => Some(Self::V2),
            // AMDI0063 requires its distinct HID2 DMA initialization.
            _ => None,
        }
    }
    fn status(self) -> usize {
        match self {
            Self::V1 => CONTROL,
            Self::V2 => STATUS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

/// Ordered byte/32-bit little-endian register access and the actual owner.
///
/// # Safety
/// Retain the original exclusively reserved controller resource, UC mapping,
/// ACPI/firmware arbitration, powered clock/reset epoch and board pin ownership.
/// `profile` describes that actual controller. The engine is initially stopped;
/// no DMA, IRQ, firmware, AML or other CPU accesses it during this lifetime.
/// Failed accesses may already have effects. Retention by deliberate leak must
/// preserve every original resource/clock/reset owner; a numeric base is not
/// an owner. Accesses must not themselves block indefinitely.
pub unsafe trait Registers {
    fn profile(&self) -> Profile;
    fn read8(&mut self, offset: usize) -> Result<u8, IoError>;
    fn write8(&mut self, offset: usize, value: u8) -> Result<(), IoError>;
    fn read32(&mut self, offset: usize) -> Result<u32, IoError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Mode0,
    Mode1,
    Mode2,
    Mode3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    /// Actual firmware/board chip select, 0..=3; never inferred from an ID.
    pub chip_select: u8,
    /// Actual peripheral and board limit. Values below 800kHz are refused.
    pub max_hz: u32,
    pub mode: Mode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Configuration,
    UnsupportedMode,
    Length,
    Io,
    Readback,
    Timeout,
    NeedsReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// Access at which failure was detected, including an uncertain write.
    pub offset: Option<usize>,
    /// Trigger was attempted; commands with device effects must not be replayed.
    pub triggered: bool,
    pub last_status: Option<u32>,
}

// Descending source table: (Hz, ALT_SPD encoding, optional SPD7 divisor).
const FREQUENCIES: [(u32, u32, u32); 9] = [
    (100_000_000, 4, 0),
    (66_660_000, 0, 0),
    (50_000_000, 7, 4),
    (33_330_000, 1, 0),
    (22_220_000, 2, 0),
    (16_660_000, 3, 0),
    (4_000_000, 7, 50),
    (3_170_000, 7, 63),
    (800_000, 5, 0),
];

/// One retained controller. Only explicit successful release returns its
/// original resources. Drop and every uncertain hardware error retain them.
pub struct Controller<R: Registers, T: Timer = Clock> {
    owners: Option<(R, T)>,
    timeout_us: u64,
    failed: Option<Error>,
    started: u64,
    offset: Option<usize>,
    triggered: bool,
    last_status: Option<u32>,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// The unsafe register provider supplies actual exclusive native admission.
    /// Invalid configuration returns all original owners without any access.
    pub fn new(registers: R, timer: T, timeout_us: u64) -> Result<Self, (ErrorKind, R, T)> {
        if timeout_us == 0 || !timer.calibrated() || timer.check_duration(timeout_us).is_err() {
            return Err((ErrorKind::Configuration, registers, timer));
        }
        Ok(Self {
            owners: Some((registers, timer)),
            timeout_us,
            failed: None,
            started: 0,
            offset: None,
            triggered: false,
            last_status: None,
        })
    }
    pub fn failure(&self) -> Option<Error> {
        self.failed
    }
    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            offset: self.offset,
            triggered: self.triggered,
            last_status: self.last_status,
        }
    }
    fn deadline(&self) -> Result<(), Error> {
        if self.owners.as_ref().unwrap().1.elapsed_us(self.started) >= self.timeout_us {
            Err(self.error(ErrorKind::Timeout))
        } else {
            Ok(())
        }
    }
    fn read8(&mut self, offset: usize) -> Result<u8, Error> {
        self.offset = Some(offset);
        self.deadline()?;
        let result = self.owners.as_mut().unwrap().0.read8(offset);
        let value = result.map_err(|_| self.error(ErrorKind::Io))?;
        self.deadline()?;
        Ok(value)
    }
    fn write8(&mut self, offset: usize, value: u8) -> Result<(), Error> {
        self.offset = Some(offset);
        self.deadline()?;
        let result = self.owners.as_mut().unwrap().0.write8(offset, value);
        result.map_err(|_| self.error(ErrorKind::Io))?;
        self.deadline()
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        self.offset = Some(offset);
        self.deadline()?;
        let result = self.owners.as_mut().unwrap().0.read32(offset);
        let value = result.map_err(|_| self.error(ErrorKind::Io))?;
        if offset == self.owners.as_ref().unwrap().0.profile().status() {
            self.last_status = Some(value);
        }
        self.deadline()?;
        Ok(value)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.offset = Some(offset);
        self.deadline()?;
        let result = self.owners.as_mut().unwrap().0.write32(offset, value);
        result.map_err(|_| self.error(ErrorKind::Io))?;
        self.deadline()
    }
    fn replace32(&mut self, offset: usize, mask: u32, bits: u32) -> Result<(), Error> {
        let previous = self.read32(offset)?;
        self.write32(offset, (previous & !mask) | bits)?;
        if self.read32(offset)? & mask != bits {
            return Err(self.error(ErrorKind::Readback));
        }
        Ok(())
    }
    fn select(&mut self, chip: u8) -> Result<(), Error> {
        let value = self.read8(SELECT)?;
        self.write8(SELECT, (value & !3) | chip)?;
        if self.read8(SELECT)? != (value & !3) | chip {
            return Err(self.error(ErrorKind::Readback));
        }
        Ok(())
    }
    fn wait_idle(&mut self) -> Result<(), Error> {
        let status = self.owners.as_ref().unwrap().0.profile().status();
        loop {
            if self.read32(status)? & BUSY == 0 {
                return Ok(());
            }
            self.owners.as_ref().unwrap().1.relax();
        }
    }
    fn execute(
        &mut self,
        device: Device,
        frequency: (u32, u32, u32),
        opcode: u8,
        tx: &[u8],
        rx: &mut [u8],
    ) -> Result<(), Error> {
        // Busy observation precedes every configuration/payload effect.
        self.wait_idle()?;
        self.select(device.chip_select)?;
        self.replace32(ENABLE, ALT_SPEED, frequency.1 << 20)?;
        // Source writes SPI100 only for the 100MHz selection. ALT_SPD chooses
        // all lower rates; preserve SPI100 there rather than inventing a reset.
        if frequency.0 == 100_000_000 {
            self.replace32(ENABLE, SPI100, SPI100)?;
        }
        if frequency.2 != 0 {
            self.replace32(SPEED, SPD7, frequency.2 << 8)?;
        }
        let control = self.read32(CONTROL)?;
        // The self-clearing FIFO/execute bits must never be replayed by RMW.
        self.write32(CONTROL, (control & !(FIFO_CLEAR | EXECUTE)) | FIFO_CLEAR)?;
        for (index, byte) in tx.iter().enumerate() {
            self.write8(FIFO + index, *byte)?;
        }
        let profile = self.owners.as_ref().unwrap().0.profile();
        match profile {
            Profile::V1 => {
                let value = self.read32(CONTROL)?;
                self.write32(
                    CONTROL,
                    (value & !(255 | FIFO_CLEAR | EXECUTE)) | u32::from(opcode),
                )?;
                if self.read32(CONTROL)? & 255 != u32::from(opcode) {
                    return Err(self.error(ErrorKind::Readback));
                }
            }
            Profile::V2 => {
                self.write8(OPCODE, opcode)?;
                if self.read8(OPCODE)? != opcode {
                    return Err(self.error(ErrorKind::Readback));
                }
            }
        }
        self.write8(TX_COUNT, tx.len() as u8)?;
        self.write8(RX_COUNT, rx.len() as u8)?;
        if self.read8(TX_COUNT)? != tx.len() as u8 || self.read8(RX_COUNT)? != rx.len() as u8 {
            return Err(self.error(ErrorKind::Readback));
        }
        self.wait_idle()?;
        match profile {
            Profile::V1 => {
                let value = self.read32(CONTROL)?;
                self.deadline()?;
                self.triggered = true;
                self.write32(CONTROL, (value & !FIFO_CLEAR) | EXECUTE)?;
            }
            Profile::V2 => {
                let value = self.read8(TRIGGER)?;
                self.deadline()?;
                self.triggered = true;
                self.write8(TRIGGER, value | 128)?;
            }
        }
        // Unlike the donor's TX-only FIFO path, writes also await completion.
        self.wait_idle()?;
        let mut received = [0; MAX_MESSAGE - 1];
        for (index, byte) in received[..rx.len()].iter_mut().enumerate() {
            *byte = self.read8(FIFO + tx.len() + index)?;
        }
        if profile == Profile::V2 {
            // Preserve unrelated selector bits rather than the donor's full
            // byte zero. This is selector cleanup, not an independent CS-drain
            // proof: completed opcode execution supplies the wire boundary.
            self.select(0)?;
        }
        self.deadline()?;
        rx.copy_from_slice(&received[..rx.len()]);
        Ok(())
    }
    /// One mode-0, single-line command with an opcode and optional TX then RX.
    /// Unsupported requests have no register effects and do not poison the owner.
    pub fn command(
        &mut self,
        device: Device,
        opcode: u8,
        tx: &[u8],
        rx: &mut [u8],
    ) -> Result<(), Error> {
        if self.failed.is_some() {
            return Err(self.error(ErrorKind::NeedsReset));
        }
        self.offset = None;
        self.triggered = false;
        self.last_status = None;
        if device.mode != Mode::Mode0 {
            return Err(self.error(ErrorKind::UnsupportedMode));
        }
        let Some(frequency) = FREQUENCIES.iter().copied().find(|f| f.0 <= device.max_hz) else {
            return Err(self.error(ErrorKind::Configuration));
        };
        if device.chip_select > 3 {
            return Err(self.error(ErrorKind::Configuration));
        }
        if tx
            .len()
            .checked_add(rx.len())
            .is_none_or(|length| length >= MAX_MESSAGE)
        {
            return Err(self.error(ErrorKind::Length));
        }
        self.started = self.owners.as_ref().unwrap().1.start();
        let result = self.execute(device, frequency, opcode, tx, rx);
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
    /// Return the original stopped register/clock owners after successful
    /// commands (or before first use). A faulted owner needs an actual platform
    /// reset and cannot be released by observing an idle bit after its deadline.
    pub fn release(mut self) -> Result<(R, T), Self> {
        if self.failed.is_some() {
            return Err(self);
        }
        Ok(self.owners.take().unwrap())
    }
}
impl<R: Registers, T: Timer> Drop for Controller<R, T> {
    fn drop(&mut self) {
        if let Some(owners) = self.owners.take() {
            core::mem::forget(owners);
        }
    }
}

#[cfg(test)]
mod tests;
