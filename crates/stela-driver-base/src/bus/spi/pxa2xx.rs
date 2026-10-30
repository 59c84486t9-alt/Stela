// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2005 Stephen Street / StreetFire Sound Labs
// Copyright (C) 2013, 2021 Intel Corporation
// SSP register interface: Copyright (C) 2003 Russell King, All Rights Reserved.
// LPSS/PXA2xx SSP protocol adapted from Linux spi-pxa2xx.c at
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8. See ../THIRD_PARTY.md.
//! Intel LPSS SSP native polled full-duplex master and manual chip selects.
//!
//! All six LPSS register layouts use the SSP wire engine. Transfers
//! support 4..=32-bit words, modes 0..3, active-low native CS, loopback, per-transfer
//! speed/word size, delays and CS changes. Every receive word is consumed even
//! for TX-only transfers. Read outputs are staged through final completion and
//! CS cleanup. IRQ/DMA service requests remain disabled in this PIO owner.
pub use super::amd::{Mode, Timer};
use crate::Clock;
use alloc::vec::Vec;

mod native;
pub use native::NativeRegisters;
const CR0: usize = 0;
const CR1: usize = 4;
const STATUS: usize = 8;
const DATA: usize = 0x10;
const TIMEOUT: usize = 0x28;
const PROTOCOL: usize = 0x2c;
const TX_THRESHOLD: usize = 0x44;
const RX_THRESHOLD: usize = 0x48;
const ENABLE: u32 = 1 << 7;
const RECEIVE: u32 = 1 << 3;
const BUSY: u32 = 1 << 4;
const OVERRUN: u32 = 1 << 7;
const TX_LEVEL: u32 = 15 << 8;
const RX_TIMEOUT: u32 = 1 << 19;
const UNDERRUN: u32 = 1 << 21;
const BIT_ERROR: u32 = 1 << 23;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    LynxPoint,
    BayTrail,
    Braswell,
    Sunrisepoint,
    Broxton,
    CannonLake,
}
#[derive(Clone, Copy)]
struct Layout {
    private: usize,
    select: usize,
    select_shift: u32,
    select_mask: u32,
    capabilities: bool,
    gated_cs: bool,
    rx: u32,
    tx_low: u32,
    tx_high: u32,
}
impl Profile {
    fn layout(self) -> Layout {
        match self {
            Self::LynxPoint => Layout {
                private: 0x800,
                select: 0x18,
                select_shift: 0,
                select_mask: 0,
                capabilities: false,
                gated_cs: false,
                rx: 64,
                tx_low: 160,
                tx_high: 224,
            },
            Self::BayTrail => Layout {
                private: 0x400,
                ..Self::LynxPoint.layout()
            },
            Self::Braswell => Layout {
                select_shift: 2,
                select_mask: 1 << 2,
                ..Self::BayTrail.layout()
            },
            Self::Sunrisepoint => Layout {
                private: 0x200,
                select: 0x24,
                select_shift: 0,
                select_mask: 0,
                capabilities: false,
                gated_cs: false,
                rx: 1,
                tx_low: 32,
                tx_high: 56,
            },
            Self::Broxton => Layout {
                select_shift: 8,
                select_mask: 3 << 8,
                capabilities: true,
                gated_cs: true,
                tx_low: 16,
                tx_high: 48,
                ..Self::Sunrisepoint.layout()
            },
            Self::CannonLake => Layout {
                tx_low: 32,
                tx_high: 56,
                ..Self::Broxton.layout()
            },
        }
    }
    pub fn register_bytes(self) -> usize {
        let layout = self.layout();
        layout.private
            + if layout.capabilities {
                0x100
            } else {
                layout.select + 4
            }
    }
    /// Translate the observed ACPI DeviceSelection only for the source Atom
    /// layouts. It does not discover or grant board pins/chip selects.
    pub fn firmware_chip_select(self, selection: u32) -> Option<u8> {
        let value = match self {
            Self::BayTrail | Self::Braswell => selection.checked_sub(1)?,
            _ => selection,
        };
        u8::try_from(value).ok()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Description {
    pub profile: Profile,
    /// Enabled SSP input clock observed from its clock owner.
    pub input_clock_hz: u32,
    /// Board-owned native CS pins; controller capability further narrows.
    pub chip_selects: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;
/// Retained, stopped LPSS SSP controller and its ordered native DWORDs.
/// # Safety
/// Keep the original powered/reset/clock/pin/firmware device ownership and
/// complete exclusive UC mapping. Description is immutable metadata;
/// prior DMA/IRQs/callbacks are stopped and drained. No other user can access,
/// reset, relocate or revoke this epoch. Leaking the provider
/// keeps every original grant. Failed accesses may have taken effect.
pub unsafe trait Registers {
    fn description(&self) -> Description;
    fn bytes(&self) -> usize;
    fn read32(&mut self, offset: usize) -> Result<u32, IoError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    pub chip_select: u8,
    pub mode: Mode,
    pub active_high: bool,
    pub loopback: bool,
}
/// Word storage matches the source: one LE byte for 4..8 bits, two for 9..16,
/// four for 17..32. Absent TX sends zero; absent RX still drains words.
pub struct Transfer<'a> {
    pub tx: Option<&'a [u8]>,
    pub rx: Option<&'a mut [u8]>,
    pub words: usize,
    pub bits_per_word: u8,
    pub max_hz: u32,
    pub delay_us: u64,
    /// Between transfers, release then reassert CS. On the final transfer,
    /// leave CS asserted until the next message or explicit release.
    pub cs_change: bool,
    pub cs_change_delay_us: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Configuration,
    UnsupportedPolarity,
    NotInitialized,
    Length,
    Allocation,
    Io,
    Readback,
    Timeout,
    Fifo,
    NeedsReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: Option<usize>,
    pub status: Option<u32>,
    pub wire_started: bool,
}

pub struct Controller<R: Registers, T: Timer = Clock> {
    owners: Option<(R, T)>,
    description: Description,
    timeout_us: u64,
    initialized: bool,
    chip_selects: u8,
    selected: Option<Device>,
    failed: Option<Error>,
    started: u64,
    offset: Option<usize>,
    status: Option<u32>,
    wire_started: bool,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    pub fn new(registers: R, timer: T, timeout_us: u64) -> Result<Self, (ErrorKind, R, T)> {
        if timeout_us == 0 || !timer.calibrated() || timer.check_duration(timeout_us).is_err() {
            return Err((ErrorKind::Configuration, registers, timer));
        }
        let description = registers.description();
        let maximum = (description.profile.layout().select_mask
            >> description.profile.layout().select_shift)
            + 1;
        if description.input_clock_hz == 0
            || description.chip_selects == 0
            || u32::from(description.chip_selects) > maximum
            || registers.bytes() < description.profile.register_bytes()
        {
            return Err((ErrorKind::Configuration, registers, timer));
        }
        Ok(Self {
            owners: Some((registers, timer)),
            description,
            timeout_us,
            initialized: false,
            chip_selects: description.chip_selects,
            selected: None,
            failed: None,
            started: 0,
            offset: None,
            status: None,
            wire_started: false,
        })
    }
    pub fn failure(&self) -> Option<Error> {
        self.failed
    }
    pub fn chip_selects(&self) -> u8 {
        self.chip_selects
    }
    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            offset: self.offset,
            status: self.status,
            wire_started: self.wire_started,
        }
    }
    fn begin(&mut self) -> Result<(), Error> {
        if self.failed.is_some() {
            return Err(self.error(ErrorKind::NeedsReset));
        }
        self.started = self.owners.as_ref().unwrap().1.start();
        self.offset = None;
        self.status = None;
        self.wire_started = false;
        Ok(())
    }
    fn deadline(&self) -> Result<(), Error> {
        if self.owners.as_ref().unwrap().1.elapsed_us(self.started) >= self.timeout_us {
            Err(self.error(ErrorKind::Timeout))
        } else {
            Ok(())
        }
    }
    fn read(&mut self, offset: usize) -> Result<u32, Error> {
        self.offset = Some(offset);
        self.deadline()?;
        let result = self.owners.as_mut().unwrap().0.read32(offset);
        let value = result.map_err(|_| self.error(ErrorKind::Io))?;
        if offset == STATUS {
            self.status = Some(value);
        }
        self.deadline()?;
        Ok(value)
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.offset = Some(offset);
        self.deadline()?;
        let result = self.owners.as_mut().unwrap().0.write32(offset, value);
        result.map_err(|_| self.error(ErrorKind::Io))?;
        self.deadline()
    }
    fn verified(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.write(offset, value)?;
        if self.read(offset)? != value {
            return Err(self.error(ErrorKind::Readback));
        }
        Ok(())
    }
    fn update(&mut self, offset: usize, mask: u32, value: u32) -> Result<bool, Error> {
        let old = self.read(offset)?;
        let next = (old & !mask) | value;
        if old == next {
            return Ok(false);
        }
        self.verified(offset, next)?;
        Ok(true)
    }
    fn delay(&mut self, micros: u64) -> Result<(), Error> {
        let start = self.owners.as_ref().unwrap().1.start();
        while self.owners.as_ref().unwrap().1.elapsed_us(start) < micros {
            self.deadline()?;
            self.owners.as_ref().unwrap().1.relax();
        }
        self.deadline()
    }
    fn checked_status(&mut self) -> Result<u32, Error> {
        let status = self.read(STATUS)?;
        if status & (OVERRUN | UNDERRUN | BIT_ERROR) != 0 {
            return Err(self.error(ErrorKind::Fifo));
        }
        Ok(status)
    }
    fn idle(&mut self) -> Result<(), Error> {
        loop {
            if self.checked_status()? & BUSY == 0 {
                return Ok(());
            }
            self.owners.as_ref().unwrap().1.relax();
        }
    }
    fn off(&mut self) -> Result<(), Error> {
        self.idle()?;
        self.update(CR0, ENABLE, 0)?;
        if self.read(STATUS)? & TX_LEVEL != 0 {
            return Err(self.error(ErrorKind::Fifo));
        }
        Ok(())
    }
    fn cs(&mut self, device: Device, asserted: bool) -> Result<(), Error> {
        let layout = self.description.profile.layout();
        let offset = layout.private + layout.select;
        if asserted
            && self.update(
                offset,
                layout.select_mask,
                u32::from(device.chip_select) << layout.select_shift,
            )?
        {
            // Source waits two SSP input-clock cycles after selection. The
            // shared timer rounds this minimum up to whole microseconds.
            self.delay(2_000_000u64.div_ceil(u64::from(self.description.input_clock_hz)))?;
        }
        let high = if asserted {
            device.active_high
        } else {
            !device.active_high
        };
        self.update(offset, 3, 1 | if high { 2 } else { 0 })?;
        if layout.gated_cs {
            let gate = layout.private + 0x38;
            if self.update(gate, 3, 3)? {
                self.update(gate, 3, 0)?;
            }
        }
        self.selected = asserted.then_some(device);
        Ok(())
    }
    /// Source probe defaults, PIO service exclusion, private manual CS
    /// and hardware CS capability admission. Failure keeps the original owner.
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.begin()?;
        if self.initialized {
            return Err(self.error(ErrorKind::Configuration));
        }
        let result = (|| {
            // Disable before loading default configuration. Never start any
            // stale firmware FIFO, IRQ or DMA request to establish readiness.
            self.update(CR0, ENABLE, 0)?;
            self.idle()?;
            while self.read(STATUS)? & RECEIVE != 0 {
                self.read(DATA)?;
            }
            self.write(STATUS, OVERRUN | RX_TIMEOUT)?;
            self.verified(CR1, 7 << 10 | 7 << 6)?;
            self.verified(CR0, 2 << 8 | 7)?;
            self.verified(TIMEOUT, 0)?;
            self.verified(PROTOCOL, 0)?;
            let layout = self.description.profile.layout();
            self.update(layout.private + layout.select, 3, 3)?;
            if layout.capabilities {
                let caps = self.read(layout.private + 0xfc)?;
                if caps == u32::MAX {
                    return Err(self.error(ErrorKind::Configuration));
                }
                let available = ((caps >> 9) & 15).trailing_ones().min(4) as u8;
                self.chip_selects = self.chip_selects.min(available);
                if self.chip_selects == 0 {
                    return Err(self.error(ErrorKind::Configuration));
                }
            }
            self.initialized = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
    fn divisor(&self, hz: u32) -> Result<u32, Error> {
        if hz == 0 {
            return Err(self.error(ErrorKind::Configuration));
        }
        let divider = self
            .description
            .input_clock_hz
            .div_ceil(hz.min(self.description.input_clock_hz));
        if divider > 4096 {
            return Err(self.error(ErrorKind::Configuration));
        }
        Ok(divider - 1)
    }
    fn transfer(
        &mut self,
        device: Device,
        transfer: &Transfer<'_>,
        received: &mut [u8],
    ) -> Result<(), Error> {
        self.off()?;
        let bits = transfer.bits_per_word;
        let cr0 = (self.divisor(transfer.max_hz)? << 8)
            | u32::from(if bits > 16 { bits - 17 } else { bits - 1 })
            | if bits > 16 { 1 << 20 } else { 0 };
        let cr1 = match device.mode {
            Mode::Mode0 => 0,
            Mode::Mode1 => 1 << 4,
            Mode::Mode2 => 1 << 3,
            Mode::Mode3 => 3 << 3,
        } | if device.loopback { 1 << 2 } else { 0 };
        let layout = self.description.profile.layout();
        self.update(RX_THRESHOLD, 255, layout.rx - 1)?;
        self.update(
            TX_THRESHOLD,
            65535,
            (layout.tx_low - 1) << 8 | (layout.tx_high - 1),
        )?;
        let thresholds =
            ((layout.rx - 1) << 10) & (15 << 10) | ((layout.tx_low - 1) << 6) & (15 << 6);
        self.verified(CR1, cr1 | thresholds)?;
        self.verified(TIMEOUT, 1000)?;
        self.verified(CR0, cr0)?;
        self.write(STATUS, OVERRUN | RX_TIMEOUT)?;
        self.verified(CR0, cr0 | ENABLE)?;
        if self.selected.is_none() {
            self.cs(device, true)?;
        }
        let width = usize::from(bits.div_ceil(8).next_power_of_two());
        let mask = u32::MAX >> (32 - bits);
        let (mut queued, mut drained) = (0, 0);
        while drained < transfer.words {
            let status = self.checked_status()?;
            if status & RECEIVE != 0 {
                if drained == queued {
                    return Err(self.error(ErrorKind::Fifo));
                }
                let value = self.read(DATA)? & mask;
                if !received.is_empty() {
                    received[drained * width..(drained + 1) * width]
                        .copy_from_slice(&value.to_le_bytes()[..width]);
                }
                drained += 1;
            } else if queued < transfer.words
                && queued - drained < 15
                && status & TX_LEVEL != TX_LEVEL
            {
                let mut word = [0; 4];
                if let Some(tx) = transfer.tx {
                    word[..width].copy_from_slice(&tx[queued * width..(queued + 1) * width]);
                }
                self.wire_started = true;
                self.write(DATA, u32::from_le_bytes(word) & mask)?;
                queued += 1;
            } else {
                self.owners.as_ref().unwrap().1.relax();
            }
        }
        self.idle()?;
        if self.read(STATUS)? & RECEIVE != 0 {
            return Err(self.error(ErrorKind::Fifo));
        }
        self.delay(transfer.delay_us)
    }
    /// Full-duplex message, keeping CS across transfers unless requested.
    /// All geometry/allocation checks precede hardware effects. Output commits
    /// only after the complete message, including delays and final CS state.
    pub fn message(&mut self, device: Device, transfers: &mut [Transfer<'_>]) -> Result<(), Error> {
        self.begin()?;
        if !self.initialized {
            return Err(self.error(ErrorKind::NotInitialized));
        }
        if device.active_high {
            // The LPSS selector latch workaround assumes the inactive native
            // level is high. SPI_CS_HIGH needs an independently owned GPIO CS
            // path; toggling a shared level before/after selection can pulse
            // either the old output or the new active-high peripheral.
            return Err(self.error(ErrorKind::UnsupportedPolarity));
        }
        if device.chip_select >= self.chip_selects || transfers.is_empty() {
            return Err(self.error(ErrorKind::Configuration));
        }
        let mut output_bytes = 0usize;
        for transfer in transfers.iter() {
            if !(4..=32).contains(&transfer.bits_per_word) {
                return Err(self.error(ErrorKind::Configuration));
            }
            self.divisor(transfer.max_hz)?;
            let width = usize::from(transfer.bits_per_word.div_ceil(8).next_power_of_two());
            let length = transfer
                .words
                .checked_mul(width)
                .ok_or_else(|| self.error(ErrorKind::Length))?;
            if transfer.tx.is_some_and(|tx| tx.len() != length)
                || transfer.rx.as_ref().is_some_and(|rx| rx.len() != length)
            {
                return Err(self.error(ErrorKind::Length));
            }
            if transfer.rx.is_some() {
                output_bytes = output_bytes
                    .checked_add(length)
                    .ok_or_else(|| self.error(ErrorKind::Length))?;
            }
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_bytes)
            .map_err(|_| self.error(ErrorKind::Allocation))?;
        output.resize(output_bytes, 0);
        let result = (|| {
            if let Some(old) = self.selected
                && old != device
            {
                self.idle()?;
                self.cs(old, false)?;
            }
            let mut cursor = 0;
            let last = transfers.len() - 1;
            for (index, transfer) in transfers.iter().enumerate() {
                let length = if transfer.rx.is_some() {
                    transfer.words
                        * usize::from(transfer.bits_per_word.div_ceil(8).next_power_of_two())
                } else {
                    0
                };
                self.transfer(device, transfer, &mut output[cursor..cursor + length])?;
                cursor += length;
                if index == last {
                    if !transfer.cs_change {
                        self.cs(device, false)?;
                    }
                } else if transfer.cs_change {
                    self.cs(device, false)?;
                    self.delay(transfer.cs_change_delay_us)?;
                }
            }
            self.off()?;
            self.deadline()?;
            Ok(())
        })();
        if let Err(error) = result {
            self.failed = Some(error);
            return Err(error);
        }
        let mut cursor = 0;
        for transfer in transfers.iter_mut() {
            if let Some(rx) = transfer.rx.as_deref_mut() {
                rx.copy_from_slice(&output[cursor..cursor + rx.len()]);
                cursor += rx.len();
            }
        }
        Ok(())
    }
    /// Acknowledge idle, deassert a held CS, disable SSP and return every
    /// original owner. Faults keep the complete owner without guessed reset.
    pub fn release(mut self) -> Result<(R, T), Self> {
        if self.begin().is_err() {
            return Err(self);
        }
        let result = (|| {
            if self.initialized {
                self.off()?;
                if let Some(device) = self.selected {
                    self.cs(device, false)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.failed = Some(error);
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
