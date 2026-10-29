// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2015-17 Intel Corporation.
//! Cadence SoundWire control-word PIO over an already running, owned link.
//!
//! Adapted from Linux cadence_master.c at
//! cc9de5d4b5ab6459f5774946aa3195ad51236fa8. This is the synchronous command
//! path, not a parent SHIM/PUNIT, bus initialization or audio stream driver.
use crate::bus::i2c::Timer;
use alloc::vec::Vec;

mod native;
pub use native::NativeRegisters;

const CONFIG: usize = 0;
const CONTROL: usize = 4;
const STATUS: usize = 0x40;
const INTERRUPT: usize = 0x44;
const INTERRUPT_MASK: usize = 0x48;
const WATERMARK: usize = 0x78;
const FIFO: usize = 0x7c;
const COMMAND: usize = 0x80;
const RX_WATERMARK: u32 = 1 << 2;
const BUS_ERRORS: u32 = 0xf << 7;
const RESERVED_INTERRUPTS: u32 = 0x7ffe_0070;
const TIMEOUT_US: u64 = 500_000;
const BATCH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    /// Cadence MCP and command registers share the original link aperture.
    Legacy,
    /// Newer Intel IP_MCP registers are 0x4000 above the common MCP registers.
    Extended,
}
impl Layout {
    fn offset(self) -> usize {
        match self {
            Self::Legacy => 0,
            Self::Extended => 0x4000,
        }
    }
    pub fn register_bytes(self) -> usize {
        self.offset() + COMMAND + (BATCH + 2) * 4
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoError;

/// Original serialized Cadence link register and platform owner.
///
/// # Safety
/// The provider keeps this controller/link's mappings, power, reset,
/// frame clock, pins, firmware exclusion and parent resource lifetime. The link
/// is already initialized in normal command mode. No other command, IRQ,
/// deferred task, wake or firmware user may access/reset this epoch. Every
/// access is ordered; errors may follow effects. Retaining/leaking the provider
/// must keep those grants. A copied ID or temporary lock is inadequate.
pub unsafe trait Registers: 'static {
    fn layout(&self) -> Layout;
    fn bytes(&self) -> usize;
    fn read32(&mut self, offset: usize) -> Result<u32, IoError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError>;
}

pub use super::{Error, ErrorKind};

/// A serialized device register message. Page writes precede every paged
/// message, even when the same page was used previously; no stale page cache.
#[derive(Clone, Copy, Debug)]
pub struct Message {
    pub device: u8,
    pub address: u16,
    pub page: Option<[u8; 2]>,
    pub ssp_sync: bool,
}

pub struct Controller<R: Registers, T: Timer> {
    owners: Option<(R, T)>,
    layout: Layout,
    failed: Option<Error>,
    issued: bool,
    completed: usize,
    offset: Option<usize>,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Invalid timing/geometry returns both original owners before any MMIO.
    pub fn new(registers: R, timer: T) -> Result<Self, (ErrorKind, R, T)> {
        if timer.check_duration(TIMEOUT_US).is_err() {
            return Err((ErrorKind::Configuration, registers, timer));
        }
        let layout = registers.layout();
        if registers.bytes() < layout.register_bytes() {
            return Err((ErrorKind::Configuration, registers, timer));
        }
        Ok(Self {
            owners: Some((registers, timer)),
            layout,
            failed: None,
            issued: false,
            completed: 0,
            offset: None,
        })
    }
    pub fn failure(&self) -> Option<Error> {
        self.failed
    }
    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            offset: self.offset,
            issued: self.issued,
            completed: self.completed,
        }
    }
    fn read(&mut self, offset: usize) -> Result<u32, Error> {
        self.offset = Some(offset);
        self.owners
            .as_mut()
            .unwrap()
            .0
            .read32(offset)
            .map_err(|_| self.error(ErrorKind::Io))
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.offset = Some(offset);
        self.owners
            .as_mut()
            .unwrap()
            .0
            .write32(offset, value)
            .map_err(|_| self.error(ErrorKind::Io))
    }
    fn deadline(&self, start: u64) -> Result<(), Error> {
        if self.owners.as_ref().unwrap().1.elapsed_us(start) >= TIMEOUT_US {
            Err(self.error(ErrorKind::Timeout))
        } else {
            Ok(())
        }
    }
    fn ready(&mut self) -> Result<(), Error> {
        let ip = self.layout.offset();
        // Observe source normal mode, accepted commands, running frame clock,
        // stopped reset and disabled physical interrupt delivery. These checks
        // supplement, but cannot establish, the provider's permission.
        if self.read(CONFIG)? & (1 << 6) != 0
            || self.read(ip + CONFIG)? & (7 | (1 << 3) | (1 << 5) | (15 << 24)) != 0
            || self.read(CONTROL)? & ((1 << 7) | (1 << 6) | (1 << 4)) != 0
            || self.read(ip + CONTROL)? & ((1 << 5) | (1 << 3) | 2) != 2
            || self.read(STATUS)? & (1 << 16) != 0
            || self.read(INTERRUPT_MASK)? != 0
            || self.read(ip + 8)? & (1 << 2) != 0
        {
            return Err(self.error(ErrorKind::Link));
        }
        let status = self.read(INTERRUPT)?;
        if status & (BUS_ERRORS | RESERVED_INTERRUPTS) != 0 {
            return Err(self.error(ErrorKind::Link));
        }
        if self.read(FIFO)? & 63 != 0 || status & RX_WATERMARK != 0 {
            return Err(self.error(ErrorKind::ForeignResponse));
        }
        Ok(())
    }
    fn batch(&mut self, words: &[u32], response: &mut [u8]) -> Result<(), Error> {
        self.ready()?;
        let start = self.owners.as_ref().unwrap().1.start();
        if self.read(WATERMARK)? != words.len() as u32 {
            self.write(WATERMARK, words.len() as u32)?;
            if self.read(WATERMARK)? != words.len() as u32 {
                return Err(self.error(ErrorKind::Link));
            }
        }
        for (index, &word) in words.iter().enumerate() {
            self.deadline(start)?;
            self.issued = true;
            self.write(self.layout.offset() + COMMAND + index * 4, word)?;
        }
        loop {
            self.deadline(start)?;
            let status = self.read(INTERRUPT)?;
            if status & (BUS_ERRORS | RESERVED_INTERRUPTS) != 0 {
                return Err(self.error(ErrorKind::Link));
            }
            let count = self.read(FIFO)? & 63;
            if count > words.len() as u32 {
                return Err(self.error(ErrorKind::ForeignResponse));
            }
            if count == words.len() as u32 {
                break;
            }
            self.owners.as_ref().unwrap().1.relax();
        }
        let mut nack = false;
        let mut ignored = false;
        for (index, byte) in response.iter_mut().enumerate() {
            let value = self.read(self.layout.offset() + COMMAND + index * 4)?;
            nack |= value & 2 != 0;
            ignored |= value & 1 == 0;
            *byte = (value >> 8) as u8;
        }
        // Source IRQ path drains responses, then W1C before completing the
        // waiter. Preserve every unrelated attach/alert/data-port cause.
        self.write(INTERRUPT, RX_WATERMARK)?;
        let status = self.read(INTERRUPT)?;
        if status & (BUS_ERRORS | RESERVED_INTERRUPTS | RX_WATERMARK) != 0
            || self.read(FIFO)? & 63 != 0
        {
            return Err(self.error(ErrorKind::ForeignResponse));
        }
        self.deadline(start)?;
        if nack {
            return Err(self.error(ErrorKind::Nack));
        }
        if ignored {
            return Err(self.error(ErrorKind::Ignored));
        }
        self.completed += words.len();
        Ok(())
    }
    fn transfer(
        &mut self,
        message: Message,
        tx: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<(), Error> {
        if self.failed.is_some() {
            return Err(self.error(ErrorKind::Faulted));
        }
        self.issued = false;
        self.completed = 0;
        self.offset = None;
        let count = tx.map_or(output.len(), <[u8]>::len);
        if message.device > 15
            || count == 0
            || count > usize::from(u16::MAX)
            || count > 65536 - usize::from(message.address)
        {
            return Err(self.error(ErrorKind::Length));
        }
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(count)
            .map_err(|_| self.error(ErrorKind::Allocation))?;
        staged.resize(count, 0);
        let result = (|| {
            if let Some(pages) = message.page {
                let words = core::array::from_fn::<_, 2, _>(|i| {
                    3 << 28
                        | u32::from(message.device) << 24
                        | (0x48 + i as u32) << 8
                        | u32::from(pages[i])
                });
                self.batch(&words, &mut [0; 2])?;
            }
            for offset in (0..count).step_by(BATCH) {
                let size = (count - offset).min(BATCH);
                let mut words = [0; BATCH];
                for (i, word) in words[..size].iter_mut().enumerate() {
                    *word = u32::from(message.ssp_sync) << 31
                        | if tx.is_some() { 3 } else { 2 } << 28
                        | u32::from(message.device) << 24
                        | (u32::from(message.address) + (offset + i) as u32) << 8
                        | tx.map_or(0, |tx| u32::from(tx[offset + i]));
                }
                self.batch(&words[..size], &mut staged[offset..offset + size])?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            // Complete NACK/ignored batches are drained, but earlier commands
            // may have changed a peripheral. No automatic replay/reset/release.
            self.failed = Some(error);
            return Err(error);
        }
        if tx.is_none() {
            output.copy_from_slice(&staged);
        }
        Ok(())
    }
    pub fn read_registers(&mut self, message: Message, output: &mut [u8]) -> Result<(), Error> {
        self.transfer(message, None, output)
    }
    pub fn write_registers(&mut self, message: Message, bytes: &[u8]) -> Result<(), Error> {
        self.transfer(message, Some(bytes), &mut [])
    }
    /// Successful idle observation returns exactly the original command/link
    /// owners. Parent stream/IRQ/frame/power retirement is their next duty.
    pub fn release(mut self) -> Result<(R, T), Self> {
        if self.failed.is_some() {
            return Err(self);
        }
        if let Err(error) = self.ready() {
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
