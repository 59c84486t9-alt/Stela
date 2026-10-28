// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
// Copyright 2023-24 Advanced Micro Devices, Inc.
//! AMD ACP SoundWire immediate commands on an already initialized owned link.
//!
//! Adapted from amd_manager.c at cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
//! Parent ACP power/clock/reset/pins, initialization, enumeration, streams and
//! IRQ/wake arbitration remain the original platform owner's responsibility.
use crate::bus::i2c::Timer;
use alloc::vec::Vec;

mod native;
pub use native::NativeRegisters;

const ENABLE: usize = 0x3000;
const ENABLE_STATUS: usize = 0x3004;
const CLOCK_RESUME: usize = 0x3180;
const RESET: usize = 0x3188;
const COMMAND_UPPER: usize = 0x3230;
const COMMAND_LOWER: usize = 0x3234;
const RESPONSE_UPPER: usize = 0x3238;
const RESPONSE_LOWER: usize = 0x323c;
const STATUS: usize = 0x3240;
const STATE_MASK_LOW: usize = 0x3264;
const STATE_MASK_HIGH: usize = 0x3268;
const ERROR_MASK: usize = 0x3270;
const VALID: u32 = 1;
const BUSY: u32 = 2;
const PHASE_US: u64 = 1_000;
const POLL_US: u64 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Manager {
    First,
    Second,
}
impl Manager {
    fn base(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => 0xc00,
        }
    }
    pub fn register_bytes(self) -> usize {
        self.base() + ERROR_MASK + 4
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoError;

/// Ordered ACP registers and the original exclusive initialized sublink owner.
///
/// # Safety
/// The provider retains the actual ACP parent, this manager's powered and
/// initialized link/frame clocks, pins/reset and firmware/IRQ/work exclusion.
/// The same mapping/manager observation supplies `manager`; no sibling stream,
/// wake, IRQ or deferred user may reset or access this command epoch. Errors
/// may follow effects, and retaining the provider must retain all real grants.
pub unsafe trait Registers: 'static {
    fn manager(&self) -> Manager;
    fn bytes(&self) -> usize;
    fn read32(&mut self, offset: usize) -> Result<u32, IoError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError>;
}

pub use super::{Error, ErrorKind};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message {
    pub device: u8,
    pub address: u16,
    pub page: Option<[u8; 2]>,
}

pub struct Controller<R: Registers, T: Timer> {
    owners: Option<(R, T)>,
    manager: Manager,
    timeout_us: u64,
    fault: Option<Error>,
    issued: bool,
    completed: usize,
    offset: Option<usize>,
    started: u64,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Invalid timing returns the exact owners before even geometry callbacks.
    pub fn new(registers: R, timer: T, timeout_us: u64) -> Result<Self, (ErrorKind, R, T)> {
        if timeout_us == 0
            || timer.check_duration(timeout_us).is_err()
            || timer.check_duration(PHASE_US).is_err()
        {
            return Err((ErrorKind::Configuration, registers, timer));
        }
        let manager = registers.manager();
        if registers.bytes() < manager.register_bytes() {
            return Err((ErrorKind::Configuration, registers, timer));
        }
        Ok(Self {
            owners: Some((registers, timer)),
            manager,
            timeout_us,
            fault: None,
            issued: false,
            completed: 0,
            offset: None,
            started: 0,
        })
    }
    pub fn failure(&self) -> Option<Error> {
        self.fault
    }
    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            offset: self.offset,
            issued: self.issued,
            completed: self.completed,
        }
    }
    fn check(&self) -> Result<(), Error> {
        if self.owners.as_ref().unwrap().1.elapsed_us(self.started) >= self.timeout_us {
            Err(self.error(ErrorKind::Timeout))
        } else {
            Ok(())
        }
    }
    fn read(&mut self, relative: usize) -> Result<u32, Error> {
        self.check()?;
        let at = self.manager.base() + relative;
        self.offset = Some(at);
        let value = self.owners.as_mut().unwrap().0.read32(at);
        let value = value.map_err(|_| self.error(ErrorKind::Io))?;
        self.check()?;
        Ok(value)
    }
    fn write(&mut self, relative: usize, value: u32) -> Result<(), Error> {
        self.check()?;
        let at = self.manager.base() + relative;
        self.offset = Some(at);
        if relative == COMMAND_LOWER {
            self.issued = true;
        }
        self.owners
            .as_mut()
            .unwrap()
            .0
            .write32(at, value)
            .map_err(|_| self.error(ErrorKind::Io))?;
        self.check()
    }
    fn ready(&mut self) -> Result<(), Error> {
        if self.read(ENABLE)? & 1 != 1
            || self.read(ENABLE_STATUS)? & 1 != 1
            || self.read(RESET)? != 0
            || self.read(CLOCK_RESUME)? != 0
            || self.read(STATE_MASK_LOW)? != 0
            || self.read(STATE_MASK_HIGH)? != 0
            || self.read(ERROR_MASK)? != 0
        {
            return Err(self.error(ErrorKind::Link));
        }
        Ok(())
    }
    fn poll(&mut self, mask: u32, set: bool) -> Result<u32, Error> {
        let phase = self.owners.as_ref().unwrap().1.start();
        loop {
            let value = self.read(STATUS)?;
            if self.owners.as_ref().unwrap().1.elapsed_us(phase) >= PHASE_US {
                return Err(self.error(ErrorKind::Timeout));
            }
            if (value & mask != 0) == set {
                return Ok(value);
            }
            // Match the source's ten-microsecond observed poll cadence; both
            // the phase and original whole-operation budgets remain active.
            let pause = self.owners.as_ref().unwrap().1.start();
            loop {
                self.check()?;
                if self.owners.as_ref().unwrap().1.elapsed_us(phase) >= PHASE_US {
                    return Err(self.error(ErrorKind::Timeout));
                }
                if self.owners.as_ref().unwrap().1.elapsed_us(pause) >= POLL_US {
                    break;
                }
                self.owners.as_ref().unwrap().1.relax();
            }
        }
    }
    fn command(&mut self, device: u8, address: u16, data: Option<u8>) -> Result<u8, Error> {
        let status = self.poll(BUSY, false)?;
        if status & VALID != 0 {
            // Source clears a stale VALID response and immediately triggers.
            // Refuse unknown ownership instead of consuming a foreign reply.
            return Err(self.error(ErrorKind::ForeignResponse));
        }
        let upper = if data.is_some() { 3 } else { 2 } << 12
            | u32::from(device) << 8
            | u32::from(address >> 8);
        let lower = u32::from(address & 255) << 24 | u32::from(data.unwrap_or(0)) << 7;
        self.write(COMMAND_UPPER, upper)?;
        self.write(COMMAND_LOWER, lower)?;
        self.poll(VALID, true)?;
        let upper = self.read(RESPONSE_UPPER)?;
        let lower = self.read(RESPONSE_LOWER)?;
        self.write(STATUS, VALID)?;
        self.poll(VALID, false)?;
        // The source checks ACK first, including a response containing ACK
        // and NACK together. Preserve that policy; all-ones data is not a
        // transport-failure sentinel on this register interface.
        let response = u64::from(upper) << 32 | u64::from(lower);
        if response & 1 == 0 {
            return Err(self.error(if response & 2 != 0 {
                ErrorKind::Nack
            } else {
                ErrorKind::Ignored
            }));
        }
        self.completed += 1;
        Ok((response >> 7) as u8)
    }
    fn transfer(
        &mut self,
        message: Message,
        tx: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<(), Error> {
        if self.fault.is_some() {
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
        if tx.is_none() {
            staged
                .try_reserve_exact(count)
                .map_err(|_| self.error(ErrorKind::Allocation))?;
            staged.resize(count, 0);
        }
        self.started = self.owners.as_ref().unwrap().1.start();
        let result = (|| {
            self.ready()?;
            if let Some(pages) = message.page {
                for (i, data) in pages.into_iter().enumerate() {
                    self.command(message.device, 0x48 + i as u16, Some(data))?;
                }
            }
            for offset in 0..count {
                let data = self.command(
                    message.device,
                    message.address + offset as u16,
                    tx.map(|bytes| bytes[offset]),
                )?;
                if tx.is_none() {
                    staged[offset] = data;
                }
            }
            self.check()
        })();
        if let Err(error) = result {
            self.fault = Some(error);
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
    /// Return the original link owners after an observed idle response epoch.
    /// Parent stream/frame/IRQ/power retirement remains the parent's duty.
    pub fn release(mut self) -> Result<(R, T), Self> {
        if self.fault.is_some() {
            return Err(self);
        }
        self.started = self.owners.as_ref().unwrap().1.start();
        let result = self.ready().and_then(|()| {
            if self.read(STATUS)? & (BUSY | VALID) != 0 {
                Err(self.error(ErrorKind::ForeignResponse))
            } else {
                Ok(())
            }
        });
        if let Err(error) = result {
            self.fault = Some(error);
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
