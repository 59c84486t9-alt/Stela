// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017-2018 NVIDIA Corporation. All rights reserved.
// Copyright (c) 2026 Stela contributors
//! Cypress CCGx HPI transport, adapted from pinned Linux ucsi_ccg.c.
//!
//! The platform supplies the actual powered I²C adapter/target and exclusive
//! HPI ownership. Polling drains the same real interrupt-status register as
//! Linux's threaded handler, copying CCI and MESSAGE_IN before W1C. No cached
//! notification can complete a newly submitted command. CCG's fixed 16-byte
//! operation region supports UCSI 1.x; larger layouts are explicitly refused.
//! Firmware flashing, NVIDIA alternate-mode rewriting and runtime PM policy
//! are separate; raw firmware/alternate-mode data is retained.

use super::{Cci, Timer, Transport, TransportError};
use crate::bus::i2c::{Address, Bus, Operation};
use core::num::NonZeroU16;

const INTERRUPT: u16 = 6;
const CONTROL: u16 = 0x39;
const UCSI_INTERRUPT: u8 = 0x80;
const DEVICE_INTERRUPT: u8 = 1;
const UCSI_BASE: u16 = 0xf000;

pub const DEVICE_TREE_COMPATIBLE: &str = "cypress,cypd4226";
pub const ACPI_HID: &str = "AMDI0042";
pub const I2C_DRIVER_ID: &str = "ucsi_ccg";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareInfo {
    pub device: [u8; 6],
    /// Bootloader, FW1 and FW2 base/app version pairs, unchanged wire bytes.
    pub versions: [u8; 24],
}
impl FirmwareInfo {
    pub fn mode(self) -> u8 {
        self.device[0] & 3
    }
    pub fn silicon_id(self) -> u16 {
        u16::from_le_bytes([self.device[2], self.device[3]])
    }
    pub fn ports(self) -> u8 {
        1 + u8::from(self.device[0] & 0x0c != 0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    TimerBudget { microseconds: u64 },
    Transport(TransportError),
    InterruptDrainTimeout { last: u8 },
    FirmwareUnavailable(FirmwareInfo),
}
impl From<TransportError> for StartError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

pub struct Ccg<B: Bus> {
    bus: B,
    address: Address,
    max_read: NonZeroU16,
    firmware: FirmwareInfo,
    cci: Cci,
    message: [u8; 16],
    message_bytes: usize,
    last_interrupt: u8,
}
impl<B: Bus> Ccg<B> {
    /// Start the real HPI UCSI interface. `max_read` comes from the actual
    /// adapter capability; chunking preserves repeated START and advances RAB.
    /// This does not discover or power NVIDIA GPU/DesignWare I²C hardware.
    pub fn start(
        bus: B,
        address: Address,
        max_read: NonZeroU16,
        timer: &impl Timer,
    ) -> Result<Self, StartError> {
        if !timer.supports_duration(100_000) {
            return Err(StartError::TimerBudget {
                microseconds: 100_000,
            });
        }
        let mut this = Self {
            bus,
            address,
            max_read,
            firmware: FirmwareInfo {
                device: [0; 6],
                versions: [0; 24],
            },
            cci: Cci(0),
            message: [0; 16],
            message_bytes: 0,
            last_interrupt: 0,
        };
        this.write(CONTROL, &[2])?;
        this.write(CONTROL, &[1])?;
        let mut interrupts = [0];
        let mut drained = false;
        for _ in 0..10 {
            this.read(INTERRUPT, &mut interrupts)?;
            if interrupts[0] & DEVICE_INTERRUPT == 0 {
                drained = true;
                break;
            }
            this.write(INTERRUPT, &interrupts)?;
            timer.delay_us(10_000);
        }
        if !drained {
            return Err(StartError::InterruptDrainTimeout {
                last: interrupts[0],
            });
        }
        let mut versions = [0; 24];
        this.read(0x10, &mut versions)?;
        let mut device = [0; 6];
        this.read(0, &mut device)?;
        this.firmware = FirmwareInfo { device, versions };
        if !matches!(this.firmware.mode(), 1 | 2) {
            return Err(StartError::FirmwareUnavailable(this.firmware));
        }
        Ok(this)
    }
    pub fn firmware(&self) -> FirmwareInfo {
        self.firmware
    }
    pub fn last_interrupt(&self) -> u8 {
        self.last_interrupt
    }
    fn read(&mut self, register: u16, bytes: &mut [u8]) -> Result<(), TransportError> {
        if usize::from(register) + bytes.len() > 65536 {
            return Err(TransportError::Bounds {
                offset: usize::from(register),
                bytes: bytes.len(),
            });
        }
        for (index, chunk) in bytes
            .chunks_mut(usize::from(self.max_read.get()))
            .enumerate()
        {
            let offset = index * usize::from(self.max_read.get());
            let address = (register + offset as u16).to_le_bytes();
            self.bus
                .transaction(
                    self.address,
                    &mut [Operation::Write(&address), Operation::Read(chunk)],
                )
                .map_err(TransportError::I2c)?;
        }
        Ok(())
    }
    fn write(&mut self, register: u16, bytes: &[u8]) -> Result<(), TransportError> {
        if usize::from(register) + bytes.len() > 65536 {
            return Err(TransportError::Bounds {
                offset: usize::from(register),
                bytes: bytes.len(),
            });
        }
        let mut buffer = alloc::vec::Vec::with_capacity(bytes.len() + 2);
        buffer.extend_from_slice(&register.to_le_bytes());
        buffer.extend_from_slice(bytes);
        self.bus
            .transaction(self.address, &mut [Operation::Write(&buffer)])
            .map_err(TransportError::I2c)
    }
    /// Deferred interrupt work, or the equivalent real hardware poll. Cache
    /// publication follows a complete snapshot and successful interrupt ACK.
    pub fn service_interrupt(&mut self) -> Result<Cci, TransportError> {
        let mut interrupt = [0];
        self.read(INTERRUPT, &mut interrupt)?;
        self.last_interrupt = interrupt[0];
        if interrupt[0] == 0 {
            return Ok(self.cci);
        }
        let mut cci = self.cci;
        let mut message = self.message;
        let mut bytes = self.message_bytes;
        if interrupt[0] & UCSI_INTERRUPT != 0 {
            let mut raw = [0; 4];
            self.read(UCSI_BASE + 4, &mut raw)?;
            cci = Cci(u32::from_le_bytes(raw));
            bytes = 0;
            if !cci.busy() && cci.0 != u32::MAX && cci.length() != 0 {
                if cci.length() > message.len() {
                    return Err(TransportError::Bounds {
                        offset: 16,
                        bytes: cci.length(),
                    });
                }
                // CCG HPI requires the full region copied before clearing IRQ.
                self.read(UCSI_BASE + 16, &mut message)?;
                bytes = cci.length();
            }
        }
        self.write(INTERRUPT, &interrupt)?;
        self.cci = cci;
        self.message = message;
        self.message_bytes = bytes;
        Ok(cci)
    }
}
impl<B: Bus> Transport for Ccg<B> {
    fn read_version(&mut self) -> Result<u16, TransportError> {
        let mut raw = [0; 2];
        self.read(UCSI_BASE, &mut raw)?;
        let version = u16::from_le_bytes(raw);
        if version > 0x0120 {
            return Err(TransportError::UnsupportedTransportVersion(version));
        }
        Ok(version)
    }
    fn poll_cci(&mut self) -> Result<u32, TransportError> {
        self.service_interrupt().map(|cci| cci.0)
    }
    fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
        if bytes.len() > self.message_bytes {
            return Err(TransportError::Bounds {
                offset: 16,
                bytes: bytes.len(),
            });
        }
        bytes.copy_from_slice(&self.message[..bytes.len()]);
        Ok(())
    }
    fn write_message_out(&mut self, _bytes: &[u8]) -> Result<(), TransportError> {
        // Linux's CCG transport has no write_message_out operation.
        Err(TransportError::Unavailable)
    }
    fn write_control(&mut self, control: u64) -> Result<(), TransportError> {
        self.cci = Cci(0);
        self.message_bytes = 0;
        self.write(UCSI_BASE + 8, &control.to_le_bytes())
    }
}

#[cfg(test)]
mod tests;
