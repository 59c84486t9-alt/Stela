// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2008-2010, 2015 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Real polled Intel SCU/PMC IPC register engine from pinned intel_scu_ipc.c.
//! Platform discovery, power, mapping leases and interrupt delivery ownership
//! remain explicit native prerequisites; no ACPI/PCI attachment is fabricated.
use crate::usb::typec::ucsi::Timer;
use core::{
    ptr::NonNull,
    sync::atomic::{Ordering, fence},
};

pub const ACPI_HID: &str = "INTC1026";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    Mapping,
    Bounds { offset: usize },
    Io { offset: usize, status: u64 },
}
pub trait Registers {
    fn read32(&mut self, offset: usize) -> Result<u32, RegisterError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), RegisterError>;
}
/// Native scalar MMIO. CPU accesses use actual aligned volatile u32 words.
pub struct Mmio {
    base: NonNull<u8>,
    bytes: usize,
}
impl Mmio {
    /// # Safety
    /// Caller retains the actual native device's mapping lease, mapped as
    /// uncached device MMIO and aligned to four bytes. The resource must remain
    /// powered and exclusively serialized for this object's lifetime. For an
    /// IPC mapping, CPU interrupt delivery must be masked or owned by this same
    /// controller; this core polls and acknowledges its completion status.
    pub unsafe fn new(base: NonNull<u8>, bytes: usize) -> Result<Self, RegisterError> {
        if (base.as_ptr() as usize) & 3 != 0
            || bytes < 4
            || (base.as_ptr() as usize).checked_add(bytes).is_none()
        {
            return Err(RegisterError::Mapping);
        }
        Ok(Self { base, bytes })
    }
    fn checked(&self, offset: usize) -> Result<*mut u32, RegisterError> {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.bytes) {
            return Err(RegisterError::Bounds { offset });
        }
        // SAFETY: constructor establishes live mapping; offset/alignment checked.
        Ok(unsafe { self.base.as_ptr().add(offset).cast::<u32>() })
    }
}
impl Registers for Mmio {
    fn read32(&mut self, offset: usize) -> Result<u32, RegisterError> {
        let pointer = self.checked(offset)?;
        // SAFETY: checked proves one aligned word in the live mapping.
        Ok(u32::from_le(unsafe { pointer.read_volatile() }))
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), RegisterError> {
        let pointer = self.checked(offset)?;
        // SAFETY: mapping is exclusively owned and checked above.
        unsafe { pointer.write_volatile(value.to_le()) };
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Preflight,
    WriteBuffer,
    Publish,
    Completion,
    InterruptAck,
    ReadBuffer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Register { phase: Phase, error: RegisterError },
    InvalidArgument,
    InvalidStatus(u32),
    Busy(u32),
    Timeout(u32),
    Controller(u32),
    SequenceExhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub sequence: u64,
    pub command: u32,
    pub status: u32,
    pub response_bytes: usize,
}

pub struct Scu<R: Registers, C: Timer> {
    registers: R,
    timer: C,
    fault: Option<Error>,
    sequence: u64,
    last_status: u32,
    last_receipt: Option<Receipt>,
}
impl<R: Registers, C: Timer> Scu<R, C> {
    pub fn new(registers: R, timer: C) -> Self {
        Self {
            registers,
            timer,
            fault: None,
            sequence: 0,
            last_status: 0,
            last_receipt: None,
        }
    }
    pub fn fault(&self) -> Option<Error> {
        self.fault
    }
    pub fn last_status(&self) -> u32 {
        self.last_status
    }
    pub fn last_receipt(&self) -> Option<Receipt> {
        self.last_receipt
    }
    fn poison(&mut self, error: Error) -> Error {
        self.fault = Some(error);
        error
    }
    fn read(&mut self, phase: Phase, offset: usize) -> Result<u32, Error> {
        self.registers
            .read32(offset)
            .map_err(|error| self.poison(Error::Register { phase, error }))
    }
    fn write(&mut self, phase: Phase, offset: usize, value: u32) -> Result<(), Error> {
        self.registers
            .write32(offset, value)
            .map_err(|error| self.poison(Error::Register { phase, error }))
    }
    fn status(&mut self, phase: Phase) -> Result<u32, Error> {
        let status = self.read(phase, 4)?;
        self.last_status = status;
        if status == u32::MAX {
            return Err(self.poison(Error::InvalidStatus(status)));
        }
        Ok(status)
    }
    /// Execute a real scalar IPC command. Input padding is zero and responses
    /// are copied to callers only after completion, interrupt ACK and all reads.
    /// There is no software reset that discards an unresolved hardware command.
    pub fn command(
        &mut self,
        command: u8,
        subcommand: u8,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<Receipt, Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if input.len() > 16 || output.len() > 16 || subcommand > 15 {
            return Err(Error::InvalidArgument);
        }
        let status = self.status(Phase::Preflight)?;
        if status & 1 != 0 {
            return Err(Error::Busy(status));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| self.poison(Error::SequenceExhausted))?;
        self.last_receipt = None;
        let mut words = [0; 16];
        words[..input.len()].copy_from_slice(input);
        for (index, bytes) in words
            .as_chunks::<4>()
            .0
            .iter()
            .take(input.len().div_ceil(4))
            .enumerate()
        {
            self.write(
                Phase::WriteBuffer,
                0x80 + index * 4,
                u32::from_le_bytes(*bytes),
            )?;
        }
        let control = ((input.len() as u32) << 16)
            | (u32::from(subcommand) << 12)
            | u32::from(command)
            | 0x100;
        fence(Ordering::SeqCst);
        self.write(Phase::Publish, 0, control)?;
        let start = self.timer.now_us();
        let status = loop {
            let status = self.status(Phase::Completion)?;
            if status & 1 == 0 {
                break status;
            }
            if self.timer.now_us().wrapping_sub(start) >= 10_000_000 {
                return Err(self.poison(Error::Timeout(status)));
            }
            self.timer.delay_us(100);
        };
        if status & 4 != 0 {
            self.write(Phase::InterruptAck, 4, status | 4)?;
        }
        if status & 2 != 0 {
            return Err(Error::Controller(status));
        }
        fence(Ordering::SeqCst);
        let mut response = [0; 16];
        for index in 0..output.len().div_ceil(4) {
            response[index * 4..index * 4 + 4].copy_from_slice(
                &self
                    .read(Phase::ReadBuffer, 0x90 + index * 4)?
                    .to_le_bytes(),
            );
        }
        output.copy_from_slice(&response[..output.len()]);
        let receipt = Receipt {
            sequence: self.sequence,
            command: control,
            status,
            response_bytes: output.len(),
        };
        self.last_receipt = Some(receipt);
        Ok(receipt)
    }
}
