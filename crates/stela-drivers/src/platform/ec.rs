// SPDX-License-Identifier: GPL-2.0-or-later
//! ACPI embedded-controller byte transactions and operation-region access.
//!
//! The platform must supply the actual PNP0C09/ECDT resources, firmware lock
//! policy and exclusive native ownership. This is a polled engine, not GPE
//! installation, AML `_Qxx` dispatch or vendor-specific EC RAM interpretation.
//! Commands follow pinned Linux `drivers/acpi/ec.c`; see `THIRD_PARTY.md`.
use crate::{Clock, bus::i2c::Timer};

const OBF: u8 = 1;
const IBF: u8 = 1 << 1;
const BURST: u8 = 1 << 4;
const SCI: u8 = 1 << 5;
const READ: u8 = 0x80;
const WRITE: u8 = 0x81;
const BURST_ENABLE: u8 = 0x82;
const BURST_DISABLE: u8 = 0x83;
const QUERY: u8 = 0x84;
const BURST_ACK: u8 = 0x90;
const ADDRESS_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

/// Ordered accesses to the exclusively owned command/status and data registers.
/// An error on a write can follow its hardware effect; it never permits replay.
pub trait Registers {
    fn status(&mut self) -> Result<u8, IoError>;
    fn read_data(&mut self) -> Result<u8, IoError>;
    fn command(&mut self, value: u8) -> Result<(), IoError>;
    fn write_data(&mut self, value: u8) -> Result<(), IoError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockError;

/// Firmware arbitration for the entire operation, including burst cleanup.
/// A `_GLK` EC requires the real ACPI global lock, not a local Rust mutex.
pub trait FirmwareLock {
    fn acquire(&mut self, timeout_us: u64) -> Result<(), LockError>;
    fn release(&mut self) -> Result<(), LockError>;
}

/// Only for a firmware EC explicitly not requiring the ACPI global lock.
pub struct NoGlobalLock(());

impl NoGlobalLock {
    /// # Safety
    /// The observed EC `_GLK` policy does not require a global lock, and the
    /// platform excludes concurrent native, firmware and AML EC transactions.
    pub unsafe fn exclusively_owned() -> Self {
        Self(())
    }
}

impl FirmwareLock for NoGlobalLock {
    fn acquire(&mut self, _timeout_us: u64) -> Result<(), LockError> {
        Ok(())
    }
    fn release(&mut self) -> Result<(), LockError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// One bound for the complete access, rather than a fresh bound per byte.
    pub timeout_us: u64,
    pub lock_timeout_us: u64,
    /// Independent bound for disabling burst after a failed region operation.
    pub recovery_timeout_us: u64,
    /// Guard between EC accesses in polling mode; zero is an explicit board
    /// policy, not automatic detection of a fast controller.
    pub polling_guard_us: u64,
    /// Request and acknowledge burst mode around multi-byte region accesses.
    pub burst: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_us: 500_000,
            // Linux calls the millisecond ACPICA API with 1000.
            lock_timeout_us: 1_000_000,
            recovery_timeout_us: 50_000,
            polling_guard_us: 550,
            burst: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Command,
    Input,
    Output,
    Completion,
    Burst,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidConfiguration,
    InvalidRegion,
    FirmwareLock,
    Io,
    Busy,
    Timeout(Phase),
    BurstAcknowledgement(u8),
    NeedsReset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub status: u8,
    /// At least one command write was attempted; its effect may be uncertain.
    pub published: bool,
    pub lock_release_failed: bool,
    pub burst_cleanup_failed: bool,
}

/// Native port register access. Construction never guesses standard port 62/66.
pub struct PortIo {
    data: u16,
    command: u16,
}

impl PortIo {
    /// # Safety
    /// Ports are the actual EC resources, decoded/powered after ExitBootServices,
    /// caller has native I/O privilege, and this object exclusively owns them.
    /// The matching firmware arbitration must remain valid until EC retirement.
    pub unsafe fn claim(data: u16, command: u16) -> Result<Self, Error> {
        if data == command {
            return Err(Error {
                kind: ErrorKind::InvalidConfiguration,
                status: 0,
                published: false,
                lock_release_failed: false,
                burst_cleanup_failed: false,
            });
        }
        Ok(Self { data, command })
    }
    fn read(port: u16) -> u8 {
        let value;
        // SAFETY: only claim's privileged, exclusively owned EC ports reach here.
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
        }
        value
    }
    fn write(port: u16, value: u8) {
        // SAFETY: same exclusive native port contract as read.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
        }
    }
}
impl Registers for PortIo {
    fn status(&mut self) -> Result<u8, IoError> {
        Ok(Self::read(self.command))
    }
    fn read_data(&mut self) -> Result<u8, IoError> {
        Ok(Self::read(self.data))
    }
    fn command(&mut self, value: u8) -> Result<(), IoError> {
        Self::write(self.command, value);
        Ok(())
    }
    fn write_data(&mut self, value: u8) -> Result<(), IoError> {
        Self::write(self.data, value);
        Ok(())
    }
}

pub struct Ec<R = PortIo, T = Clock, G = NoGlobalLock> {
    registers: R,
    timer: T,
    gate: G,
    config: Config,
    ready: bool,
    status: u8,
    published: bool,
    last_access: Option<u64>,
}

impl<R: Registers, T: Timer, G: FirmwareLock> Ec<R, T, G> {
    pub fn new(registers: R, timer: T, gate: G, config: Config) -> Result<Self, Error> {
        if config.timeout_us == 0
            || config.lock_timeout_us == 0
            || config.recovery_timeout_us == 0
            || config.polling_guard_us >= config.timeout_us
            || config.polling_guard_us >= config.recovery_timeout_us
        {
            return Err(Error {
                kind: ErrorKind::InvalidConfiguration,
                status: 0,
                published: false,
                lock_release_failed: false,
                burst_cleanup_failed: false,
            });
        }
        Ok(Self {
            registers,
            timer,
            gate,
            config,
            ready: true,
            status: 0,
            published: false,
            last_access: None,
        })
    }

    pub fn needs_reset(&self) -> bool {
        !self.ready
    }

    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            status: self.status,
            published: self.published,
            lock_release_failed: false,
            burst_cleanup_failed: false,
        }
    }

    fn io<V>(&mut self, result: Result<V, IoError>) -> Result<V, Error> {
        result.map_err(|_| self.error(ErrorKind::Io))
    }

    fn expired(&self, start: u64) -> bool {
        self.timer.now_us().wrapping_sub(start) >= self.config.timeout_us
    }

    fn guard(&self, start: u64, phase: Phase) -> Result<(), Error> {
        while self.last_access.is_some_and(|last| {
            self.timer.now_us().wrapping_sub(last) < self.config.polling_guard_us
        }) {
            if self.expired(start) {
                return Err(self.error(ErrorKind::Timeout(phase)));
            }
            self.timer.relax();
        }
        if self.expired(start) {
            return Err(self.error(ErrorKind::Timeout(phase)));
        }
        Ok(())
    }

    fn wait(&mut self, start: u64, mask: u8, expected: u8, phase: Phase) -> Result<u8, Error> {
        loop {
            self.guard(start, phase)?;
            let status = self.registers.status();
            self.status = self.io(status)?;
            if self.status & mask == expected {
                return Ok(self.status);
            }
            if self.expired(start) {
                return Err(self.error(ErrorKind::Timeout(phase)));
            }
            self.timer.relax();
        }
    }

    fn transfer(
        &mut self,
        start: u64,
        command: u8,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        self.wait(start, IBF, 0, Phase::Command)?;
        // Mark before writing: a fallible provider can report an uncertain write.
        self.published = true;
        let result = self.registers.command(command);
        self.io(result)?;
        self.last_access = Some(self.timer.now_us());
        for &byte in input {
            self.wait(start, IBF, 0, Phase::Input)?;
            let result = self.registers.write_data(byte);
            self.io(result)?;
            self.last_access = Some(self.timer.now_us());
        }
        for byte in &mut *output {
            self.wait(start, OBF, OBF, Phase::Output)?;
            let result = self.registers.read_data();
            *byte = self.io(result)?;
            self.last_access = Some(self.timer.now_us());
        }
        if output.is_empty() {
            self.wait(start, IBF, 0, Phase::Completion)?;
        }
        Ok(())
    }

    fn owned<V>(
        &mut self,
        access: impl FnOnce(&mut Self, u64) -> Result<V, Error>,
    ) -> Result<V, Error> {
        self.published = false;
        if !self.ready {
            return Err(self.error(ErrorKind::NeedsReset));
        }
        self.gate
            .acquire(self.config.lock_timeout_us)
            .map_err(|_| self.error(ErrorKind::FirmwareLock))?;
        let start = self.timer.now_us();
        let result = (|| {
            let status = self.registers.status();
            self.status = self.io(status)?;
            // Do not discard another transaction's pending output or burst.
            if self.status & (OBF | BURST) != 0 {
                return Err(self.error(ErrorKind::Busy));
            }
            access(self, start)
        })();
        if result.is_err() && self.published {
            self.ready = false;
        }
        if self.gate.release().is_err() {
            self.ready = false;
            let mut error = result
                .err()
                .unwrap_or_else(|| self.error(ErrorKind::FirmwareLock));
            error.lock_release_failed = true;
            return Err(error);
        }
        result
    }

    pub fn read(&mut self, address: u8) -> Result<u8, Error> {
        self.owned(|ec, start| {
            let mut data = [0];
            ec.transfer(start, READ, &[address], &mut data)?;
            Ok(data[0])
        })
    }

    pub fn write(&mut self, address: u8, value: u8) -> Result<(), Error> {
        self.owned(|ec, start| ec.transfer(start, WRITE, &[address, value], &mut []))
    }

    /// Consume one actual QR_EC response; zero means no pending query method.
    /// The returned nonzero value names `_Qxx`; dispatch belongs to deferred AML
    /// work after this call releases the firmware lock, never inside this call.
    pub fn query(&mut self) -> Result<Option<u8>, Error> {
        self.owned(|ec, start| {
            let mut value = [0];
            ec.transfer(start, QUERY, &[], &mut value)?;
            Ok((value[0] != 0).then_some(value[0]))
        })
    }

    pub fn event_pending(&mut self) -> Result<bool, Error> {
        self.owned(|ec, _| Ok(ec.status & SCI != 0))
    }

    fn region(address: u64, width: u32) -> Result<(u8, usize), Error> {
        let bytes = match width {
            8 => 1,
            16 => 2,
            32 => 4,
            64 => 8,
            _ => {
                return Err(Error {
                    kind: ErrorKind::InvalidRegion,
                    status: 0,
                    published: false,
                    lock_release_failed: false,
                    burst_cleanup_failed: false,
                });
            }
        };
        if address
            .checked_add(bytes as u64)
            .is_none_or(|end| end > ADDRESS_BYTES as u64)
        {
            return Err(Error {
                kind: ErrorKind::InvalidRegion,
                status: 0,
                published: false,
                lock_release_failed: false,
                burst_cleanup_failed: false,
            });
        }
        Ok((address as u8, bytes))
    }

    fn region_access(&mut self, address: u8, bytes: &mut [u8], write: bool) -> Result<(), Error> {
        self.owned(|ec, start| {
            let burst = ec.config.burst && bytes.len() > 1;
            let result = (|| {
                if burst {
                    let mut ack = [0];
                    ec.transfer(start, BURST_ENABLE, &[], &mut ack)?;
                    if ack[0] != BURST_ACK {
                        return Err(ec.error(ErrorKind::BurstAcknowledgement(ack[0])));
                    }
                    ec.wait(start, BURST, BURST, Phase::Burst)?;
                }
                for (offset, byte) in bytes.iter_mut().enumerate() {
                    let address = address + offset as u8;
                    if write {
                        ec.transfer(start, WRITE, &[address, *byte], &mut [])?;
                    } else {
                        ec.transfer(start, READ, &[address], core::slice::from_mut(byte))?;
                    }
                }
                Ok(())
            })();
            // A failed region access still owns burst state. Attempt a bounded
            // disable before releasing firmware arbitration; preserve the first
            // error, and quarantine any uncertain published transaction.
            if burst && ec.published {
                let bound = ec.config.timeout_us;
                let cleanup_start = if result.is_err() {
                    ec.config.timeout_us = ec.config.recovery_timeout_us;
                    ec.timer.now_us()
                } else {
                    start
                };
                let cleanup = (|| {
                    ec.transfer(cleanup_start, BURST_DISABLE, &[], &mut [])?;
                    ec.wait(cleanup_start, BURST, 0, Phase::Burst)?;
                    ec.wait(cleanup_start, OBF, 0, Phase::Completion)?;
                    Ok(())
                })();
                ec.config.timeout_us = bound;
                if let Err(cleanup_error) = cleanup {
                    let mut error = result.err().unwrap_or(cleanup_error);
                    error.burst_cleanup_failed = true;
                    return Err(error);
                }
            }
            result
        })
    }

    pub fn read_region(&mut self, address: u64, width: u32) -> Result<u64, Error> {
        let (address, count) = Self::region(address, width)?;
        let mut bytes = [0; 8];
        self.region_access(address, &mut bytes[..count], false)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Multi-byte EC writes are consecutive byte commands, not atomic hardware
    /// updates. An error preserves publication uncertainty and forbids replay.
    pub fn write_region(&mut self, address: u64, width: u32, value: u64) -> Result<(), Error> {
        let (address, count) = Self::region(address, width)?;
        self.region_access(address, &mut value.to_le_bytes()[..count], true)
    }
}

#[cfg(test)]
mod tests;
