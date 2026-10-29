// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
// AMD MP2 I2C protocol adapted from Linux; Authors: Shyam Sundar S K,
// Elie Morisse, Nehal Bakulchandra Shah. See ../THIRD_PARTY.md.
//! Serialized AMD 1022:15e6 MP2 firmware mailbox and AMDI0011 bus engines.
//!
//! The two buses share one payload mailbox and are owned by one Controller.
//! Requests are individual firmware messages. Combined repeated-START semantics
//! are not established by the donor and are not invented here.
use super::{Address, Clock, Timer};
use crate::bus::dma::DmaBuffer;
use core::sync::atomic::{Ordering, fence};

const COMMAND: [usize; 2] = [0x10500, 0x10504];
const PAYLOAD: usize = 0x10508;
const EVENT: [usize; 2] = [0x10684, 0x10688];
const INTERRUPT: usize = 0x10690;
const INLINE: usize = 32;
pub const MAX_LENGTH: usize = 4095;
pub const VENDOR: u16 = 0x1022;
pub const DEVICE: u16 = 0x15e6;
pub const ACPI_ID: &str = "AMDI0011";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;
/// Ordered access to the MP2 BAR2 registers and byte payload window.
/// # Safety
/// The provider keeps the exclusively owned PCI function, powered BAR2
/// UC mapping and firmware/reset epoch. No other CPU, firmware/AML driver or IRQ
/// handler accesses either bus or mailbox. It grants ordered volatile accesses;
/// errors may follow effects. It must remain valid when leaked.
pub unsafe trait Registers {
    fn read32(&mut self, offset: usize) -> Result<u32, IoError>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError>;
    fn read_payload(&mut self, bytes: &mut [u8]) -> Result<(), IoError>;
    fn write_payload(&mut self, bytes: &[u8]) -> Result<(), IoError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Speed {
    Khz100 = 0,
    Khz400 = 1,
    Mhz1 = 2,
    Mhz1_4 = 3,
    Mhz3_4 = 4,
}
impl Speed {
    /// Largest source-defined speed not exceeding the peripheral/board
    /// limit. An absent/too-low limit is refused, rather than guessed as 400kHz.
    pub fn from_limit(hz: u32) -> Result<Self, ErrorKind> {
        match hz {
            3_400_000.. => Ok(Self::Mhz3_4),
            1_400_000.. => Ok(Self::Mhz1_4),
            1_000_000.. => Ok(Self::Mhz1),
            400_000.. => Ok(Self::Khz400),
            100_000.. => Ok(Self::Khz100),
            _ => Err(ErrorKind::Configuration),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusId(u8);
impl BusId {
    /// The observed AMDI0011 `_UID`, with a separately established binding to
    /// this PCI function. Two MP2 devices cannot be associated by guesswork.
    pub fn from_uid(uid: u64) -> Result<Self, ErrorKind> {
        if uid < 2 {
            Ok(Self(uid as u8))
        } else {
            Err(ErrorKind::Configuration)
        }
    }
    pub fn get(self) -> u8 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Command {
    Read = 0,
    Write = 1,
    Enable = 2,
    Disable = 3,
}
impl Command {
    fn status(self) -> u32 {
        (self as u32) * 2
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Configuration,
    InvalidAddress,
    Length(usize),
    NotEnabled,
    Io,
    /// An unsolicited or stale response was present before publication.
    Pending,
    Timeout,
    /// Raw response is preserved even when the firmware reports failure.
    Response,
    NeedsReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub bus: u8,
    pub command: Option<u32>,
    pub event: Option<u32>,
    /// A mailbox or command write was attempted; it must not be replayed.
    pub published: bool,
}

/// Exclusive owner for both adapters, the shared mailbox and one DMA
/// bounce allocation. A timed-out command has no reset primitive in this
/// protocol: the whole owner is quarantined, including the other bus.
pub struct Controller<R: Registers + 'static, T: Timer + 'static = Clock> {
    owners: Option<(R, T, DmaBuffer)>,
    speeds: [Option<Speed>; 2],
    enabled: [bool; 2],
    timeout_us: u64,
    failed: Option<Error>,
    observed: Option<u32>,
    command: Option<u32>,
    published: bool,
    started: u64,
}
impl<R: Registers + 'static, T: Timer + 'static> Controller<R, T> {
    /// # Safety
    /// Registers keep the exclusive 1022:15e6 BAR2 owner. Both firmware
    /// buses are stopped and no old DMA/request/IRQ callback is outstanding.
    /// The platform masks PCI interrupt delivery for the complete polled
    /// lifetime; clearing the source event/INTEN registers is not a PCI mask.
    /// The supplied private bounce allocation is coherent, reachable by this
    /// requester, not shared, and remains pinned for the rest of boot.
    /// Speed inputs are observed board/peripheral limits; None means no adapter
    /// is granted. The clock is calibrated, monotonic and advancing.
    pub unsafe fn claim(
        registers: R,
        timer: T,
        buffer: DmaBuffer,
        speeds: [Option<Speed>; 2],
        timeout_us: u64,
    ) -> Result<Self, (ErrorKind, (R, T, DmaBuffer))> {
        if buffer.len() < MAX_LENGTH
            || timeout_us == 0
            || timer.check_duration(timeout_us).is_err()
            || speeds == [None, None]
        {
            return Err((ErrorKind::Configuration, (registers, timer, buffer)));
        }
        Ok(Self {
            owners: Some((registers, timer, buffer)),
            speeds,
            enabled: [false; 2],
            timeout_us,
            failed: None,
            observed: None,
            command: None,
            published: false,
            started: 0,
        })
    }
    pub fn failure(&self) -> Option<Error> {
        self.failed
    }
    pub fn is_enabled(&self, bus: BusId) -> bool {
        self.enabled[usize::from(bus.0)]
    }
    fn error(&self, bus: BusId, kind: ErrorKind) -> Error {
        Error {
            kind,
            bus: bus.0,
            command: self.command,
            event: self.observed,
            published: self.published,
        }
    }
    fn io(&mut self, bus: BusId, result: Result<(), IoError>) -> Result<(), Error> {
        result.map_err(|_| self.error(bus, ErrorKind::Io))
    }
    fn write32(&mut self, bus: BusId, offset: usize, value: u32) -> Result<(), Error> {
        self.published = true;
        let result = self.owners.as_mut().unwrap().0.write32(offset, value);
        self.io(bus, result)?;
        self.deadline(bus)
    }
    fn read32(&mut self, bus: BusId, offset: usize) -> Result<u32, Error> {
        let value = self
            .owners
            .as_mut()
            .unwrap()
            .0
            .read32(offset)
            .map_err(|_| self.error(bus, ErrorKind::Io))?;
        if EVENT.contains(&offset) {
            self.observed = Some(value);
        }
        self.deadline(bus)?;
        Ok(value)
    }
    fn deadline(&self, bus: BusId) -> Result<(), Error> {
        if self.owners.as_ref().unwrap().1.elapsed_us(self.started) >= self.timeout_us {
            Err(self.error(bus, ErrorKind::Timeout))
        } else {
            Ok(())
        }
    }
    fn prepare(&mut self, bus: BusId) -> Result<Speed, Error> {
        if self.failed.is_some() {
            return Err(self.error(bus, ErrorKind::NeedsReset));
        }
        self.command = None;
        self.observed = None;
        self.published = false;
        self.started = self.owners.as_ref().unwrap().1.start();
        self.speeds[usize::from(bus.0)].ok_or_else(|| self.error(bus, ErrorKind::Configuration))
    }
    fn preflight(&mut self, bus: BusId) -> Result<(), Error> {
        // A response cannot be silently consumed or mistaken for our new ACK.
        for offset in EVENT {
            let event = self.read32(bus, offset)?;
            if event != 0 {
                self.observed = Some(event);
                return Err(self.error(bus, ErrorKind::Pending));
            }
        }
        Ok(())
    }
    fn execute(
        &mut self,
        bus: BusId,
        cmd: Command,
        speed: Speed,
        address: u8,
        length: usize,
    ) -> Result<(), Error> {
        let inline = matches!(cmd, Command::Read | Command::Write) && length <= INLINE;
        let command = cmd as u32
            | u32::from(bus.0) << 4
            | u32::from(address) << 8
            | (length as u32) << 16
            | (speed as u32) << 28
            | u32::from(inline) << 31;
        self.command = Some(command);
        if length > INLINE {
            let physical = self.owners.as_ref().unwrap().2.bus_address();
            // Linux's writeq is explicitly low then high on this platform.
            self.write32(bus, PAYLOAD, physical as u32)?;
            self.write32(bus, PAYLOAD + 4, (physical >> 32) as u32)?;
        }
        fence(Ordering::SeqCst);
        self.deadline(bus)?;
        self.write32(bus, COMMAND[usize::from(bus.0)], command)?;
        loop {
            let event = self.read32(bus, EVENT[usize::from(bus.0)])?;
            if event != 0 {
                self.observed = Some(event);
            }
            self.deadline(bus)?;
            if event != 0 {
                // Match the completion before touching caller output.
                let response = event & 3;
                let status = (event >> 2) & 31;
                let event_bus = (event >> 8) & 15;
                let data_ok = !matches!(cmd, Command::Read | Command::Write)
                    || ((event >> 12) & 4095 == length as u32
                        && event >> 24 == u32::from(address)
                        && ((event >> 7) & 1 != 0) == inline);
                if response != 1
                    || status != cmd.status()
                    || event_bus != u32::from(bus.0)
                    || !data_ok
                {
                    return Err(self.error(bus, ErrorKind::Response));
                }
                self.write32(bus, EVENT[usize::from(bus.0)], 0)?;
                self.write32(bus, INTERRUPT, 0)?;
                fence(Ordering::SeqCst);
                self.deadline(bus)?;
                return Ok(());
            }
            self.owners.as_ref().unwrap().1.relax();
        }
    }
    fn finish(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        if let Err(error) = result {
            // No donor timeout-unmap/retry: firmware can still own DMA/mailbox.
            self.failed = Some(error);
            self.enabled = [false; 2];
        }
        result
    }
    pub fn enable(&mut self, bus: BusId) -> Result<(), Error> {
        let speed = self.prepare(bus)?;
        if self.is_enabled(bus) {
            return Ok(());
        }
        let result = self
            .preflight(bus)
            .and_then(|()| self.execute(bus, Command::Enable, speed, 0, 0));
        self.finish(result)?;
        self.enabled[usize::from(bus.0)] = true;
        Ok(())
    }
    pub fn disable(&mut self, bus: BusId) -> Result<(), Error> {
        let speed = self.prepare(bus)?;
        if !self.is_enabled(bus) {
            return Ok(());
        }
        let result = self
            .preflight(bus)
            .and_then(|()| self.execute(bus, Command::Disable, speed, 0, 0));
        self.finish(result)?;
        self.enabled[usize::from(bus.0)] = false;
        Ok(())
    }
    fn data_preflight(
        &mut self,
        bus: BusId,
        address: Address,
        length: usize,
    ) -> Result<(Speed, u8), Error> {
        let speed = self.prepare(bus)?;
        let Address::SevenBit(address @ 0x08..=0x77) = address else {
            return Err(self.error(bus, ErrorKind::InvalidAddress));
        };
        if !(1..=MAX_LENGTH).contains(&length) {
            return Err(self.error(bus, ErrorKind::Length(length)));
        }
        if !self.is_enabled(bus) {
            return Err(self.error(bus, ErrorKind::NotEnabled));
        }
        Ok((speed, address))
    }
    /// One complete firmware write. No combined repeated START is claimed.
    pub fn write(&mut self, bus: BusId, address: Address, bytes: &[u8]) -> Result<(), Error> {
        let (speed, address) = self.data_preflight(bus, address, bytes.len())?;
        let result = (|| {
            self.preflight(bus)?;
            if bytes.len() <= INLINE {
                self.published = true;
                let result = self.owners.as_mut().unwrap().0.write_payload(bytes);
                self.io(bus, result)?;
                self.deadline(bus)?;
            } else {
                self.owners.as_mut().unwrap().2.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
            }
            self.execute(bus, Command::Write, speed, address, bytes.len())
        })();
        self.finish(result)
    }
    /// Read output is committed only after a matching event and all
    /// payload accesses succeed. Partial mailbox reads stay private on errors.
    pub fn read(&mut self, bus: BusId, address: Address, bytes: &mut [u8]) -> Result<(), Error> {
        let (speed, address) = self.data_preflight(bus, address, bytes.len())?;
        let result = (|| {
            self.preflight(bus)?;
            self.execute(bus, Command::Read, speed, address, bytes.len())?;
            if bytes.len() <= INLINE {
                let mut scratch = [0; INLINE];
                let result = self
                    .owners
                    .as_mut()
                    .unwrap()
                    .0
                    .read_payload(&mut scratch[..bytes.len()]);
                self.io(bus, result)?;
                self.deadline(bus)?;
                bytes.copy_from_slice(&scratch[..bytes.len()]);
            } else {
                bytes.copy_from_slice(&self.owners.as_ref().unwrap().2.bytes()[..bytes.len()]);
            }
            Ok(())
        })();
        self.finish(result)
    }
    /// Release only after both real disable acknowledgments and no uncertain
    /// request. The kept DMA allocation itself remains boot-lifetime pinned.
    pub fn release(mut self) -> Result<(R, T, DmaBuffer), Self> {
        if self.failed.is_some() || self.enabled != [false; 2] {
            return Err(self);
        }
        Ok(self.owners.take().unwrap())
    }
}
impl<R: Registers + 'static, T: Timer + 'static> Drop for Controller<R, T> {
    fn drop(&mut self) {
        if (self.failed.is_some() || self.enabled != [false; 2])
            && let Some(owners) = self.owners.take()
        {
            core::mem::forget(owners);
        }
    }
}

#[cfg(test)]
mod tests;
