// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2007 Alexey Starikovskiy
//! ACPI EC-SMB-HC transactions through the actual owned EC address space.
//!
//! Linux `drivers/acpi/sbshc.c` supplies the register/protocol reference. Polling
//! observes the ACPI-defined STATUS-before-PROTOCOL completion boundary instead
//! of consuming EC queries. GPE/query installation and alarm dispatch belong to
//! the platform. No firmware arbitration, namespace discovery or reset is inferred.
use super::ec;
use crate::{
    Clock,
    bus::{
        i2c::Timer,
        smbus::{self, Address, Block, Bus, Transaction},
    },
};

#[cfg(test)]
mod tests;

const PROTOCOL: u8 = 0;
const STATUS: u8 = 1;
const ADDRESS: u8 = 2;
const COMMAND: u8 = 3;
const DATA: u8 = 4;
const COUNT: u8 = 0x24;
const ALARM_ADDRESS: u8 = 0x25;
const ALARM_DATA: u8 = 0x26;
const REGISTER_BYTES: u8 = 0x28;
const DONE: u8 = 0x80;
const ALARM: u8 = 0x40;
const CODE: u8 = 0x1f;
const PEC: u8 = 0x80;
const RESERVED_STATUS: u8 = 0x20;

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum Protocol {
    SendByte = 4,
    ReceiveByte = 5,
    WriteByte = 6,
    ReadByte = 7,
    WriteWord = 8,
    ReadWord = 9,
    WriteBlock = 10,
    ReadBlock = 11,
    ProcessCall = 12,
}

/// Actual EC byte transactions, including their original failure evidence.
/// # Safety
/// These are ordered accesses to the same retained, exclusively owned native
/// EC/reset epoch. A successful write acknowledges the EC's actual byte effect;
/// errors may follow an effect. This provider establishes byte-level EC
/// arbitration only. Host::claim separately requires the caller's actual
/// whole-mailbox firmware/AML ownership grant across a host operation.
pub unsafe trait EcAccess {
    fn read(&mut self, address: u8) -> Result<u8, ec::Error>;
    fn write(&mut self, address: u8, value: u8) -> Result<(), ec::Error>;
}

// SAFETY: Ec's construction/Registers/FirmwareLock contracts retain the actual
// EC and acknowledge each ordered byte operation; Host additionally requires
// exclusive authority over the complete EC-SMB-HC sequence.
unsafe impl<R: ec::Registers, T: Timer, G: ec::FirmwareLock> EcAccess for ec::Ec<R, T, G> {
    fn read(&mut self, address: u8) -> Result<u8, ec::Error> {
        ec::Ec::read(self, address)
    }
    fn write(&mut self, address: u8, value: u8) -> Result<(), ec::Error> {
        ec::Ec::write(self, address, value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    offset: u8,
    query: u8,
}
impl Descriptor {
    /// Decode a real ACPI0001/ACPI0005 `_EC` result, never a guessed base.
    pub fn from_ec(value: u64) -> Result<Self, ErrorKind> {
        let offset = (value >> 8) as u8;
        let query = value as u8;
        if value >> 16 != 0 || query == 0 || offset.checked_add(REGISTER_BYTES - 1).is_none() {
            return Err(ErrorKind::Configuration);
        }
        Ok(Self { offset, query })
    }
    pub fn offset(self) -> u8 {
        self.offset
    }
    pub fn query(self) -> u8 {
        self.query
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Configuration,
    Ec(ec::Error),
    Busy,
    Timeout,
    Status,
    Count(usize),
    NeedsReset,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub protocol: u8,
    pub status: u8,
    /// At least one native EC write was attempted. An error does not authorize
    /// automatic replay, including when firmware reports terminal failure.
    pub published: bool,
    /// Last actually acknowledged byte, even if that access crossed a deadline.
    pub last_read: Option<ObservedRead>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedRead {
    pub address: u8,
    pub value: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Alarm {
    /// Preserve the full wire address, including any reserved bit.
    pub raw_address: u8,
    pub data: [u8; 2],
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AlarmProgress {
    pub raw_address: Option<u8>,
    pub data: [Option<u8>; 2],
}

/// Polled host; uncertain writes/timeouts retain the actual EC owner on Drop.
pub struct Host<E: EcAccess + 'static, T: Timer + 'static = Clock> {
    owners: Option<(E, T)>,
    descriptor: Descriptor,
    timeout_us: u64,
    quarantined: bool,
    published: bool,
    protocol: u8,
    status: u8,
    error: Option<Error>,
    alarm: AlarmProgress,
    last_read: Option<ObservedRead>,
}
impl<E: EcAccess + 'static, T: Timer + 'static> Host<E, T> {
    /// # Safety
    /// Actual ACPI0001/ACPI0005 identity and its `_EC` result were evaluated
    /// under the retained namespace/resource owner. Own the matching live EC,
    /// all host registers and firmware/AML arbitration across whole operations,
    /// not just individual EC bytes. No competing host command or ALARM handler
    /// may modify the mailbox. Existing native queries remain the platform's
    /// responsibility; this owner does not install or consume them. Timer is an
    /// actually advancing, qualified monotonic source. Providers own their
    /// retained resources; borrowed nonstatic owners cannot satisfy quarantine.
    /// Process/deferred context.
    pub unsafe fn claim(
        space: E,
        timer: T,
        descriptor: Descriptor,
        timeout_us: u64,
    ) -> Result<Self, (ErrorKind, E, T)> {
        if timeout_us == 0 || timeout_us >= (1u64 << 63) {
            return Err((ErrorKind::Configuration, space, timer));
        }
        Ok(Self {
            owners: Some((space, timer)),
            descriptor,
            timeout_us,
            quarantined: false,
            published: false,
            protocol: 0,
            status: 0,
            error: None,
            alarm: AlarmProgress::default(),
            last_read: None,
        })
    }
    pub fn needs_reset(&self) -> bool {
        self.quarantined
    }
    pub fn last_error(&self) -> Option<Error> {
        self.error
    }
    pub fn alarm_progress(&self) -> AlarmProgress {
        self.alarm
    }
    /// Only an unquarantined host has completed every operation it published.
    pub fn release(mut self) -> Result<(E, T), Self> {
        if self.quarantined {
            return Err(self);
        }
        Ok(self.owners.take().unwrap())
    }
    fn start(&mut self) -> Result<u64, ErrorKind> {
        if self.quarantined {
            return Err(ErrorKind::NeedsReset);
        }
        self.published = false;
        self.protocol = 0;
        self.status = 0;
        self.error = None;
        self.last_read = None;
        Ok(self.owners.as_ref().unwrap().1.now_us())
    }
    fn deadline(&self, start: u64) -> Result<(), ErrorKind> {
        if self.owners.as_ref().unwrap().1.now_us().wrapping_sub(start) >= self.timeout_us {
            Err(ErrorKind::Timeout)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, start: u64, register: u8) -> Result<u8, ErrorKind> {
        self.deadline(start)?;
        let value = self
            .owners
            .as_mut()
            .unwrap()
            .0
            .read(self.descriptor.offset + register)
            .map_err(ErrorKind::Ec)?;
        // Preserve actual acknowledged evidence before checking elapsed time.
        // A deadline never authorizes publishing the caller's read output.
        self.last_read = Some(ObservedRead {
            address: self.descriptor.offset + register,
            value,
        });
        match register {
            PROTOCOL => self.protocol = value,
            STATUS => self.status = value,
            ALARM_ADDRESS => self.alarm.raw_address = Some(value),
            ALARM_DATA => self.alarm.data[0] = Some(value),
            offset if offset == ALARM_DATA + 1 => self.alarm.data[1] = Some(value),
            _ => {}
        }
        self.deadline(start)?;
        Ok(value)
    }
    fn write(&mut self, start: u64, register: u8, value: u8) -> Result<(), ErrorKind> {
        self.deadline(start)?;
        self.published = true;
        self.owners
            .as_mut()
            .unwrap()
            .0
            .write(self.descriptor.offset + register, value)
            .map_err(ErrorKind::Ec)?;
        self.deadline(start)
    }
    fn finish<R>(&mut self, result: Result<R, ErrorKind>) -> Result<R, Error> {
        result.map_err(|kind| {
            let (native_published, uncertain_ec) = match kind {
                ErrorKind::Ec(error) => (
                    error.published,
                    error.published || error.lock_release_failed || error.burst_cleanup_failed,
                ),
                _ => (false, false),
            };
            let error = Error {
                kind,
                protocol: self.protocol,
                status: self.status,
                published: self.published || native_published,
                last_read: self.last_read,
            };
            let terminal_error = matches!(kind, ErrorKind::Status)
                && self.protocol == 0
                && self.status & (DONE | RESERVED_STATUS) == 0
                && matches!(self.status & CODE, 7 | 0x10..=0x13 | 0x17..=0x1a | 0x1f);
            // A fully observed firmware NACK/access-denied/etc. completion is
            // not uncertain host execution. Return its actual error without
            // automatically replaying it or permanently disabling this host.
            self.quarantined |= uncertain_ec || (self.published && !terminal_error);
            if self.error.is_none() {
                self.error = Some(error);
            }
            error
        })
    }
    fn idle(&mut self, start: u64) -> Result<(), ErrorKind> {
        self.protocol = self.read(start, PROTOCOL)?;
        if self.protocol != 0 {
            return Err(ErrorKind::Busy);
        }
        Ok(())
    }
    fn execute(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), ErrorKind> {
        let start = self.start()?;
        // Preflight all caller input before any actual EC access.
        if let Transaction::WriteBlock { data, .. } = &transaction
            && !(1..=smbus::MAX_BLOCK).contains(&data.len())
        {
            return Err(ErrorKind::Count(data.len()));
        }
        self.idle(start)?;
        let (protocol, command, payload, count) = match &transaction {
            Transaction::SendByte(value) => (Protocol::SendByte, *value, &[][..], false),
            Transaction::ReceiveByte(_) => (Protocol::ReceiveByte, 0, &[][..], false),
            Transaction::WriteByte { command, .. } => {
                (Protocol::WriteByte, *command, &[][..], false)
            }
            Transaction::ReadByte { command, .. } => (Protocol::ReadByte, *command, &[][..], false),
            Transaction::WriteWord { command, .. } => {
                (Protocol::WriteWord, *command, &[][..], false)
            }
            Transaction::ReadWord { command, .. } => (Protocol::ReadWord, *command, &[][..], false),
            Transaction::WriteBlock { command, data } => {
                (Protocol::WriteBlock, *command, *data, true)
            }
            Transaction::ReadBlock { command, .. } => {
                (Protocol::ReadBlock, *command, &[][..], false)
            }
            Transaction::ProcessCall { command, .. } => {
                (Protocol::ProcessCall, *command, &[][..], false)
            }
        };
        if protocol != Protocol::ReceiveByte {
            self.write(start, COMMAND, command)?;
        }
        match &transaction {
            Transaction::WriteByte { data, .. } => self.write(start, DATA, *data)?,
            Transaction::WriteWord { data, .. }
            | Transaction::ProcessCall { request: data, .. } => {
                for (index, byte) in data.to_le_bytes().iter().enumerate() {
                    self.write(start, DATA + index as u8, *byte)?;
                }
            }
            _ => {}
        }
        for (index, byte) in payload.iter().enumerate() {
            self.write(start, DATA + index as u8, *byte)?;
        }
        if count {
            self.write(start, COUNT, payload.len() as u8)?;
        }
        self.write(start, ADDRESS, address.get() << 1)?;
        self.write(start, PROTOCOL, protocol as u8 | if pec { PEC } else { 0 })?;
        // ACPI requires the controller to publish STATUS before clearing
        // PROTOCOL. Immediate completion is legal; old DONE alone is not proof.
        loop {
            self.protocol = self.read(start, PROTOCOL)?;
            if self.protocol == 0 {
                break;
            }
            self.owners.as_ref().unwrap().1.relax();
        }
        self.status = self.read(start, STATUS)?;
        if self.status & CODE != 0 || self.status & DONE == 0 || self.status & RESERVED_STATUS != 0
        {
            return Err(ErrorKind::Status);
        }
        let mut bytes = [0; smbus::MAX_BLOCK];
        let length = match transaction {
            Transaction::ReceiveByte(_) | Transaction::ReadByte { .. } => 1,
            Transaction::ReadWord { .. } | Transaction::ProcessCall { .. } => 2,
            Transaction::ReadBlock { .. } => {
                let length = self.read(start, COUNT)?;
                if !(1..=smbus::MAX_BLOCK).contains(&usize::from(length)) {
                    return Err(ErrorKind::Count(usize::from(length)));
                }
                usize::from(length)
            }
            _ => 0,
        };
        for (index, byte) in bytes[..length].iter_mut().enumerate() {
            *byte = self.read(start, DATA + index as u8)?;
        }
        match transaction {
            Transaction::ReceiveByte(data) | Transaction::ReadByte { data, .. } => *data = bytes[0],
            Transaction::ReadWord { data, .. }
            | Transaction::ProcessCall { response: data, .. } => {
                *data = u16::from_le_bytes([bytes[0], bytes[1]])
            }
            Transaction::ReadBlock { data, .. } => {
                *data = Block::from_slice(&bytes[..length]).unwrap()
            }
            _ => {}
        }
        Ok(())
    }
    /// Read and acknowledge one real hardware alarm. Retain partial evidence on
    /// an EC failure; after a failed ACK it is never automatically retried.
    pub fn poll_alarm(&mut self) -> Result<Option<Alarm>, Error> {
        let result = (|| {
            let start = self.start()?;
            self.idle(start)?;
            self.status = self.read(start, STATUS)?;
            if self.status & ALARM == 0 {
                return Ok(None);
            }
            self.alarm = AlarmProgress::default();
            let address = self.read(start, ALARM_ADDRESS)?;
            self.alarm.raw_address = Some(address);
            let first = self.read(start, ALARM_DATA)?;
            self.alarm.data[0] = Some(first);
            let second = self.read(start, ALARM_DATA + 1)?;
            self.alarm.data[1] = Some(second);
            self.write(start, STATUS, 0)?;
            // A new alarm can arrive immediately after ACK; do not mistake it
            // for a failed ACK or overwrite its mailbox with a replay.
            Ok(Some(Alarm {
                raw_address: address,
                data: [first, second],
            }))
        })();
        self.finish(result)
    }
}
impl<E: EcAccess + 'static, T: Timer + 'static> Bus for Host<E, T> {
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), smbus::Error> {
        let result = self.execute(address, transaction, pec);
        self.finish(result).map_err(|error| smbus::Error {
            kind: match error.kind {
                ErrorKind::Configuration => smbus::ErrorKind::InvalidConfiguration,
                ErrorKind::Busy => smbus::ErrorKind::Busy,
                ErrorKind::Timeout => smbus::ErrorKind::Timeout(smbus::Phase::Completion),
                ErrorKind::Count(value) => smbus::ErrorKind::InvalidBlockLength(value),
                ErrorKind::NeedsReset => smbus::ErrorKind::NeedsReset,
                ErrorKind::Status => smbus::ErrorKind::Device,
                ErrorKind::Ec(_) => smbus::ErrorKind::Failed,
            },
            status: error.status,
            recovery: smbus::Recovery::NotAttempted,
        })
    }
}
impl<E: EcAccess + 'static, T: Timer + 'static> Drop for Host<E, T> {
    fn drop(&mut self) {
        if self.quarantined
            && let Some(owners) = self.owners.take()
        {
            core::mem::forget(owners);
        }
    }
}
