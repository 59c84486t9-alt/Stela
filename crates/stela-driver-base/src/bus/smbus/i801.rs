// SPDX-License-Identifier: GPL-2.0-or-later
//
// Adapted from Linux drivers/i2c/busses/i2c-i801.c at
// a804c5742bff224d4cb4d25dd383554d598be32b.
// SHA-256: 752d89228a166ec26ee11ccebe094896b8ded3600df9da3b998b825bf98b80d0
//
// Copyright (c) 1998 - 2002 Frodo Looijaard <frodol@dds.nl>,
// Philip Edelbrock <phil@netroedge.com>, and Mark D. Studebaker
// <mdsxyz123@yahoo.com>
// Copyright (C) 2007 - 2014 Jean Delvare <jdelvare@suse.de>
// Copyright (C) 2010 Intel Corporation,
//                    David Woodhouse <dwmw2@infradead.org>
//
//! Intel I801 host controller: polled SMBus byte, word and block transactions.
//!
//! This ports the host register sequencing, W1C discipline, block buffer and
//! BYTE_DONE handshakes. All waits, including malformed block recovery, have a
//! deadline. Failed KILL poisons the controller until a platform reset.
//!
//! There is no automatic PCI attachment: the platform must enable
//! the PCI I/O decode/host function in D0 and arbitrate ACPI AML and SMM access.
//! A device ID or an idle status bit does not prove exclusive ownership. The
//! unsafe [`PortIo::claim`] contract requires that ownership before any I/O.
//! MMIO-only devices need a separate register accessor. [`i2c_block`] adds
//! fixed-length I²C blocks with kept PCI configuration ownership and opt-in
//! hardware PEC and E32B block process calls through that owner. Raw I801 handles
//! still refuse PEC; SMBALERT remains unsupported. Host Notify follows Linux
//! `i801_enable_host_notify` and `i801_host_notify_isr`, its status polled with
//! the interrupt left disabled, as every input device here is polled.
//! The kept owner also exposes payload-free SMBus Quick without PEC.
//!
//! Read-to-acquire INUSE semantics are documented in Intel's Host Status
//! Register Address (HSTS), offset 0, Core Ultra SoC I/O Registers, ID 795260.
pub mod i2c_block;
mod pec;

use super::{Address, Block, Bus, Error, ErrorKind, MAX_BLOCK, Phase, Recovery, Transaction};
use crate::{Clock, bus::i2c::Timer};

const HOST_STATUS: u8 = 0;
const HOST_CONTROL: u8 = 2;
const HOST_COMMAND: u8 = 3;
const HOST_ADDRESS: u8 = 4;
const HOST_DATA0: u8 = 5;
const HOST_DATA1: u8 = 6;
const BLOCK_DATA: u8 = 7;
const AUX_STATUS: u8 = 12;
const AUX_CONTROL: u8 = 13;
const SLAVE_STATUS: u8 = 16;
const SLAVE_COMMAND: u8 = 17;
const NOTIFY_ADDRESS: u8 = 20;

const HOST_BUSY: u8 = 1;
const INTR: u8 = 1 << 1;
const DEV_ERR: u8 = 1 << 2;
const BUS_ERR: u8 = 1 << 3;
const FAILED: u8 = 1 << 4;
const INUSE: u8 = 1 << 6;
const BYTE_DONE: u8 = 1 << 7;
const ERROR_FLAGS: u8 = DEV_ERR | BUS_ERR | FAILED;
const STATUS_FLAGS: u8 = INTR | ERROR_FLAGS | BYTE_DONE;
const KILL: u8 = 1 << 1;
const LAST_BYTE: u8 = 1 << 5;
const START: u8 = 1 << 6;
const AUX_CRC: u8 = 1;
const AUX_BUFFER: u8 = 1 << 1;
const AUX_CRC_ERROR: u8 = 1;
const HOST_NOTIFY_STATUS: u8 = 1;
const HOST_NOTIFY_INTERRUPT: u8 = 1;
const SMBALERT_DISABLE: u8 = 1 << 2;
const HOST_ENABLED: u8 = 1;
const HOST_SMI: u8 = 1 << 1;
const HOST_I2C: u8 = 1 << 2;

const PROTOCOL_QUICK: u8 = 0;
const PROTOCOL_BYTE: u8 = 0x04;
const PROTOCOL_BYTE_DATA: u8 = 0x08;
const PROTOCOL_WORD_DATA: u8 = 0x0c;
const PROTOCOL_PROCESS_CALL: u8 = 0x10;
const PROTOCOL_BLOCK: u8 = 0x14;
const PROTOCOL_BLOCK_PROCESS_CALL: u8 = 0x1c;

/// Ordered byte access to a single exclusively owned host controller.
pub trait Registers {
    fn read8(&mut self, offset: u8) -> u8;
    fn write8(&mut self, offset: u8, value: u8);
}

/// Exact Linux I801 PCI ID match and register capabilities, not a claim that
/// firmware ownership has been acquired or that an OEM board was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerInfo {
    device: u16,
    register_bytes: u16,
    block_buffer: bool,
}

impl ControllerInfo {
    pub fn from_pci_id(vendor: u16, device: u16) -> Option<Self> {
        if vendor != 0x8086 {
            return None;
        }
        let (register_bytes, block_buffer) = match device {
            0x2413 | 0x2423 | 0x2443 => (16, false),
            0x2483 => (32, false),
            0x24c3 | 0x24d3 | 0x25a4 | 0x266a | 0x269b | 0x27da | 0x283e | 0x2930 | 0x5032
            | 0x3a30 | 0x3a60 | 0x3b30 | 0x1c22 | 0x1d22 | 0x1d70 | 0x1d71 | 0x1d72 | 0x2330
            | 0x1e22 | 0x8c22 | 0x9c22 | 0x1f3c | 0x8d22 | 0x8d7d | 0x8d7e | 0x8d7f | 0x23b0
            | 0x8ca2 | 0x9ca2 | 0x0f12 | 0x2292 | 0xa123 | 0x9d23 | 0x19df | 0x1bc9 | 0x5ad4
            | 0xa1a3 | 0xa223 | 0xa2a3 | 0x31d4 | 0xa323 | 0x9da3 | 0x18df | 0x34a3 | 0x38a3
            | 0x02a3 | 0x06a3 | 0x4b23 | 0xa0a3 | 0x43a3 | 0x4da3 | 0xa3a3 | 0x7aa3 | 0x51a3
            | 0x54a3 | 0x7a23 | 0x7e22 | 0xae22 | 0x7f23 | 0x5796 | 0x7722 | 0xe322 | 0xe422
            | 0x4d22 | 0x5827 | 0x6e23 => (32, true),
            _ => return None,
        };
        Some(Self {
            device,
            register_bytes,
            block_buffer,
        })
    }

    pub fn device_id(self) -> u16 {
        self.device
    }

    pub fn register_bytes(self) -> u16 {
        self.register_bytes
    }

    pub fn has_block_buffer(self) -> bool {
        self.block_buffer
    }

    /// Linux advertises block process calls from ICH5; ICH4 only has E32B/PEC.
    pub fn has_block_process_call(self) -> bool {
        self.block_buffer && self.device != 0x24c3
    }

    /// Linux FEATURE_HOST_NOTIFY: ICH3 (82801CA) and every later profile.
    pub fn has_host_notify(self) -> bool {
        self.device == 0x2483 || self.block_buffer
    }

    /// Exact pinned FEATURE_SMBUS_PEC profiles: ICH4 and later. This reports
    /// capability only; configuration ownership is separately required.
    pub fn has_hardware_pec(self) -> bool {
        self.block_buffer
    }
}

/// Exclusive x86 I/O port accessor. It does not change PCI configuration or
/// claim firmware resources; platform arbitration must precede construction.
pub struct PortIo {
    base: u16,
    bytes: u16,
}

impl PortIo {
    /// # Safety
    ///
    /// `base` must be the decoded SMBus I/O BAR of the controller described by
    /// `info`, in D0 with I/O decoding enabled. Caller must execute at an x86
    /// privilege level permitting IN/OUT. ACPI AML, firmware/SMM, IRQ handlers
    /// and other CPUs must have relinquished the entire window for its lifetime.
    /// The platform must arrange device/reset/lifecycle ownership; an idle
    /// HOST_BUSY bit alone does not satisfy these requirements.
    pub unsafe fn claim(base: u16, info: ControllerInfo) -> Result<Self, Error> {
        if base == 0
            || !base.is_multiple_of(info.register_bytes)
            || u32::from(base) + u32::from(info.register_bytes) > 0x1_0000
        {
            return Err(ErrorKind::InvalidPortRange.into());
        }
        Ok(Self {
            base,
            bytes: info.register_bytes,
        })
    }
}

impl Registers for PortIo {
    fn read8(&mut self, offset: u8) -> u8 {
        assert!(u16::from(offset) < self.bytes);
        let value: u8;
        // SAFETY: claim's exclusive decoded window and privilege contract.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") self.base + u16::from(offset),
                out("al") value,
                options(nostack, preserves_flags),
            );
        }
        value
    }

    fn write8(&mut self, offset: u8, value: u8) {
        assert!(u16::from(offset) < self.bytes);
        // SAFETY: claim's exclusive decoded window and privilege contract.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.base + u16::from(offset),
                in("al") value,
                options(nostack, preserves_flags),
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// One bound for the complete transaction, not a fresh bound per byte.
    pub timeout_us: u64,
    pub recovery_timeout_us: u64,
    /// Use the 32-byte buffer only where the exact PCI ID advertises it.
    /// False selects the BYTE_DONE path even on capable controllers.
    pub use_block_buffer: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_us: 200_000,
            recovery_timeout_us: 100_000,
            use_block_buffer: true,
        }
    }
}

pub struct I801<R = PortIo, T = Clock> {
    registers: R,
    timer: T,
    info: ControllerInfo,
    config: Config,
    ready: bool,
    locked: bool,
    /// SMBSLVCMD as found, kept while Host Notify is enabled.
    slave_command: Option<u8>,
}

impl<R: Registers, T: Timer> I801<R, T> {
    /// `host_configuration` is the current PCI SMBHSTCFG byte (offset 0x40),
    /// captured under the platform's exclusive ownership. Enabling the host,
    /// clearing I²C mode, power and ACPI/SMM arbitration belong to that platform.
    pub fn new(
        registers: R,
        timer: T,
        info: ControllerInfo,
        host_configuration: u8,
        config: Config,
    ) -> Result<Self, Error> {
        if config.timeout_us == 0
            || config.recovery_timeout_us == 0
            || timer.check_duration(config.timeout_us).is_err()
            || timer.check_duration(config.recovery_timeout_us).is_err()
        {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        if host_configuration & HOST_ENABLED == 0 {
            return Err(ErrorKind::HostDisabled.into());
        }
        if host_configuration & HOST_SMI != 0 {
            return Err(ErrorKind::FirmwareSmi.into());
        }
        if host_configuration & HOST_I2C != 0 {
            return Err(ErrorKind::WrongProtocolMode.into());
        }
        let mut controller = Self {
            registers,
            timer,
            info,
            config,
            ready: true,
            locked: false,
            slave_command: None,
        };
        controller.prepare()?;
        controller.release();
        Ok(controller)
    }

    fn expired(&self, start: u64, timeout: u64) -> bool {
        self.timer.elapsed_us(start) >= timeout
    }

    fn error(kind: ErrorKind, status: u8) -> Error {
        Error {
            kind,
            status,
            recovery: Recovery::NotAttempted,
        }
    }

    fn clear_modes(&mut self) {
        if self.info.block_buffer {
            let auxiliary = self.registers.read8(AUX_CONTROL);
            self.registers
                .write8(AUX_CONTROL, auxiliary & !(AUX_CRC | AUX_BUFFER));
            let crc = self.registers.read8(AUX_STATUS) & AUX_CRC_ERROR;
            if crc != 0 {
                self.registers.write8(AUX_STATUS, crc);
            }
        }
    }

    fn prepare(&mut self) -> Result<(), Error> {
        let status = self.registers.read8(HOST_STATUS);
        // Reading HSTS atomically sets INUSE after returning its old value.
        // Respect another owner's semaphore and release only one we acquired.
        if status & INUSE != 0 {
            return Err(Self::error(ErrorKind::Busy, status));
        }
        self.locked = true;
        if status & HOST_BUSY != 0 {
            self.release();
            return Err(Self::error(ErrorKind::Busy, status));
        }
        // Preserve SMBALERT; only our completion/error bits are W1C here.
        // Never write a read status byte blindly.
        self.registers.write8(HOST_STATUS, status & STATUS_FLAGS);
        let remaining = self.registers.read8(HOST_STATUS);
        if remaining & STATUS_FLAGS != 0 {
            self.release();
            return Err(Self::error(ErrorKind::StatusStuck, remaining));
        }
        self.registers.write8(HOST_CONTROL, 0);
        self.clear_modes();
        if self.info.block_buffer && self.registers.read8(AUX_CONTROL) & (AUX_CRC | AUX_BUFFER) != 0
        {
            self.release();
            return Err(Self::error(ErrorKind::BufferModeRejected, status));
        }
        Ok(())
    }

    fn release(&mut self) {
        if self.locked {
            self.registers.write8(HOST_STATUS, INUSE);
            self.locked = false;
        }
    }

    fn status_error(status: u8) -> Option<Error> {
        let kind = if status & BUS_ERR != 0 {
            ErrorKind::ArbitrationLost
        } else if status & DEV_ERR != 0 {
            ErrorKind::Device
        } else if status & FAILED != 0 {
            ErrorKind::Failed
        } else {
            return None;
        };
        Some(Self::error(kind, status))
    }

    fn wait(&mut self, start: u64, phase: Phase) -> Result<u8, Error> {
        loop {
            let status = self.registers.read8(HOST_STATUS);
            if let Some(error) = Self::status_error(status) {
                return Err(error);
            }
            // An observed completion still cannot satisfy an expired
            // transaction deadline. Keep its raw status for the caller.
            if self.expired(start, self.config.timeout_us) {
                return Err(Self::error(ErrorKind::Timeout(phase), status));
            }
            match phase {
                Phase::Completion if status & HOST_BUSY == 0 && status & INTR != 0 => {
                    return Ok(status);
                }
                Phase::ByteDone if status & BYTE_DONE != 0 => return Ok(status),
                Phase::ByteDone if status & HOST_BUSY == 0 && status & INTR != 0 => {
                    return Err(Self::error(ErrorKind::UnexpectedCompletion, status));
                }
                _ => {}
            }
            self.timer.relax();
        }
    }

    /// Kill only a transaction we started. A successful kill must both clear
    /// HOST_BUSY and set FAILED; a zero status is not proof that KILL worked.
    fn finish(&mut self, mut error: Option<Error>) -> Result<(), Error> {
        let mut status = self.registers.read8(HOST_STATUS);
        if error.is_none() {
            error = Self::status_error(status);
            if error.is_none() && status & HOST_BUSY != 0 {
                error = Some(Self::error(ErrorKind::UnexpectedCompletion, status));
            }
        }
        let mut recovery = Recovery::Cleared;
        if status & HOST_BUSY != 0 {
            self.registers.write8(HOST_CONTROL, KILL);
            let start = self.timer.start();
            loop {
                status = self.registers.read8(HOST_STATUS);
                if status & HOST_BUSY == 0 && status & FAILED != 0 {
                    recovery = Recovery::Killed;
                    break;
                }
                if self.expired(start, self.config.recovery_timeout_us) {
                    recovery = Recovery::Failed;
                    self.ready = false;
                    break;
                }
                self.timer.relax();
            }
        }
        self.registers.write8(HOST_CONTROL, 0);
        self.registers.write8(HOST_STATUS, status & STATUS_FLAGS);
        self.clear_modes();
        let modes_stuck = self.info.block_buffer
            && self.registers.read8(AUX_CONTROL) & (AUX_CRC | AUX_BUFFER) != 0;
        if recovery != Recovery::Failed
            && (self.registers.read8(HOST_STATUS) & (HOST_BUSY | STATUS_FLAGS) != 0 || modes_stuck)
        {
            recovery = Recovery::Failed;
            self.ready = false;
        }
        if recovery == Recovery::Failed && error.is_none() {
            error = Some(Self::error(
                if modes_stuck {
                    ErrorKind::BufferModeRejected
                } else {
                    ErrorKind::StatusStuck
                },
                status,
            ));
        }
        self.release();
        if let Some(error) = &mut error {
            error.recovery = recovery;
        }
        error.map_or(Ok(()), Err)
    }

    fn set_target(&mut self, address: Address, read: bool, command: Option<u8>) {
        self.registers
            .write8(HOST_ADDRESS, address.get() << 1 | u8::from(read));
        if let Some(command) = command {
            self.registers.write8(HOST_COMMAND, command);
        }
    }

    fn deadline(&self, start: u64) -> Result<(), Error> {
        if self.expired(start, self.config.timeout_us) {
            Err(ErrorKind::Timeout(Phase::Completion).into())
        } else {
            Ok(())
        }
    }

    fn start_transfer(&mut self, control: u8, start: u64) -> Result<(), Error> {
        self.deadline(start)?;
        self.registers.write8(HOST_CONTROL, control | START);
        Ok(())
    }

    fn completed_deadline(&self, start: u64) -> Result<(), Error> {
        self.deadline(start).map_err(|mut error| {
            error.recovery = Recovery::Cleared;
            error
        })
    }

    fn simple(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        start: u64,
    ) -> Result<(), Error> {
        let protocol = match &transaction {
            Transaction::SendByte(byte) => {
                self.set_target(address, false, Some(*byte));
                PROTOCOL_BYTE
            }
            Transaction::ReceiveByte(_) => {
                self.set_target(address, true, None);
                PROTOCOL_BYTE
            }
            Transaction::WriteByte { command, data } => {
                self.set_target(address, false, Some(*command));
                self.registers.write8(HOST_DATA0, *data);
                PROTOCOL_BYTE_DATA
            }
            Transaction::ReadByte { command, .. } => {
                self.set_target(address, true, Some(*command));
                PROTOCOL_BYTE_DATA
            }
            Transaction::WriteWord { command, data }
            | Transaction::ProcessCall {
                command,
                request: data,
                ..
            } => {
                self.set_target(address, false, Some(*command));
                let [low, high] = data.to_le_bytes();
                self.registers.write8(HOST_DATA0, low);
                self.registers.write8(HOST_DATA1, high);
                if matches!(transaction, Transaction::ProcessCall { .. }) {
                    PROTOCOL_PROCESS_CALL
                } else {
                    PROTOCOL_WORD_DATA
                }
            }
            Transaction::ReadWord { command, .. } => {
                self.set_target(address, true, Some(*command));
                PROTOCOL_WORD_DATA
            }
            _ => unreachable!("block operations use the block engine"),
        };
        if let Err(error) = self.start_transfer(protocol, start) {
            return self.finish(Some(error));
        }
        let completed = self.wait(start, Phase::Completion);
        if let Err(error) = completed {
            return self.finish(Some(error));
        }
        // Stage the output before cleanup; publish it only if cleanup succeeds.
        let low = self.registers.read8(HOST_DATA0);
        let high = self.registers.read8(HOST_DATA1);
        self.finish(None)?;
        self.completed_deadline(start)?;
        match transaction {
            Transaction::ReceiveByte(byte) | Transaction::ReadByte { data: byte, .. } => {
                *byte = low
            }
            Transaction::ReadWord { data: word, .. }
            | Transaction::ProcessCall { response: word, .. } => {
                *word = u16::from_le_bytes([low, high]);
            }
            _ => {}
        }
        Ok(())
    }

    fn quick_until(&mut self, address: Address, read: bool, start: u64) -> Result<(), Error> {
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        if let Err(error) = self.prepare() {
            if error.kind == ErrorKind::BufferModeRejected {
                self.ready = false;
            }
            return Err(error);
        }
        // QUICK carries only an address/direction, with no command/data or PEC.
        self.set_target(address, read, None);
        let result = self
            .start_transfer(PROTOCOL_QUICK, start)
            .and_then(|()| self.wait(start, Phase::Completion).map(|_| ()));
        self.finish(result.err())?;
        self.completed_deadline(start)
    }

    fn block(
        &mut self,
        address: Address,
        command: u8,
        write: Option<&[u8]>,
        output: Option<&mut Block>,
        start: u64,
    ) -> Result<(), Error> {
        self.set_target(address, write.is_none(), Some(command));
        let mut result = Block::default();
        let buffered = self.info.block_buffer && self.config.use_block_buffer;
        if buffered {
            let auxiliary = self.registers.read8(AUX_CONTROL);
            self.registers.write8(AUX_CONTROL, auxiliary | AUX_BUFFER);
            if self.registers.read8(AUX_CONTROL) & AUX_BUFFER == 0 {
                let status = self.registers.read8(HOST_STATUS);
                return self.finish(Some(Self::error(ErrorKind::BufferModeRejected, status)));
            }
            if let Some(bytes) = write {
                self.registers.write8(HOST_DATA0, bytes.len() as u8);
                self.registers.read8(HOST_CONTROL); // reset block-buffer index
                for &byte in bytes {
                    self.registers.write8(BLOCK_DATA, byte);
                }
            }
            if let Err(error) = self.start_transfer(PROTOCOL_BLOCK, start) {
                return self.finish(Some(error));
            }
            if let Err(error) = self.wait(start, Phase::Completion) {
                return self.finish(Some(error));
            }
            if write.is_none() {
                let count = usize::from(self.registers.read8(HOST_DATA0));
                if !(1..=MAX_BLOCK).contains(&count) {
                    let status = self.registers.read8(HOST_STATUS);
                    return self.finish(Some(Self::error(
                        ErrorKind::InvalidBlockLength(count),
                        status,
                    )));
                }
                self.registers.read8(HOST_CONTROL); // reset block-buffer index
                for byte in &mut result.bytes[..count] {
                    *byte = self.registers.read8(BLOCK_DATA);
                }
                result.length = count as u8;
            }
        } else {
            if let Some(bytes) = write {
                self.registers.write8(HOST_DATA0, bytes.len() as u8);
                self.registers.write8(BLOCK_DATA, bytes[0]);
            }
            if let Err(error) = self.start_transfer(PROTOCOL_BLOCK, start) {
                return self.finish(Some(error));
            }
            let mut count = write.map_or(MAX_BLOCK + 1, <[u8]>::len);
            let mut index = 0;
            while index < count {
                if let Err(error) = self.wait(start, Phase::ByteDone) {
                    return self.finish(Some(error));
                }
                if write.is_none() {
                    if index == 0 {
                        count = usize::from(self.registers.read8(HOST_DATA0));
                        if !(1..=MAX_BLOCK).contains(&count) {
                            let status = self.registers.read8(HOST_STATUS);
                            return self.finish(Some(Self::error(
                                ErrorKind::InvalidBlockLength(count),
                                status,
                            )));
                        }
                        result.length = count as u8;
                    }
                    result.bytes[index] = self.registers.read8(BLOCK_DATA);
                    if index + 2 == count {
                        self.registers
                            .write8(HOST_CONTROL, PROTOCOL_BLOCK | LAST_BYTE);
                    }
                } else if let Some(bytes) = write
                    && index + 1 < count
                {
                    self.registers.write8(BLOCK_DATA, bytes[index + 1]);
                }
                self.registers.write8(HOST_STATUS, BYTE_DONE);
                index += 1;
            }
            if let Err(error) = self.wait(start, Phase::Completion) {
                return self.finish(Some(error));
            }
        }
        self.finish(None)?;
        self.completed_deadline(start)?;
        if let Some(output) = output {
            *output = result;
        }
        Ok(())
    }
}

impl<R: Registers, T: Timer> I801<R, T> {
    fn transaction_until(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
        start: u64,
    ) -> Result<(), Error> {
        if pec {
            return Err(ErrorKind::UnsupportedPec.into());
        }
        if let Transaction::WriteBlock { data, .. } = &transaction
            && !(1..=MAX_BLOCK).contains(&data.len())
        {
            return Err(ErrorKind::InvalidBlockLength(data.len()).into());
        }
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        self.prepare()?;
        match transaction {
            Transaction::WriteBlock { command, data } => {
                self.block(address, command, Some(data), None, start)
            }
            Transaction::ReadBlock { command, data } => {
                self.block(address, command, None, Some(data), start)
            }
            transaction => self.simple(address, transaction, start),
        }
    }
}

impl<R: Registers, T: Timer> I801<R, T> {
    /// Linux `i801_enable_host_notify`: SMBALERT# stops raising interrupts and
    /// the Host Notify status is cleared for the next notification. Its
    /// interrupt stays disabled; [`Self::take_host_notify`] polls the status.
    pub fn enable_host_notify(&mut self) -> Result<(), Error> {
        if !self.info.has_host_notify() {
            return Err(ErrorKind::UnsupportedTransaction.into());
        }
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        let original = *self
            .slave_command
            .get_or_insert_with(|| self.registers.read8(SLAVE_COMMAND));
        self.registers.write8(
            SLAVE_COMMAND,
            (original & !HOST_NOTIFY_INTERRUPT) | SMBALERT_DISABLE,
        );
        self.registers.write8(SLAVE_STATUS, HOST_NOTIFY_STATUS);
        Ok(())
    }

    /// Linux `i801_host_notify_isr`, polled: the seven-bit address of the
    /// peripheral whose Host Notify arrived, its status then cleared for the
    /// next one. The notification's data bytes are not read, as Linux reads
    /// none.
    pub fn take_host_notify(&mut self) -> Result<Option<u8>, Error> {
        if self.slave_command.is_none() {
            return Err(ErrorKind::UnsupportedTransaction.into());
        }
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        if self.registers.read8(SLAVE_STATUS) & HOST_NOTIFY_STATUS == 0 {
            return Ok(None);
        }
        let address = self.registers.read8(NOTIFY_ADDRESS) >> 1;
        self.registers.write8(SLAVE_STATUS, HOST_NOTIFY_STATUS);
        Ok(Some(address))
    }

    /// Linux `i801_disable_host_notify`: SMBSLVCMD returns to its value as
    /// found.
    pub fn disable_host_notify(&mut self) {
        if let Some(original) = self.slave_command.take() {
            self.registers.write8(SLAVE_COMMAND, original);
        }
    }
}

impl<R: Registers, T: Timer> Bus for I801<R, T> {
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), Error> {
        let start = self.timer.start();
        self.transaction_until(address, transaction, pec, start)
    }
}

#[cfg(test)]
mod tests;
