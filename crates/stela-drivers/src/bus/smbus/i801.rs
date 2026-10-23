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
//! There is deliberately no automatic PCI attachment: the platform must enable
//! the PCI I/O decode/host function in D0 and arbitrate ACPI AML and SMM access.
//! A device ID or an idle status bit does not prove exclusive ownership. The
//! unsafe [`PortIo::claim`] contract requires that ownership before any I/O.
//! MMIO-only devices need a separate register accessor. PEC, I²C block mode,
//! block process calls, SMBALERT and Host Notify are unsupported here.
//!
//! Read-to-acquire INUSE semantics are documented in Intel's Host Status
//! Register Address (HSTS), offset 0, Core Ultra SoC I/O Registers, ID 795260.
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
const HOST_ENABLED: u8 = 1;
const HOST_SMI: u8 = 1 << 1;
const HOST_I2C: u8 = 1 << 2;

const PROTOCOL_BYTE: u8 = 0x04;
const PROTOCOL_BYTE_DATA: u8 = 0x08;
const PROTOCOL_WORD_DATA: u8 = 0x0c;
const PROTOCOL_PROCESS_CALL: u8 = 0x10;
const PROTOCOL_BLOCK: u8 = 0x14;

/// Ordered byte access to a single exclusively owned host controller.
pub trait Registers {
    fn read8(&mut self, offset: u8) -> u8;
    fn write8(&mut self, offset: u8, value: u8);
}

/// Exact Linux I801 PCI ID match and register capabilities, not a claim that
/// firmware ownership has been acquired or that an OEM board was qualified.
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
        if config.timeout_us == 0 || config.recovery_timeout_us == 0 {
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
        };
        controller.prepare()?;
        controller.release();
        Ok(controller)
    }

    fn expired(&self, start: u64, timeout: u64) -> bool {
        self.timer.now_us().wrapping_sub(start) >= timeout
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
            if self.expired(start, self.config.timeout_us) {
                return Err(Self::error(ErrorKind::Timeout(phase), status));
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
            let start = self.timer.now_us();
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
        self.registers.write8(HOST_CONTROL, protocol | START);
        let completed = self.wait(start, Phase::Completion);
        if let Err(error) = completed {
            return self.finish(Some(error));
        }
        // Stage the output before cleanup; publish it only if cleanup succeeds.
        let low = self.registers.read8(HOST_DATA0);
        let high = self.registers.read8(HOST_DATA1);
        self.finish(None)?;
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
            self.registers.write8(HOST_CONTROL, PROTOCOL_BLOCK | START);
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
            self.registers.write8(HOST_CONTROL, PROTOCOL_BLOCK | START);
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
        if let Some(output) = output {
            *output = result;
        }
        Ok(())
    }
}

impl<R: Registers, T: Timer> Bus for I801<R, T> {
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
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
        let start = self.timer.now_us();
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "linux-i801")]
    mod comparison;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::{Cell, RefCell};

    const ALERT: u8 = 1 << 5;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Request {
        protocol: u8,
        address: u8,
        command: u8,
        word: u16,
        block: Vec<u8>,
    }

    /// Hardware model with an independent peripheral response, read-to-acquire
    /// INUSE semaphore, W1C status and byte-by-byte SCL holding until BYTE_DONE is
    /// acknowledged. The production driver is the only bus transaction engine.
    struct Model {
        registers: [u8; 32],
        status: u8,
        time: Rc<Cell<u64>>,
        due: u64,
        latency: u64,
        requests: Vec<Request>,
        reads: usize,
        writes: Vec<(u8, u8)>,
        reply: Vec<u8>,
        reply_word: u16,
        count: usize,
        byte: usize,
        buffer: [u8; MAX_BLOCK],
        buffer_index: usize,
        staged_byte: Option<u8>,
        read: bool,
        block: bool,
        buffered: bool,
        active: bool,
        kill_at: Option<u64>,
        kills: usize,
        freeze: bool,
        freeze_kill: bool,
        kill_without_failed: bool,
        error: u8,
        error_byte: Option<usize>,
        premature_intr: Option<usize>,
        stuck_status: u8,
        refuse_buffer: bool,
        auxiliary_present: bool,
    }

    impl Model {
        fn new(time: Rc<Cell<u64>>, auxiliary_present: bool) -> Self {
            Self {
                registers: [0; 32],
                status: ALERT,
                time,
                due: 0,
                latency: 3,
                requests: Vec::new(),
                reads: 0,
                writes: Vec::new(),
                reply: vec![5, 6, 7],
                reply_word: 0x9876,
                count: 0,
                byte: 0,
                buffer: [0; MAX_BLOCK],
                buffer_index: 0,
                staged_byte: None,
                read: false,
                block: false,
                buffered: false,
                active: false,
                kill_at: None,
                kills: 0,
                freeze: false,
                freeze_kill: false,
                kill_without_failed: false,
                error: 0,
                error_byte: None,
                premature_intr: None,
                stuck_status: 0,
                refuse_buffer: false,
                auxiliary_present,
            }
        }

        fn complete(&mut self) {
            self.active = false;
            self.status &= !HOST_BUSY;
            if self.error == 0 {
                self.status |= INTR;
            } else {
                self.status |= self.error;
            }
        }

        fn step(&mut self) {
            let now = self.time.get();
            if self.kill_at.is_some_and(|at| now >= at) {
                self.kill_at = None;
                self.active = false;
                self.status &= !(HOST_BUSY | BYTE_DONE);
                if !self.kill_without_failed {
                    self.status |= FAILED;
                }
            }
            if !self.active || self.freeze || now < self.due || self.status & BYTE_DONE != 0 {
                return;
            }
            if self.premature_intr == Some(self.byte) {
                self.active = false;
                self.status &= !HOST_BUSY;
                self.status |= INTR;
                return;
            }
            if self.error_byte == Some(self.byte) || (!self.block && self.error != 0) {
                self.status |= self.error;
                self.active = false;
                self.status &= !HOST_BUSY;
                return;
            }
            if !self.block {
                let [low, high] = self.reply_word.to_le_bytes();
                self.registers[usize::from(HOST_DATA0)] = low;
                self.registers[usize::from(HOST_DATA1)] = high;
                self.complete();
            } else if self.buffered {
                if self.read {
                    self.registers[usize::from(HOST_DATA0)] = self.reply.len() as u8;
                    for (to, &from) in self.buffer.iter_mut().zip(&self.reply) {
                        *to = from;
                    }
                } else {
                    self.requests.last_mut().unwrap().block = self.buffer[..self.count].to_vec();
                }
                self.complete();
            } else {
                if self.read {
                    self.registers[usize::from(HOST_DATA0)] = self.reply.len() as u8;
                    self.registers[usize::from(BLOCK_DATA)] =
                        self.reply.get(self.byte).copied().unwrap_or(0);
                } else {
                    let byte = self
                        .staged_byte
                        .take()
                        .expect("write byte not supplied before ACK");
                    self.requests.last_mut().unwrap().block.push(byte);
                }
                self.status |= BYTE_DONE;
            }
        }

        fn start(&mut self, value: u8) {
            assert!(
                !self.active && self.status & HOST_BUSY == 0,
                "START on busy bus"
            );
            assert!(self.status & INUSE != 0, "START without software semaphore");
            assert_eq!(value & 1, 0, "interrupt generation must remain disabled");
            assert_eq!(value & 0x80, 0, "unsupported PEC enabled");
            self.block = value & 0x1c == PROTOCOL_BLOCK;
            self.buffered = self.registers[usize::from(AUX_CONTROL)] & AUX_BUFFER != 0;
            self.read = self.registers[usize::from(HOST_ADDRESS)] & 1 != 0;
            self.count = if self.read {
                self.reply.len()
            } else {
                usize::from(self.registers[usize::from(HOST_DATA0)])
            };
            self.byte = 0;
            self.active = true;
            self.status |= HOST_BUSY;
            self.due = self.time.get() + self.latency;
            self.requests.push(Request {
                protocol: value & 0x1c,
                address: self.registers[usize::from(HOST_ADDRESS)],
                command: self.registers[usize::from(HOST_COMMAND)],
                word: u16::from_le_bytes([
                    self.registers[usize::from(HOST_DATA0)],
                    self.registers[usize::from(HOST_DATA1)],
                ]),
                block: Vec::new(),
            });
        }

        fn read(&mut self, offset: u8) -> u8 {
            self.reads += 1;
            self.step();
            assert!(self.auxiliary_present || !matches!(offset, AUX_CONTROL | AUX_STATUS));
            match offset {
                HOST_STATUS => {
                    let status = self.status;
                    self.status |= INUSE;
                    status
                }
                HOST_CONTROL => {
                    if self.registers[usize::from(AUX_CONTROL)] & AUX_BUFFER != 0 {
                        self.buffer_index = 0;
                    }
                    self.registers[usize::from(offset)] & 0x1f
                }
                BLOCK_DATA if self.buffered => {
                    let value = self.buffer[self.buffer_index];
                    self.buffer_index += 1;
                    value
                }
                _ => self.registers[usize::from(offset)],
            }
        }

        fn write(&mut self, offset: u8, value: u8) {
            self.step();
            self.writes.push((offset, value));
            assert!(self.auxiliary_present || !matches!(offset, AUX_CONTROL | AUX_STATUS));
            match offset {
                HOST_STATUS => {
                    let acknowledged = value & self.status & BYTE_DONE != 0;
                    self.status &= !(value & !self.stuck_status & !HOST_BUSY);
                    if acknowledged && self.active {
                        self.byte += 1;
                        if self.byte >= self.count {
                            self.complete();
                        } else {
                            if self.read && self.byte + 1 == self.count {
                                assert_ne!(
                                    self.registers[usize::from(HOST_CONTROL)] & LAST_BYTE,
                                    0,
                                    "last-byte NACK was not armed before final byte"
                                );
                            }
                            self.due = self.time.get() + self.latency;
                        }
                    }
                }
                HOST_CONTROL => {
                    self.registers[usize::from(offset)] = value;
                    if value & KILL != 0 {
                        self.kills += 1;
                        if !self.freeze_kill {
                            self.kill_at = Some(self.time.get() + self.latency);
                        }
                    } else if value & START != 0 {
                        self.start(value);
                    }
                }
                BLOCK_DATA => {
                    if self.registers[usize::from(AUX_CONTROL)] & AUX_BUFFER != 0 {
                        self.buffer[self.buffer_index] = value;
                        self.buffer_index += 1;
                    } else {
                        self.staged_byte = Some(value);
                    }
                    self.registers[usize::from(offset)] = value;
                }
                AUX_STATUS => self.registers[usize::from(offset)] &= !value,
                AUX_CONTROL if self.refuse_buffer => {
                    self.registers[usize::from(offset)] = value & !AUX_BUFFER;
                }
                _ => self.registers[usize::from(offset)] = value,
            }
        }
    }

    #[derive(Clone)]
    struct RegisterModel(Rc<RefCell<Model>>);

    impl Registers for RegisterModel {
        fn read8(&mut self, offset: u8) -> u8 {
            self.0.borrow_mut().read(offset)
        }

        fn write8(&mut self, offset: u8, value: u8) {
            self.0.borrow_mut().write(offset, value);
        }
    }

    struct ModelTimer(Rc<Cell<u64>>);

    impl Timer for ModelTimer {
        fn now_us(&self) -> u64 {
            self.0.get()
        }

        fn relax(&self) {
            self.0.set(self.0.get().wrapping_add(1));
        }
    }

    type Controller = I801<RegisterModel, ModelTimer>;

    fn config(buffer: bool) -> Config {
        Config {
            timeout_us: 1000,
            recovery_timeout_us: 100,
            use_block_buffer: buffer,
        }
    }

    fn model(device: u16) -> (RegisterModel, ModelTimer, ControllerInfo) {
        let info = ControllerInfo::from_pci_id(0x8086, device).unwrap();
        let time = Rc::new(Cell::new(0));
        (
            RegisterModel(Rc::new(RefCell::new(Model::new(
                time.clone(),
                info.block_buffer,
            )))),
            ModelTimer(time),
            info,
        )
    }

    fn new_controller(device: u16, buffer: bool) -> (Controller, Rc<RefCell<Model>>) {
        let (registers, timer, info) = model(device);
        let state = registers.0.clone();
        let controller = I801::new(registers, timer, info, HOST_ENABLED, config(buffer)).unwrap();
        (controller, state)
    }

    fn address() -> Address {
        Address::new(0x2c).unwrap()
    }

    #[test]
    fn byte_word_and_process_call_protocols_match_the_wire_register_contract() {
        let (mut controller, state) = new_controller(0x7aa3, true);
        let mut byte = 0;
        let mut word = 0;
        for transaction in [
            Transaction::SendByte(0x11),
            Transaction::ReceiveByte(&mut byte),
            Transaction::WriteByte {
                command: 0x22,
                data: 0x33,
            },
            Transaction::WriteWord {
                command: 0x44,
                data: 0x5566,
            },
            Transaction::ReadWord {
                command: 0x77,
                data: &mut word,
            },
        ] {
            controller
                .transaction(address(), transaction, false)
                .unwrap();
        }
        assert_eq!(byte, 0x76);
        assert_eq!(word, 0x9876);
        controller
            .transaction(
                address(),
                Transaction::ProcessCall {
                    command: 0x88,
                    request: 0x1234,
                    response: &mut word,
                },
                false,
            )
            .unwrap();
        assert_eq!(word, 0x9876);
        controller
            .transaction(
                address(),
                Transaction::ReadByte {
                    command: 0x99,
                    data: &mut byte,
                },
                false,
            )
            .unwrap();
        assert_eq!(byte, 0x76);
        let state = state.borrow();
        let requests = &state.requests;
        assert_eq!(
            (
                requests[0].protocol,
                requests[0].address,
                requests[0].command
            ),
            (4, 0x58, 0x11)
        );
        assert_eq!((requests[1].protocol, requests[1].address), (4, 0x59));
        assert_eq!(
            (
                requests[2].protocol,
                requests[2].command,
                requests[2].word as u8
            ),
            (8, 0x22, 0x33)
        );
        assert_eq!(
            (requests[3].protocol, requests[3].command, requests[3].word),
            (12, 0x44, 0x5566)
        );
        assert_eq!((requests[4].protocol, requests[4].address), (12, 0x59));
        assert_eq!(
            (requests[5].protocol, requests[5].address, requests[5].word),
            (16, 0x58, 0x1234)
        );
        assert_eq!(
            (
                requests[6].protocol,
                requests[6].address,
                requests[6].command
            ),
            (8, 0x59, 0x99)
        );
        assert_eq!(state.status, ALERT);
    }

    #[test]
    fn block_transfers_preserve_all_lengths_in_byte_and_buffer_modes() {
        for (device, buffer) in [
            (0x2413, true),
            (0x2483, true),
            (0x24c3, true),
            (0x7aa3, true),
            (0x7aa3, false),
        ] {
            for count in 1..=MAX_BLOCK {
                let (mut controller, state) = new_controller(device, buffer);
                let bytes: Vec<_> = (0..count).map(|i| (i * 7 + 1) as u8).collect();
                state.borrow_mut().reply = bytes.clone();
                let mut result = Block::default();
                controller
                    .transaction(
                        address(),
                        Transaction::ReadBlock {
                            command: 0x52,
                            data: &mut result,
                        },
                        false,
                    )
                    .unwrap();
                assert_eq!(result.as_slice(), bytes);
                controller
                    .transaction(
                        address(),
                        Transaction::WriteBlock {
                            command: 0x53,
                            data: &bytes,
                        },
                        false,
                    )
                    .unwrap();
                let state = state.borrow();
                assert_eq!(state.requests.last().unwrap().block, bytes);
                assert_eq!(state.status, ALERT);
                assert_eq!(
                    state.registers[usize::from(AUX_CONTROL)] & (AUX_CRC | AUX_BUFFER),
                    0
                );
            }
        }
    }

    #[test]
    fn stale_status_and_crc_are_cleared_without_acknowledging_alerts_or_other_owner() {
        let (registers, timer, info) = model(0x7aa3);
        let state = registers.0.clone();
        {
            let mut state = state.borrow_mut();
            state.status |= STATUS_FLAGS;
            state.registers[usize::from(AUX_STATUS)] = AUX_CRC_ERROR | 2;
            state.registers[usize::from(AUX_CONTROL)] = AUX_CRC | AUX_BUFFER | 4;
        }
        let mut controller = I801::new(registers, timer, info, HOST_ENABLED, config(true)).unwrap();
        assert_eq!(state.borrow().status, ALERT);
        assert_eq!(state.borrow().registers[usize::from(AUX_STATUS)], 2);
        assert_eq!(state.borrow().registers[usize::from(AUX_CONTROL)], 4);
        state.borrow_mut().status |= INUSE;
        let writes = state.borrow().writes.len();
        let error = controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Busy);
        assert_eq!(state.borrow().writes.len(), writes);
        assert_eq!(state.borrow().status, ALERT | INUSE);
    }

    #[test]
    fn controller_errors_preserve_status_and_do_not_publish_read_outputs() {
        for (status, kind) in [
            (DEV_ERR, ErrorKind::Device),
            (BUS_ERR, ErrorKind::ArbitrationLost),
            (FAILED, ErrorKind::Failed),
        ] {
            let (mut controller, state) = new_controller(0x7aa3, true);
            state.borrow_mut().error = status;
            let mut value = 0xaaaa;
            let error = controller
                .transaction(
                    address(),
                    Transaction::ReadWord {
                        command: 4,
                        data: &mut value,
                    },
                    false,
                )
                .unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(error.status & ERROR_FLAGS, status);
            assert_eq!(error.recovery, Recovery::Cleared);
            assert_eq!(value, 0xaaaa);
            assert_eq!(state.borrow().status, ALERT);
            state.borrow_mut().error = 0;
            controller
                .transaction(address(), Transaction::SendByte(5), false)
                .unwrap();
        }
    }

    #[test]
    fn timeouts_kill_only_our_transaction_and_failed_kills_poison_the_new_controller() {
        for kill_fails in [false, true] {
            let (mut controller, state) = new_controller(0x7aa3, true);
            {
                let mut state = state.borrow_mut();
                state.freeze = true;
                state.freeze_kill = kill_fails;
            }
            let error = controller
                .transaction(address(), Transaction::SendByte(1), false)
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
            assert_eq!(
                error.recovery,
                if kill_fails {
                    Recovery::Failed
                } else {
                    Recovery::Killed
                }
            );
            assert_eq!(state.borrow().kills, 1);
            assert!(state.borrow().time.get() <= 1100);
            if kill_fails {
                let writes = state.borrow().writes.len();
                assert_eq!(
                    controller
                        .transaction(address(), Transaction::SendByte(2), false)
                        .unwrap_err()
                        .kind,
                    ErrorKind::NeedsReset
                );
                assert_eq!(state.borrow().writes.len(), writes);
            } else {
                state.borrow_mut().freeze = false;
                controller
                    .transaction(address(), Transaction::SendByte(2), false)
                    .unwrap();
            }
        }
        let (mut controller, state) = new_controller(0x7aa3, true);
        state.borrow_mut().status |= HOST_BUSY;
        assert_eq!(
            controller
                .transaction(address(), Transaction::SendByte(3), false)
                .unwrap_err()
                .kind,
            ErrorKind::Busy
        );
        assert_eq!(state.borrow().kills, 0);
        assert_eq!(state.borrow().status & INUSE, 0);
    }

    #[test]
    fn bad_block_counts_are_bounded_and_never_publish_partial_data() {
        for buffered in [false, true] {
            for length in [0, 33, 255] {
                let (mut controller, state) = new_controller(0x7aa3, buffered);
                state.borrow_mut().reply = vec![1; length];
                let mut block = Block::default();
                let error = controller
                    .transaction(
                        address(),
                        Transaction::ReadBlock {
                            command: 8,
                            data: &mut block,
                        },
                        false,
                    )
                    .unwrap_err();
                assert_eq!(error.kind, ErrorKind::InvalidBlockLength(length));
                assert_eq!(block, Block::default());
                assert_eq!(
                    error.recovery,
                    if buffered {
                        Recovery::Cleared
                    } else {
                        Recovery::Killed
                    }
                );
                assert!(state.borrow().time.get() < 1100);
                assert_eq!(state.borrow().status, ALERT);
            }
        }
    }

    #[test]
    fn premature_intr_mid_block_is_an_error_and_the_byte_bound_is_transaction_wide() {
        let (mut controller, state) = new_controller(0x2413, false);
        state.borrow_mut().premature_intr = Some(1);
        let mut block = Block::default();
        let error = controller
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 3,
                    data: &mut block,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnexpectedCompletion);
        assert!(block.as_slice().is_empty());

        let (mut controller, state) = new_controller(0x2413, false);
        {
            let mut state = state.borrow_mut();
            state.latency = 40;
            state.reply = vec![7; 32];
        }
        let error = controller
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 3,
                    data: &mut block,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::ByteDone));
        assert_eq!(error.recovery, Recovery::Killed);
        assert!(state.borrow().time.get() <= 1100);
    }

    #[test]
    fn unsupported_pec_invalid_lengths_and_bad_configuration_never_start_io() {
        for address in [0, 7, 0x78, 0x80, 0xff] {
            assert_eq!(
                Address::new(address).unwrap_err().kind,
                ErrorKind::InvalidAddress
            );
        }
        for (host, kind) in [
            (0, ErrorKind::HostDisabled),
            (HOST_ENABLED | HOST_SMI, ErrorKind::FirmwareSmi),
            (HOST_ENABLED | HOST_I2C, ErrorKind::WrongProtocolMode),
        ] {
            let (registers, timer, info) = model(0x7aa3);
            let state = registers.0.clone();
            let error = I801::new(registers, timer, info, host, config(true))
                .err()
                .unwrap();
            assert_eq!(error.kind, kind);
            assert!(state.borrow().writes.is_empty());
        }
        let (mut controller, state) = new_controller(0x7aa3, true);
        let writes = state.borrow().writes.len();
        assert_eq!(
            controller
                .transaction(address(), Transaction::SendByte(1), true)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedPec
        );
        for bytes in [&[][..], &[1; 33][..]] {
            assert_eq!(
                controller
                    .transaction(
                        address(),
                        Transaction::WriteBlock {
                            command: 0,
                            data: bytes
                        },
                        false
                    )
                    .unwrap_err()
                    .kind,
                ErrorKind::InvalidBlockLength(bytes.len())
            );
        }
        assert_eq!(state.borrow().writes.len(), writes);
        assert!(ControllerInfo::from_pci_id(0x8086, 0xffff).is_none());
        assert!(ControllerInfo::from_pci_id(0x1022, 0x7aa3).is_none());
        assert_eq!(
            ControllerInfo::from_pci_id(0x8086, 0x2413)
                .unwrap()
                .register_bytes(),
            16
        );
        assert!(
            !ControllerInfo::from_pci_id(0x8086, 0x2483)
                .unwrap()
                .has_block_buffer()
        );
    }

    #[test]
    fn a_successful_wire_transfer_with_stuck_completion_status_is_still_an_error() {
        let (mut controller, state) = new_controller(0x7aa3, true);
        state.borrow_mut().stuck_status = INTR;
        let mut value = 0xaabb;
        let error = controller
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 4,
                    data: &mut value,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::StatusStuck);
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(value, 0xaabb);
        assert_eq!(state.borrow().status & INUSE, 0);
        assert_eq!(
            controller
                .transaction(address(), Transaction::SendByte(1), false)
                .unwrap_err()
                .kind,
            ErrorKind::NeedsReset
        );
    }

    #[test]
    fn a_kill_without_the_required_failed_acknowledgement_is_not_accepted() {
        let (mut controller, state) = new_controller(0x7aa3, true);
        {
            let mut state = state.borrow_mut();
            state.freeze = true;
            state.kill_without_failed = true;
        }
        let error = controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(state.borrow().status & HOST_BUSY, 0);
        assert_eq!(state.borrow().status & INUSE, 0);
        assert!(state.borrow().time.get() <= 1100);
    }

    #[test]
    fn a_device_error_after_a_partial_block_read_keeps_the_previous_output() {
        let (mut controller, state) = new_controller(0x2413, false);
        let mut result = Block::default();
        controller
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 1,
                    data: &mut result,
                },
                false,
            )
            .unwrap();
        let previous = result.clone();
        {
            let mut state = state.borrow_mut();
            state.error = DEV_ERR;
            state.error_byte = Some(1);
            state.reply = vec![8, 9, 10];
        }
        let error = controller
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 2,
                    data: &mut result,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Device);
        assert_eq!(result, previous);
        assert_eq!(state.borrow().status, ALERT);
    }

    #[test]
    fn hardware_refusing_the_requested_block_buffer_mode_is_rejected_before_start() {
        let (mut controller, state) = new_controller(0x7aa3, true);
        state.borrow_mut().refuse_buffer = true;
        let mut block = Block::default();
        let error = controller
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 1,
                    data: &mut block,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::BufferModeRejected);
        assert!(state.borrow().requests.is_empty());
        assert_eq!(state.borrow().status, ALERT);
        assert!(block.as_slice().is_empty());
    }
}
