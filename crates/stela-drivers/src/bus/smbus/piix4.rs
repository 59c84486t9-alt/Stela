// SPDX-License-Identifier: GPL-2.0-or-later
//
// Adapted from Linux drivers/i2c/busses/i2c-piix4.c and i2c-piix4.h at
// a804c5742bff224d4cb4d25dd383554d598be32b.
// c SHA-256: 4090404533b3a372acd1809e25d2c525edf00295e5e4c319bb096a33bfadbbba
// h SHA-256: 2e41c2f6f385f45e20a5f51f6d65fe16785b9c65fa4a312c1e5354366ccf8788
//
// Copyright (c) 1998 - 2002 Frodo Looijaard <frodol@dds.nl> and
// Philip Edelbrock <phil@netroedge.com>
// Copyright (c) 2024, Advanced Micro Devices, Inc. All Rights Reserved.
// Authors of the upstream interface header:
// Shyam Sundar S K <Shyam-sundar.S-k@amd.com>
// Sanket Goswami <Sanket.Goswami@amd.com>
//
//! PIIX4-compatible SMBus register engine, including AMD SB/FCH controllers.
//!
//! This is not I801: host status reads do not acquire an INUSE semaphore, and
//! block transfers use the host's data array whose index resets on HSTCNT read.
//! There is no E32B mode or BYTE_DONE streaming protocol in this implementation.
//!
//! Platform setup remains explicit. Legacy PCI base/enable, SB800 PMIO/MMIO
//! decode, AMD port selection/restoration, IMC semaphore/mailbox and ACPI/SMM
//! arbitration must be completed before [`PortIo::claim`]. The exact revision
//! distinctions are exposed by [`ControllerInfo`]; they do not perform setup.
//! No port scan, forced enable, automatic mux change or firmware takeover occurs.
//!
//! Linux reports that collisions can leave the bus locked until hard reset and
//! provides no portable controller termination sequence. On timeout, collision
//! or a stuck busy/status flag this driver stops and requires platform reset;
//! it never guesses that I801's KILL acknowledgement applies to an AMD revision.
//! PEC, process calls, arbitrary I²C transfers and Host Notify are unsupported.
use super::{Address, Block, Bus, Error, ErrorKind, MAX_BLOCK, Phase, Recovery, Transaction};
use crate::{Clock, bus::i2c::Timer};

const HOST_STATUS: u8 = 0;
const HOST_CONTROL: u8 = 2;
const HOST_COMMAND: u8 = 3;
const HOST_ADDRESS: u8 = 4;
const HOST_DATA0: u8 = 5;
const HOST_DATA1: u8 = 6;
const BLOCK_DATA: u8 = 7;
const PORT_BYTES: u16 = 9;

const HOST_BUSY: u8 = 1;
const INTR: u8 = 1 << 1;
const DEV_ERR: u8 = 1 << 2;
const BUS_ERR: u8 = 1 << 3;
const FAILED: u8 = 1 << 4;
const ERROR_FLAGS: u8 = DEV_ERR | BUS_ERR | FAILED;
const STATUS_FLAGS: u8 = INTR | ERROR_FLAGS;
const START: u8 = 1 << 6;
const PROTOCOL_BYTE: u8 = 0x04;
const PROTOCOL_BYTE_DATA: u8 = 0x08;
const PROTOCOL_WORD_DATA: u8 = 0x0c;
const PROTOCOL_BLOCK: u8 = 0x14;

pub trait Registers {
    fn read8(&mut self, offset: u8) -> u8;
    fn write8(&mut self, offset: u8, value: u8);
}

/// How platform code must find the host enable/base registers. `PmDecode`
/// distinguishes the newer fixed-high-byte layout from older SB800 registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseRegisters {
    /// PCI configuration: SMBBA at 0x90, host enable at 0xd2.
    LegacyPci,
    /// Main controller PMIO 0x2c/0x2d; auxiliary 0x28/0x29.
    Sb800,
    /// PM DecodeEn bit 4 enables SMBus; PM byte 1 supplies base bits 15:8.
    /// Main base low byte is zero, auxiliary low byte is 0x20.
    PmDecode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmAccess {
    NotApplicable,
    IndexedIo,
    /// AMD 790b revision >= 0x51 can disable 0xcd6/0xcd7 access; use the
    /// separately mapped FCH PM register window for setup and mux selection.
    Mmio,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortSelection {
    NotApplicable,
    /// SB800 chooses PMIO 0x2c or 0x2e according to bit 0 of 0x2f.
    Sb800Selectable,
    /// Early Hudson main ports use PMIO 0x2e bits 2:1.
    HudsonEarly,
    /// Later Hudson/KernCZ main ports use DecodeEn byte 2 bits 4:3.
    DecodeEn,
}

/// A precise upstream PCI/revision match and required platform layout, not
/// proof of firmware ownership, valid DMI routing, or peripheral compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControllerInfo {
    vendor: u16,
    device: u16,
    revision: u8,
    base_registers: BaseRegisters,
    pm_access: PmAccess,
    port_selection: PortSelection,
    main_ports: u8,
    first_poll_us: u64,
}

impl ControllerInfo {
    pub fn from_pci_id(vendor: u16, device: u16, revision: u8) -> Option<Self> {
        let mut info = Self {
            vendor,
            device,
            revision,
            base_registers: BaseRegisters::LegacyPci,
            pm_access: PmAccess::NotApplicable,
            port_selection: PortSelection::NotApplicable,
            main_ports: 1,
            first_poll_us: 250,
        };
        match (vendor, device) {
            (0x8086, 0x7113 | 0x719b)
            | (0x1055, 0x9463)
            | (0x1002, 0x4353 | 0x4363 | 0x4372)
            | (0x1166, 0x0200 | 0x0203 | 0x0205 | 0x0408) => {}
            (0x1166, 0x0201) => info.first_poll_us = 2000,
            (0x1002, 0x4385) if revision < 0x40 => {}
            (0x1002, 0x4385) => {
                info.base_registers = BaseRegisters::Sb800;
                info.pm_access = PmAccess::IndexedIo;
                info.port_selection = PortSelection::Sb800Selectable;
                info.main_ports = 4;
            }
            (0x1022, 0x780b) => {
                info.base_registers = if revision >= 0x41 {
                    BaseRegisters::PmDecode
                } else {
                    BaseRegisters::Sb800
                };
                info.pm_access = PmAccess::IndexedIo;
                info.port_selection = if revision >= 0x1f {
                    PortSelection::DecodeEn
                } else {
                    PortSelection::HudsonEarly
                };
                info.main_ports = if revision >= 0x1f { 2 } else { 4 };
            }
            (0x1022 | 0x1d94, 0x790b) => {
                info.base_registers = if vendor == 0x1d94 || revision >= 0x49 {
                    BaseRegisters::PmDecode
                } else {
                    BaseRegisters::Sb800
                };
                info.pm_access = if vendor == 0x1022 && revision >= 0x51 {
                    PmAccess::Mmio
                } else {
                    PmAccess::IndexedIo
                };
                info.port_selection = PortSelection::DecodeEn;
                info.main_ports = 2;
            }
            _ => return None,
        }
        Some(info)
    }

    pub fn pci_id(self) -> (u16, u16, u8) {
        (self.vendor, self.device, self.revision)
    }

    pub fn base_registers(self) -> BaseRegisters {
        self.base_registers
    }

    pub fn pm_access(self) -> PmAccess {
        self.pm_access
    }

    pub fn port_selection(self) -> PortSelection {
        self.port_selection
    }

    /// Number of main mux choices: physical port numbers are 0, 2, 3, 4,
    /// rather than the auxiliary controller's physical port 1.
    pub fn main_ports(self) -> u8 {
        self.main_ports
    }
}

/// Exclusive PIO accessor for one already configured and selected host port.
pub struct PortIo {
    base: u16,
}

impl PortIo {
    /// # Safety
    ///
    /// `base..base + 9` must be the enabled, decoded SMBus host I/O window
    /// matching `info`, accessible at this CPU's I/O privilege. The platform
    /// must validate its address from the appropriate PCI/PM decode registers.
    /// Firmware/SMM, AML, IRQ handlers and other CPUs must relinquish access.
    /// For SB800/FCH, hold the selected port, PM register ownership, hardware
    /// semaphore and any required IMC ownership throughout this object's life;
    /// do not restore the mux until shutdown succeeds or platform reset finishes.
    /// Apply upstream DMI exclusions first (IBM Intel PIIX4, Sapphire AM2RD790,
    /// DFI LP UT 790FX); this accessor does not inspect board firmware tables.
    pub unsafe fn claim(base: u16, _info: ControllerInfo) -> Result<Self, Error> {
        if base == 0
            || !base.is_multiple_of(16)
            || u32::from(base) + u32::from(PORT_BYTES) > 0x1_0000
        {
            return Err(ErrorKind::InvalidPortRange.into());
        }
        Ok(Self { base })
    }
}

impl Registers for PortIo {
    fn read8(&mut self, offset: u8) -> u8 {
        assert!(u16::from(offset) < PORT_BYTES);
        let value: u8;
        // SAFETY: claim's decoded-window, exclusive ownership and privilege contract.
        unsafe {
            core::arch::asm!(
                "in al, dx", in("dx") self.base + u16::from(offset), out("al") value,
                options(nostack, preserves_flags),
            );
        }
        value
    }

    fn write8(&mut self, offset: u8, value: u8) {
        assert!(u16::from(offset) < PORT_BYTES);
        // SAFETY: claim's decoded-window, exclusive ownership and privilege contract.
        unsafe {
            core::arch::asm!(
                "out dx, al", in("dx") self.base + u16::from(offset), in("al") value,
                options(nostack, preserves_flags),
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub timeout_us: u64,
    pub poll_interval_us: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_us: 250_000,
            poll_interval_us: 250,
        }
    }
}

pub struct Piix4<R = PortIo, T = Clock> {
    registers: R,
    timer: T,
    info: ControllerInfo,
    config: Config,
    ready: bool,
}

impl<R: Registers, T: Timer> Piix4<R, T> {
    /// Instantiate the register engine after platform setup/ownership. This
    /// function neither enables the host nor chooses an AMD main/auxiliary port.
    pub fn new(
        registers: R,
        timer: T,
        info: ControllerInfo,
        config: Config,
    ) -> Result<Self, Error> {
        if config.timeout_us == 0
            || config.timeout_us < info.first_poll_us
            || config.poll_interval_us == 0
            || timer.check_duration(config.timeout_us).is_err()
        {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        let mut controller = Self {
            registers,
            timer,
            info,
            config,
            ready: true,
        };
        controller.prepare()?;
        Ok(controller)
    }

    fn error(kind: ErrorKind, status: u8, recovery: Recovery) -> Error {
        Error {
            kind,
            status,
            recovery,
        }
    }

    fn elapsed(&self, start: u64) -> u64 {
        self.timer.elapsed_us(start)
    }

    fn prepare(&mut self) -> Result<(), Error> {
        let status = self.registers.read8(HOST_STATUS);
        if status & HOST_BUSY != 0 {
            return Err(Self::error(ErrorKind::Busy, status, Recovery::NotAttempted));
        }
        if status & STATUS_FLAGS != 0 {
            self.registers.write8(HOST_STATUS, status & STATUS_FLAGS);
        }
        let remaining = self.registers.read8(HOST_STATUS);
        if remaining & (HOST_BUSY | STATUS_FLAGS) != 0 {
            return Err(Self::error(
                ErrorKind::StatusStuck,
                remaining,
                Recovery::NotAttempted,
            ));
        }
        self.registers.write8(HOST_CONTROL, 0);
        Ok(())
    }

    fn delay(&self, transaction_start: u64, delay: u64) {
        let start = self.timer.start();
        while self.elapsed(start) < delay
            && self.elapsed(transaction_start) < self.config.timeout_us
        {
            self.timer.relax();
        }
    }

    fn wait(&mut self, start: u64) -> Result<(), Error> {
        // PIIX4 errata require delaying the first completion observation.
        // CSB5 needs the longer delay recorded by its exact PCI match.
        self.delay(start, self.info.first_poll_us);
        loop {
            let status = self.registers.read8(HOST_STATUS);
            if let Some(kind) = Self::status_error(status) {
                return Err(Self::error(kind, status, Recovery::NotAttempted));
            }
            if self.elapsed(start) >= self.config.timeout_us {
                return Err(Self::error(
                    ErrorKind::Timeout(Phase::Completion),
                    status,
                    Recovery::NotAttempted,
                ));
            }
            if status & HOST_BUSY == 0 && status & INTR != 0 {
                return Ok(());
            }
            self.delay(start, self.config.poll_interval_us);
        }
    }

    fn status_error(status: u8) -> Option<ErrorKind> {
        if status & BUS_ERR != 0 {
            Some(ErrorKind::ArbitrationLost)
        } else if status & DEV_ERR != 0 {
            Some(ErrorKind::Device)
        } else if status & FAILED != 0 {
            Some(ErrorKind::Failed)
        } else {
            None
        }
    }

    fn finish(&mut self, error: Option<Error>) -> Result<(), Error> {
        self.finish_transfer(error, true)
    }

    fn finish_transfer(&mut self, mut error: Option<Error>, started: bool) -> Result<(), Error> {
        let status = self.registers.read8(HOST_STATUS);
        if error.is_none() {
            error = Self::status_error(status)
                .map(|kind| Self::error(kind, status, Recovery::NotAttempted));
            if error.is_none() && status & INTR == 0 {
                error = Some(Self::error(
                    ErrorKind::UnexpectedCompletion,
                    status,
                    Recovery::NotAttempted,
                ));
            }
        }
        let must_reset = status & (HOST_BUSY | BUS_ERR) != 0
            || error.is_some_and(|error| {
                error.kind == ErrorKind::ArbitrationLost
                    || started && matches!(error.kind, ErrorKind::Timeout(_))
            });
        if must_reset {
            self.ready = false;
            let mut failure = error
                .unwrap_or_else(|| Self::error(ErrorKind::NeedsReset, status, Recovery::Failed));
            failure.recovery = Recovery::Failed;
            return Err(failure);
        }
        // Preserve unknown/vendor status bits. These hosts have no I801 INUSE
        // read-to-acquire behavior, and writing bit 6 is not an unlock operation.
        self.registers.write8(HOST_STATUS, status & STATUS_FLAGS);
        self.registers.write8(HOST_CONTROL, 0);
        let remaining = self.registers.read8(HOST_STATUS);
        let recovery = if remaining & (HOST_BUSY | STATUS_FLAGS) == 0 {
            Recovery::Cleared
        } else {
            self.ready = false;
            error.get_or_insert(Self::error(
                ErrorKind::StatusStuck,
                remaining,
                Recovery::Failed,
            ));
            Recovery::Failed
        };
        if let Some(error) = &mut error {
            error.recovery = recovery;
        }
        error.map_or(Ok(()), Err)
    }

    /// Return the port accessor only after an acknowledged idle shutdown. A
    /// failure returns the controller alongside the error, keeping ownership
    /// until platform reset before its mux/semaphore may be restored.
    pub fn shutdown(mut self) -> Result<(R, T), (Self, Error)> {
        let result = if self.ready {
            self.prepare()
        } else {
            Err(ErrorKind::NeedsReset.into())
        };
        match result {
            Ok(()) => Ok((self.registers, self.timer)),
            Err(error) => Err((self, error)),
        }
    }

    fn target(&mut self, address: Address, read: bool, command: Option<u8>) {
        self.registers
            .write8(HOST_ADDRESS, address.get() << 1 | u8::from(read));
        if let Some(command) = command {
            self.registers.write8(HOST_COMMAND, command);
        }
    }

    fn transfer(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        start: u64,
    ) -> Result<(), Error> {
        let protocol = match &transaction {
            Transaction::SendByte(byte) => {
                self.target(address, false, Some(*byte));
                PROTOCOL_BYTE
            }
            Transaction::ReceiveByte(_) => {
                self.target(address, true, None);
                PROTOCOL_BYTE
            }
            Transaction::WriteByte { command, data } => {
                self.target(address, false, Some(*command));
                self.registers.write8(HOST_DATA0, *data);
                PROTOCOL_BYTE_DATA
            }
            Transaction::ReadByte { command, .. } => {
                self.target(address, true, Some(*command));
                PROTOCOL_BYTE_DATA
            }
            Transaction::WriteWord { command, data } => {
                self.target(address, false, Some(*command));
                let [low, high] = data.to_le_bytes();
                self.registers.write8(HOST_DATA0, low);
                self.registers.write8(HOST_DATA1, high);
                PROTOCOL_WORD_DATA
            }
            Transaction::ReadWord { command, .. } => {
                self.target(address, true, Some(*command));
                PROTOCOL_WORD_DATA
            }
            Transaction::WriteBlock { command, data } => {
                self.target(address, false, Some(*command));
                self.registers.write8(HOST_DATA0, data.len() as u8);
                self.registers.read8(HOST_CONTROL); // reset the host's array index
                for &byte in *data {
                    self.registers.write8(BLOCK_DATA, byte);
                }
                PROTOCOL_BLOCK
            }
            Transaction::ReadBlock { command, .. } => {
                self.target(address, true, Some(*command));
                PROTOCOL_BLOCK
            }
            Transaction::ProcessCall { .. } => unreachable!("validated before touching the host"),
        };
        // Do not read HSTCNT here: a read resets the block-array pointer.
        self.registers.write8(HOST_CONTROL, protocol);
        if self.elapsed(start) >= self.config.timeout_us {
            let status = self.registers.read8(HOST_STATUS);
            return self.finish_transfer(
                Some(Self::error(
                    ErrorKind::Timeout(Phase::Completion),
                    status,
                    Recovery::NotAttempted,
                )),
                false,
            );
        }
        self.registers.write8(HOST_CONTROL, protocol | START);
        if let Err(error) = self.wait(start) {
            return self.finish(Some(error));
        }
        let low = self.registers.read8(HOST_DATA0);
        let high = self.registers.read8(HOST_DATA1);
        let mut block = Block::default();
        if matches!(transaction, Transaction::ReadBlock { .. }) {
            let count = usize::from(low);
            if !(1..=MAX_BLOCK).contains(&count) {
                let status = self.registers.read8(HOST_STATUS);
                return self.finish(Some(Self::error(
                    ErrorKind::InvalidBlockLength(count),
                    status,
                    Recovery::NotAttempted,
                )));
            }
            self.registers.read8(HOST_CONTROL);
            for byte in &mut block.bytes[..count] {
                *byte = self.registers.read8(BLOCK_DATA);
            }
            block.length = count as u8;
        }
        self.finish(None)?;
        if self.elapsed(start) >= self.config.timeout_us {
            return Err(Self::error(
                ErrorKind::Timeout(Phase::Completion),
                self.registers.read8(HOST_STATUS),
                Recovery::Cleared,
            ));
        }
        match transaction {
            Transaction::ReceiveByte(data) | Transaction::ReadByte { data, .. } => *data = low,
            Transaction::ReadWord { data, .. } => *data = u16::from_le_bytes([low, high]),
            Transaction::ReadBlock { data, .. } => *data = block,
            _ => {}
        }
        Ok(())
    }
}

impl<R: Registers, T: Timer> Bus for Piix4<R, T> {
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), Error> {
        if pec {
            return Err(ErrorKind::UnsupportedPec.into());
        }
        if matches!(transaction, Transaction::ProcessCall { .. }) {
            return Err(ErrorKind::UnsupportedTransaction.into());
        }
        if let Transaction::WriteBlock { data, .. } = &transaction
            && !(1..=MAX_BLOCK).contains(&data.len())
        {
            return Err(ErrorKind::InvalidBlockLength(data.len()).into());
        }
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        let start = self.timer.start();
        self.prepare()?;
        self.transfer(address, transaction, start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod timer;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::{Cell, RefCell};

    /// Vendor/reserved bits are nonzero. They are neither an I801
    /// INUSE semaphore nor BYTE_DONE; every status write is checked against W1C.
    const OTHER_STATUS: u8 = 0xe0;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Request {
        protocol: u8,
        address: u8,
        command: u8,
        word: u16,
        block: Vec<u8>,
    }

    struct Model {
        registers: [u8; 9],
        status: u8,
        time: Rc<Cell<u64>>,
        completion_at: Option<u64>,
        latency: u64,
        requests: Vec<Request>,
        writes: Vec<(u8, u8)>,
        active_status_reads: Vec<u64>,
        reply_word: u16,
        reply_block: Vec<u8>,
        block_buffer: [u8; MAX_BLOCK],
        block_index: usize,
        block_resets: usize,
        pending: bool,
        freeze: bool,
        error: u8,
        late_error: u8,
        stuck_status: u8,
        missing_intr: bool,
    }

    impl Model {
        fn new(time: Rc<Cell<u64>>) -> Self {
            Self {
                registers: [0; 9],
                status: OTHER_STATUS,
                time,
                completion_at: None,
                latency: 400,
                requests: Vec::new(),
                writes: Vec::new(),
                active_status_reads: Vec::new(),
                reply_word: 0xabcd,
                reply_block: vec![4, 5, 6],
                block_buffer: [0; MAX_BLOCK],
                block_index: 0,
                block_resets: 0,
                pending: false,
                freeze: false,
                error: 0,
                late_error: 0,
                stuck_status: 0,
                missing_intr: false,
            }
        }

        fn step(&mut self) {
            if self.freeze || !self.completion_at.is_some_and(|at| self.time.get() >= at) {
                return;
            }
            self.completion_at = None;
            self.pending = false;
            self.status &= !HOST_BUSY;
            if self.error != 0 {
                self.status |= self.error;
                return;
            }
            let request = self.requests.last().unwrap();
            if request.address & 1 != 0 {
                if request.protocol == PROTOCOL_BLOCK {
                    self.registers[usize::from(HOST_DATA0)] = self.reply_block.len() as u8;
                    for (to, &from) in self.block_buffer.iter_mut().zip(&self.reply_block) {
                        *to = from;
                    }
                } else {
                    let [low, high] = self.reply_word.to_le_bytes();
                    self.registers[usize::from(HOST_DATA0)] = low;
                    self.registers[usize::from(HOST_DATA1)] = high;
                }
            }
            if !self.missing_intr {
                self.status |= INTR;
            }
        }

        fn read(&mut self, offset: u8) -> u8 {
            assert!(offset <= 8, "access outside the PIIX4 host window");
            if offset == HOST_STATUS && self.pending {
                self.active_status_reads.push(self.time.get());
            }
            self.step();
            match offset {
                HOST_STATUS => self.status,
                HOST_CONTROL => {
                    self.block_index = 0;
                    self.block_resets += 1;
                    self.registers[usize::from(HOST_CONTROL)] & !START
                }
                BLOCK_DATA => {
                    assert!(!self.pending, "read array before host completed");
                    let byte = self.block_buffer[self.block_index];
                    self.block_index += 1;
                    byte
                }
                HOST_DATA0 => {
                    self.status |= self.late_error;
                    self.registers[usize::from(HOST_DATA0)]
                }
                _ => self.registers[usize::from(offset)],
            }
        }

        fn write(&mut self, offset: u8, value: u8) {
            assert!(offset <= 8, "access outside the PIIX4 host window");
            self.step();
            self.writes.push((offset, value));
            match offset {
                HOST_STATUS => {
                    assert_eq!(
                        value & !STATUS_FLAGS,
                        0,
                        "non-W1C or I801-only bits written"
                    );
                    self.status &= !(value & !self.stuck_status);
                }
                HOST_CONTROL if value & START != 0 => {
                    assert!(
                        !self.pending && self.status & HOST_BUSY == 0,
                        "START on a busy host"
                    );
                    assert_eq!(value & 3, 0, "interrupt/KILL must not be enabled");
                    let protocol = value & 0x1c;
                    let address = self.registers[usize::from(HOST_ADDRESS)];
                    let block = if protocol == PROTOCOL_BLOCK && address & 1 == 0 {
                        let count = usize::from(self.registers[usize::from(HOST_DATA0)]);
                        assert!((1..=MAX_BLOCK).contains(&count));
                        self.block_buffer[..count].to_vec()
                    } else {
                        Vec::new()
                    };
                    self.requests.push(Request {
                        protocol,
                        address,
                        command: self.registers[usize::from(HOST_COMMAND)],
                        word: u16::from_le_bytes([
                            self.registers[usize::from(HOST_DATA0)],
                            self.registers[usize::from(HOST_DATA1)],
                        ]),
                        block,
                    });
                    self.pending = true;
                    self.completion_at = Some(self.time.get() + self.latency);
                    self.status |= HOST_BUSY;
                    self.registers[usize::from(offset)] = value;
                }
                BLOCK_DATA => {
                    assert!(!self.pending, "write array while host owns it");
                    self.block_buffer[self.block_index] = value;
                    self.block_index += 1;
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

    type Controller = Piix4<RegisterModel, ModelTimer>;

    fn controller(vendor: u16, device: u16, revision: u8) -> (Controller, Rc<RefCell<Model>>) {
        let time = Rc::new(Cell::new(0));
        let state = Rc::new(RefCell::new(Model::new(time.clone())));
        let info = ControllerInfo::from_pci_id(vendor, device, revision).unwrap();
        let controller = Piix4::new(
            RegisterModel(state.clone()),
            ModelTimer(time),
            info,
            Config {
                timeout_us: 5000,
                poll_interval_us: 250,
            },
        )
        .unwrap();
        (controller, state)
    }

    fn address() -> Address {
        Address::new(0x2c).unwrap()
    }

    #[test]
    fn simple_protocols_set_correct_direction_command_and_little_endian_data() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        let (mut byte, mut word) = (0, 0);
        for transaction in [
            Transaction::SendByte(1),
            Transaction::ReceiveByte(&mut byte),
            Transaction::WriteByte {
                command: 2,
                data: 3,
            },
            Transaction::WriteWord {
                command: 4,
                data: 0x5678,
            },
            Transaction::ReadWord {
                command: 5,
                data: &mut word,
            },
        ] {
            controller
                .transaction(address(), transaction, false)
                .unwrap();
        }
        assert_eq!((byte, word), (0xcd, 0xabcd));
        controller
            .transaction(
                address(),
                Transaction::ReadByte {
                    command: 6,
                    data: &mut byte,
                },
                false,
            )
            .unwrap();
        let state = state.borrow();
        assert_eq!(state.requests[0].protocol, 4);
        assert_eq!(
            (state.requests[0].address, state.requests[0].command),
            (0x58, 1)
        );
        assert_eq!(
            (state.requests[1].protocol, state.requests[1].address),
            (4, 0x59)
        );
        assert_eq!(
            (
                state.requests[2].protocol,
                state.requests[2].command,
                state.requests[2].word as u8
            ),
            (8, 2, 3)
        );
        assert_eq!(
            (
                state.requests[3].protocol,
                state.requests[3].command,
                state.requests[3].word
            ),
            (12, 4, 0x5678)
        );
        assert_eq!(
            (state.requests[4].protocol, state.requests[4].address),
            (12, 0x59)
        );
        assert_eq!(
            (
                state.requests[5].protocol,
                state.requests[5].address,
                state.requests[5].command
            ),
            (8, 0x59, 6)
        );
        assert_eq!(state.status, OTHER_STATUS);
        assert_eq!(state.block_resets, 0);
    }

    #[test]
    fn block_array_index_resets_preserve_every_length_and_successive_transactions() {
        for (vendor, device, revision) in [
            (0x8086, 0x7113, 0),
            (0x1002, 0x4385, 0x3f),
            (0x1002, 0x4385, 0x40),
            (0x1022, 0x780b, 0x41),
            (0x1022, 0x790b, 0x51),
        ] {
            let (mut controller, state) = controller(vendor, device, revision);
            for count in (1..=MAX_BLOCK).rev() {
                let bytes: Vec<_> = (0..count).map(|i| (i * 3 + count) as u8).collect();
                controller
                    .transaction(
                        address(),
                        Transaction::WriteBlock {
                            command: 1,
                            data: &bytes,
                        },
                        false,
                    )
                    .unwrap();
                assert_eq!(state.borrow().requests.last().unwrap().block, bytes);
                state.borrow_mut().reply_block = bytes.clone();
                let mut result = Block::default();
                controller
                    .transaction(
                        address(),
                        Transaction::ReadBlock {
                            command: 2,
                            data: &mut result,
                        },
                        false,
                    )
                    .unwrap();
                assert_eq!(result.as_slice(), bytes);
                assert_eq!(state.borrow().status, OTHER_STATUS);
            }
            assert_eq!(state.borrow().block_resets, MAX_BLOCK * 2);
        }
    }

    #[test]
    fn a_preexisting_busy_owner_is_neither_reset_nor_reprogrammed() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        state.borrow_mut().status |= HOST_BUSY;
        let writes = state.borrow().writes.len();
        let error = controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Busy);
        assert_eq!(error.recovery, Recovery::NotAttempted);
        assert_eq!(state.borrow().writes.len(), writes);
        assert!(state.borrow().requests.is_empty());
    }

    #[test]
    fn device_and_failed_errors_preserve_status_without_publishing_outputs() {
        for (status, kind) in [(DEV_ERR, ErrorKind::Device), (FAILED, ErrorKind::Failed)] {
            let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
            state.borrow_mut().error = status;
            let mut value = 0x1234;
            let error = controller
                .transaction(
                    address(),
                    Transaction::ReadWord {
                        command: 1,
                        data: &mut value,
                    },
                    false,
                )
                .unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(error.status, OTHER_STATUS | status);
            assert_eq!(error.recovery, Recovery::Cleared);
            assert_eq!(value, 0x1234);
            assert_eq!(state.borrow().status, OTHER_STATUS);
            state.borrow_mut().error = 0;
            controller
                .transaction(address(), Transaction::SendByte(2), false)
                .unwrap();
        }
    }

    #[test]
    fn collision_requires_platform_reset_even_if_the_busy_bit_clears() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        state.borrow_mut().error = BUS_ERR;
        let error = controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::ArbitrationLost);
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(state.borrow().status & HOST_BUSY, 0);
        let writes = state.borrow().writes.len();
        assert_eq!(
            controller
                .transaction(address(), Transaction::SendByte(2), false)
                .unwrap_err()
                .kind,
            ErrorKind::NeedsReset
        );
        assert_eq!(state.borrow().writes.len(), writes);
        assert!(controller.shutdown().is_err());
    }

    #[test]
    fn timeout_is_bounded_poisoned_and_does_not_apply_i801_kill_semantics() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        state.borrow_mut().freeze = true;
        let error = controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(state.borrow().time.get(), 5000);
        assert_eq!(
            state.borrow().registers[usize::from(HOST_CONTROL)],
            PROTOCOL_BYTE | START
        );
        let writes = state.borrow().writes.len();
        assert_eq!(
            controller
                .transaction(address(), Transaction::SendByte(2), false)
                .unwrap_err()
                .kind,
            ErrorKind::NeedsReset
        );
        assert_eq!(state.borrow().writes.len(), writes);
    }

    #[test]
    fn busy_clear_without_completion_is_not_reported_as_success() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        state.borrow_mut().missing_intr = true;
        let error = controller
            .transaction(address(), Transaction::SendByte(1), false)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Completion));
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(state.borrow().status, OTHER_STATUS);
    }

    #[test]
    fn invalid_block_counts_and_late_errors_keep_previous_read_outputs() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        let mut output = Block::default();
        controller
            .transaction(
                address(),
                Transaction::ReadBlock {
                    command: 1,
                    data: &mut output,
                },
                false,
            )
            .unwrap();
        let previous = output.clone();
        for count in [0, 33, 255] {
            state.borrow_mut().reply_block = vec![1; count];
            let error = controller
                .transaction(
                    address(),
                    Transaction::ReadBlock {
                        command: 1,
                        data: &mut output,
                    },
                    false,
                )
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::InvalidBlockLength(count));
            assert_eq!(error.recovery, Recovery::Cleared);
            assert_eq!(output, previous);
        }
        state.borrow_mut().late_error = DEV_ERR;
        let mut word = 0x4567;
        let error = controller
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 1,
                    data: &mut word,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Device);
        assert_eq!(word, 0x4567);
    }

    #[test]
    fn a_stuck_w1c_completion_is_an_error_and_requires_reset() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        state.borrow_mut().stuck_status = INTR;
        let mut word = 0x4567;
        let error = controller
            .transaction(
                address(),
                Transaction::ReadWord {
                    command: 1,
                    data: &mut word,
                },
                false,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::StatusStuck);
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(word, 0x4567);
    }

    #[test]
    fn pci_revision_layout_boundaries_match_the_pinned_linux_paths() {
        let info = |vendor, device, revision| {
            ControllerInfo::from_pci_id(vendor, device, revision).unwrap()
        };
        assert_eq!(
            info(0x1002, 0x4385, 0x3f).base_registers(),
            BaseRegisters::LegacyPci
        );
        assert_eq!(
            info(0x1002, 0x4385, 0x40).base_registers(),
            BaseRegisters::Sb800
        );
        assert_eq!(
            info(0x1002, 0x4385, 0x40).port_selection(),
            PortSelection::Sb800Selectable
        );
        assert_eq!(
            (
                info(0x1022, 0x780b, 0x1e).main_ports(),
                info(0x1022, 0x780b, 0x1e).port_selection()
            ),
            (4, PortSelection::HudsonEarly)
        );
        assert_eq!(
            (
                info(0x1022, 0x780b, 0x1f).main_ports(),
                info(0x1022, 0x780b, 0x1f).port_selection()
            ),
            (2, PortSelection::DecodeEn)
        );
        assert_eq!(
            info(0x1022, 0x780b, 0x40).base_registers(),
            BaseRegisters::Sb800
        );
        assert_eq!(
            info(0x1022, 0x780b, 0x41).base_registers(),
            BaseRegisters::PmDecode
        );
        assert_eq!(
            info(0x1022, 0x790b, 0x48).base_registers(),
            BaseRegisters::Sb800
        );
        assert_eq!(
            info(0x1022, 0x790b, 0x49).base_registers(),
            BaseRegisters::PmDecode
        );
        assert_eq!(info(0x1022, 0x790b, 0x50).pm_access(), PmAccess::IndexedIo);
        assert_eq!(info(0x1022, 0x790b, 0x51).pm_access(), PmAccess::Mmio);
        assert_eq!(info(0x1d94, 0x790b, 0x51).pm_access(), PmAccess::IndexedIo);
        assert_eq!(
            info(0x1d94, 0x790b, 0).base_registers(),
            BaseRegisters::PmDecode
        );
        assert!(ControllerInfo::from_pci_id(0x8086, 0x7aa3, 0).is_none());
        assert!(ControllerInfo::from_pci_id(0x1022, 0xffff, 0).is_none());
    }

    #[test]
    fn the_first_status_poll_obeys_piix4_and_csb5_errata_delays() {
        for (vendor, device, first) in [(0x8086, 0x7113, 250), (0x1166, 0x0201, 2000)] {
            let (mut controller, state) = controller(vendor, device, 0);
            controller
                .transaction(address(), Transaction::SendByte(1), false)
                .unwrap();
            assert_eq!(state.borrow().active_status_reads[0], first);
        }
    }

    #[test]
    fn unsupported_protocols_and_invalid_write_lengths_do_not_touch_the_host() {
        let (mut controller, state) = controller(0x1022, 0x790b, 0x51);
        let writes = state.borrow().writes.len();
        assert_eq!(
            controller
                .transaction(address(), Transaction::SendByte(1), true)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedPec
        );
        let mut word = 0;
        assert_eq!(
            controller
                .transaction(
                    address(),
                    Transaction::ProcessCall {
                        command: 1,
                        request: 2,
                        response: &mut word
                    },
                    false
                )
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedTransaction
        );
        for data in [&[][..], &[0; 33][..]] {
            assert_eq!(
                controller
                    .transaction(
                        address(),
                        Transaction::WriteBlock { command: 1, data },
                        false
                    )
                    .unwrap_err()
                    .kind,
                ErrorKind::InvalidBlockLength(data.len())
            );
        }
        assert_eq!(state.borrow().writes.len(), writes);
    }
}
