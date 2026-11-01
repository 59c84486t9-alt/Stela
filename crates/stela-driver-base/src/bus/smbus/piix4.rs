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
use crate::{
    Clock,
    bus::{i2c::Timer, port},
};

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
        // SAFETY: claim's decoded-window, exclusive ownership and privilege contract.
        unsafe { port::read8(self.base + u16::from(offset)) }
    }

    fn write8(&mut self, offset: u8, value: u8) {
        assert!(u16::from(offset) < PORT_BYTES);
        // SAFETY: claim's decoded-window, exclusive ownership and privilege contract.
        unsafe { port::write8(self.base + u16::from(offset), value) }
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
mod tests;
