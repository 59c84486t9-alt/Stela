// SPDX-License-Identifier: GPL-2.0-or-later
//
// Linux DesignWare I2C master FIFO and abort handling adapted to a polled Rust
// controller at a804c5742bff224d4cb4d25dd383554d598be32b:
// drivers/i2c/busses/i2c-designware-master.c
// SHA-256 e73845fed46c45702ada39d6dfb30ed7c48c71990cf4e68e20456b57f55bb9ae
// drivers/i2c/busses/i2c-designware-core.h
// SHA-256 31cc6f6e90ea42adfdcf2b695e105f479a3a9c7be64d48484d805448070d1626
//
// Synopsys DesignWare I2C adapter driver (master only).
// Based on the TI DAVINCI I2C adapter driver.
// Copyright (C) 2006 Texas Instruments.
// Copyright (C) 2007 MontaVista Software Inc.
// Copyright (C) 2009 Provigent Ltd.
//
//! Register-level master engine. Tests run this same engine against a controller
//! model, not a replacement implementation of the bus transaction API.
use super::{AbortKind, Address, Bus, Clock, Error, ErrorKind, Operation, Phase, Recovery, Timer};
use crate::bus::mmio::Mmio;

const CON: usize = 0x00;
const TAR: usize = 0x04;
const DATA_CMD: usize = 0x10;
const SS_SCL_HCNT: usize = 0x14;
const SS_SCL_LCNT: usize = 0x18;
const FS_SCL_HCNT: usize = 0x1c;
const FS_SCL_LCNT: usize = 0x20;
const INTR_MASK: usize = 0x30;
const RAW_INTR_STAT: usize = 0x34;
const RX_TL: usize = 0x38;
const TX_TL: usize = 0x3c;
const CLR_INTR: usize = 0x40;
const CLR_TX_ABRT: usize = 0x54;
const CLR_STOP_DET: usize = 0x60;
const ENABLE: usize = 0x6c;
const STATUS: usize = 0x70;
const TXFLR: usize = 0x74;
const RXFLR: usize = 0x78;
const SDA_HOLD: usize = 0x7c;
const TX_ABRT_SOURCE: usize = 0x80;
const DMA_CR: usize = 0x88;
const ENABLE_STATUS: usize = 0x9c;
const COMP_PARAM_1: usize = 0xf4;
const COMP_VERSION: usize = 0xf8;
const COMP_TYPE: usize = 0xfc;

const COMPONENT_TYPE: u32 = 0x4457_0140;
const SDA_HOLD_VERSION: u32 = 0x3131_312a;
const PARAM_ENCODED: u32 = 1 << 7;
const PARAM_WIDTH_32: u32 = 2;
const CON_MASTER: u32 = 1;
const CON_STANDARD: u32 = 1 << 1;
const CON_FAST: u32 = 2 << 1;
const CON_TEN_BIT: u32 = 1 << 4;
const CON_RESTART: u32 = 1 << 5;
const CON_SLAVE_DISABLE: u32 = 1 << 6;
const TAR_TEN_BIT: u32 = 1 << 12;
const CMD_READ: u32 = 1 << 8;
const CMD_STOP: u32 = 1 << 9;
const CMD_RESTART: u32 = 1 << 10;
const ENABLE_ON: u32 = 1;
const ENABLE_ABORT: u32 = 1 << 1;
const STATUS_ACTIVE: u32 = 1;
const STATUS_TX_EMPTY: u32 = 1 << 2;
const STATUS_MASTER_ACTIVE: u32 = 1 << 5;
const INTR_RX_UNDER: u32 = 1;
const INTR_RX_OVER: u32 = 1 << 1;
const INTR_TX_OVER: u32 = 1 << 3;
const INTR_TX_ABRT: u32 = 1 << 6;
const INTR_STOP_DET: u32 = 1 << 9;
const INTR_FIFO_ERROR: u32 = INTR_RX_UNDER | INTR_RX_OVER | INTR_TX_OVER;
const ABRT_ADDRESS_NACK: u32 = 0b111;
const ABRT_DATA_NACK: u32 = 1 << 3;
const ABRT_ARBITRATION_LOST: u32 = 1 << 12;

/// Exclusive access to a conventional DesignWare register block. An
/// implementation must preserve ordered, volatile 32-bit register semantics.
/// The trait is public so independent models can exercise the actual driver.
pub trait Registers {
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
}

/// A uniquely owned, identity-mapped, uncached DesignWare register window.
pub struct MmioRegisters(Mmio);

impl MmioRegisters {
    /// # Safety
    ///
    /// `base..base + 0x100` must be mapped uncached, aligned to four bytes,
    /// owned exclusively for this object's lifetime, and backed by a powered
    /// DesignWare controller. The platform must provide clocks and reset first.
    /// Neither firmware, an IRQ handler nor another CPU may access the window.
    pub unsafe fn new(base: u64) -> Self {
        // SAFETY: covered by this function's own safety contract.
        Self(unsafe { Mmio::new(base) })
    }
}

impl Registers for MmioRegisters {
    fn read32(&mut self, offset: usize) -> u32 {
        self.0.read32(offset)
    }

    fn write32(&mut self, offset: usize, value: u32) {
        self.0.write32(offset, value);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speed {
    Standard,
    Fast,
}

impl Speed {
    fn control(self) -> u32 {
        match self {
            Self::Standard => CON_STANDARD,
            Self::Fast => CON_FAST,
        }
    }
}

/// Register counts already calculated or read from the platform firmware for
/// the controller input clock and the board's rise/fall times. This is not a
/// bus frequency in Hz; guessing counts can violate a peripheral's timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub speed: Speed,
    pub scl_high: u16,
    pub scl_low: u16,
    /// SDA_HOLD's TX count (low 16 bits) and RX count (bits 16–23). `None`
    /// keeps the firmware value; programming requires core version >= 1.11*.
    pub sda_hold: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub timing: Timing,
    /// Total bound for the transaction, including bus acquisition and STOP.
    pub timeout_us: u64,
    /// Additional bound for disable/abort on initialization or error cleanup.
    pub recovery_timeout_us: u64,
}

/// Master-mode engine using PIO FIFOs, with interrupts and DMA disabled.
/// Standard/fast mode and 7-/10-bit unicast addressing are implemented.
/// High-speed mode, target mode, SMBus quick/PEC and GPIO bus clear are not.
pub struct DesignWare<R = MmioRegisters, T = Clock> {
    registers: R,
    timer: T,
    config: Config,
    tx_depth: usize,
    rx_depth: usize,
    control: u32,
    ready: bool,
}

impl<R: Registers, T: Timer> DesignWare<R, T> {
    pub fn new(mut registers: R, timer: T, config: Config) -> Result<Self, Error> {
        if config.timeout_us == 0
            || config.recovery_timeout_us == 0
            || config.timing.scl_high < 6
            || config.timing.scl_low < 8
            || config
                .timing
                .sda_hold
                .is_some_and(|hold| hold > 0x00ff_ffff)
        {
            return Err(ErrorKind::InvalidConfiguration.into());
        }
        let component = registers.read32(COMP_TYPE);
        if component != COMPONENT_TYPE {
            return Err(ErrorKind::ComponentType(component).into());
        }
        let parameters = registers.read32(COMP_PARAM_1);
        let tx_depth = (((parameters >> 16) & 0xff) + 1) as usize;
        let rx_depth = (((parameters >> 8) & 0xff) + 1) as usize;
        let max_speed = (parameters >> 2) & 3;
        if parameters & PARAM_ENCODED == 0
            || parameters & 3 != PARAM_WIDTH_32
            || tx_depth < 2
            || rx_depth < 2
            || max_speed == 0
            || (config.timing.speed == Speed::Fast && max_speed < 2)
        {
            return Err(ErrorKind::ComponentParameters(parameters).into());
        }
        if config.timing.sda_hold.is_some() {
            let version = registers.read32(COMP_VERSION);
            if version < SDA_HOLD_VERSION {
                return Err(ErrorKind::UnsupportedVersion(version).into());
            }
        }
        let control = CON_MASTER | CON_RESTART | CON_SLAVE_DISABLE | config.timing.speed.control();
        let mut controller = Self {
            registers,
            timer,
            config,
            tx_depth,
            rx_depth,
            control,
            ready: false,
        };
        if !controller.quiesce() {
            return Err(Error {
                kind: ErrorKind::Timeout(Phase::Disable),
                recovery: Recovery::Failed,
            });
        }
        controller.registers.write32(INTR_MASK, 0);
        controller.registers.write32(DMA_CR, 0);
        controller.registers.write32(CON, control);
        controller.registers.write32(RX_TL, 0);
        controller.registers.write32(TX_TL, 0);
        let (high, low) = match config.timing.speed {
            Speed::Standard => (SS_SCL_HCNT, SS_SCL_LCNT),
            Speed::Fast => (FS_SCL_HCNT, FS_SCL_LCNT),
        };
        controller
            .registers
            .write32(high, u32::from(config.timing.scl_high));
        controller
            .registers
            .write32(low, u32::from(config.timing.scl_low));
        if let Some(hold) = config.timing.sda_hold {
            controller.registers.write32(SDA_HOLD, hold);
        }
        if controller.registers.read32(high) != u32::from(config.timing.scl_high)
            || controller.registers.read32(low) != u32::from(config.timing.scl_low)
            || config
                .timing
                .sda_hold
                .is_some_and(|hold| controller.registers.read32(SDA_HOLD) != hold)
        {
            return Err(ErrorKind::TimingRejected.into());
        }
        controller.ready = true;
        Ok(controller)
    }

    /// Expose ownership of the disabled register window to a platform reset
    /// path. A failed disable is explicit; it must not be treated as quiescent.
    pub fn shutdown(mut self) -> Result<(R, T), Error> {
        if self.quiesce() {
            Ok((self.registers, self.timer))
        } else {
            Err(Error {
                kind: ErrorKind::Timeout(Phase::Disable),
                recovery: Recovery::Failed,
            })
        }
    }

    pub fn fifo_depths(&self) -> (usize, usize) {
        (self.tx_depth, self.rx_depth)
    }

    fn expired(&self, start: u64, timeout: u64) -> bool {
        self.timer.now_us().wrapping_sub(start) >= timeout
    }

    fn wait_until(
        &mut self,
        start: u64,
        timeout: u64,
        mut ready: impl FnMut(&mut R) -> bool,
    ) -> bool {
        loop {
            if ready(&mut self.registers) {
                return true;
            }
            if self.expired(start, timeout) {
                return false;
            }
            self.timer.relax();
        }
    }

    /// Abort releases a master holding SCL on an empty TX FIFO; disable then
    /// flushes any unread FIFO entries. Never spin forever on wedged hardware.
    fn quiesce(&mut self) -> bool {
        let start = self.timer.now_us();
        if self.registers.read32(ENABLE_STATUS) & ENABLE_ON != 0
            && self.registers.read32(STATUS) & STATUS_MASTER_ACTIVE != 0
        {
            self.registers.write32(ENABLE, ENABLE_ON | ENABLE_ABORT);
            let _aborted = self.wait_until(start, self.config.recovery_timeout_us, |registers| {
                registers.read32(ENABLE) & ENABLE_ABORT == 0
            });
        }
        self.registers.write32(ENABLE, 0);
        let disabled = self.wait_until(start, self.config.recovery_timeout_us, |registers| {
            registers.read32(ENABLE_STATUS) & ENABLE_ON == 0
        });
        if disabled {
            self.registers.write32(INTR_MASK, 0);
            self.registers.write32(DMA_CR, 0);
            self.registers.read32(CLR_INTR);
        }
        self.ready = disabled;
        disabled
    }

    fn faults(&mut self) -> Result<u32, ErrorKind> {
        let interrupts = self.registers.read32(RAW_INTR_STAT);
        if interrupts & INTR_TX_ABRT != 0 {
            // CLR_INTR/CLR_TX_ABRT also erase the reason. Capture it first.
            let source = self.registers.read32(TX_ABRT_SOURCE);
            self.registers.read32(CLR_TX_ABRT);
            let kind = if source & ABRT_ARBITRATION_LOST != 0 {
                AbortKind::ArbitrationLost
            } else if source & ABRT_ADDRESS_NACK != 0 {
                AbortKind::AddressNack
            } else if source & ABRT_DATA_NACK != 0 {
                AbortKind::DataNack
            } else {
                AbortKind::Other
            };
            return Err(ErrorKind::Aborted { kind, source });
        }
        if interrupts & INTR_FIFO_ERROR != 0 {
            return Err(ErrorKind::Fifo { interrupts });
        }
        Ok(interrupts)
    }

    fn transfer(
        &mut self,
        address: Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), ErrorKind> {
        let start = self.timer.now_us();
        if !self.wait_until(start, self.config.timeout_us, |registers| {
            registers.read32(STATUS) & STATUS_ACTIVE == 0
        }) {
            return Err(ErrorKind::Timeout(Phase::BusIdle));
        }
        self.registers.read32(CLR_INTR);
        let (target, address_control) = match address {
            Address::SevenBit(address) => (u32::from(address), 0),
            Address::TenBit(address) => (u32::from(address) | TAR_TEN_BIT, CON_TEN_BIT),
        };
        self.registers.write32(CON, self.control | address_control);
        self.registers.write32(TAR, target);
        self.registers.write32(ENABLE, ENABLE_ON);
        if !self.wait_until(start, self.config.timeout_us, |registers| {
            registers.read32(ENABLE_STATUS) & ENABLE_ON != 0
        }) {
            return Err(ErrorKind::Timeout(Phase::Enable));
        }

        let final_message = operations.len() - 1;
        for (message, operation) in operations.iter_mut().enumerate() {
            let (mut queued, mut received) = (0, 0);
            let count = operation.len();
            loop {
                let interrupts = self.faults()?;
                if interrupts & INTR_STOP_DET != 0 {
                    // A STOP cannot belong to our final byte while more
                    // commands remain in the hardware's TX FIFO. Merely
                    // having queued every message does not prove completion.
                    if message != final_message
                        || queued != count
                        || self.registers.read32(TXFLR) != 0
                    {
                        return Err(ErrorKind::UnexpectedStop);
                    }
                }
                let available = self.registers.read32(RXFLR) as usize;
                if available > self.rx_depth {
                    return Err(ErrorKind::UnexpectedReceive);
                }
                if available != 0 {
                    match operation {
                        Operation::Read(bytes) if available <= queued - received => {
                            for byte in &mut bytes[received..received + available] {
                                *byte = self.registers.read32(DATA_CMD) as u8;
                            }
                            received += available;
                        }
                        _ => return Err(ErrorKind::UnexpectedReceive),
                    }
                }
                let pending = self.registers.read32(TXFLR) as usize;
                if pending > self.tx_depth {
                    return Err(ErrorKind::Fifo {
                        interrupts: INTR_TX_OVER,
                    });
                }
                let room = self.tx_depth - pending;
                let is_read = matches!(operation, Operation::Read(_));
                // Every queued read will eventually occupy RX FIFO space,
                // including requests still in the TX FIFO or on the wire.
                let read_room = if is_read {
                    self.rx_depth - (queued - received)
                } else {
                    usize::MAX
                };
                let issue = (count - queued).min(room).min(read_room);
                for _ in 0..issue {
                    let mut command = match operation {
                        Operation::Write(bytes) => u32::from(bytes[queued]),
                        Operation::Read(_) => CMD_READ,
                    };
                    if message != 0 && queued == 0 {
                        command |= CMD_RESTART;
                    }
                    if message == final_message && queued == count - 1 {
                        command |= CMD_STOP;
                    }
                    self.registers.write32(DATA_CMD, command);
                    queued += 1;
                }
                if queued == count && (!is_read || received == count) {
                    break;
                }
                if self.expired(start, self.config.timeout_us) {
                    return Err(ErrorKind::Timeout(Phase::Transfer));
                }
                self.timer.relax();
            }
        }
        loop {
            let interrupts = self.faults()?;
            if interrupts & INTR_STOP_DET != 0 && self.registers.read32(TXFLR) != 0 {
                return Err(ErrorKind::UnexpectedStop);
            }
            let status = self.registers.read32(STATUS);
            if interrupts & INTR_STOP_DET != 0
                && status & (STATUS_TX_EMPTY | STATUS_ACTIVE) == STATUS_TX_EMPTY
            {
                if self.registers.read32(RXFLR) != 0 {
                    return Err(ErrorKind::UnexpectedReceive);
                }
                self.registers.read32(CLR_STOP_DET);
                return Ok(());
            }
            if self.expired(start, self.config.timeout_us) {
                return Err(ErrorKind::Timeout(Phase::Stop));
            }
            self.timer.relax();
        }
    }
}

impl<R: Registers, T: Timer> Bus for DesignWare<R, T> {
    fn transaction(
        &mut self,
        address: Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Error> {
        address.validate()?;
        if operations.is_empty() {
            return Err(ErrorKind::EmptyTransaction.into());
        }
        if operations.iter().any(|operation| operation.len() == 0) {
            return Err(ErrorKind::EmptyMessage.into());
        }
        if !self.ready {
            return Err(ErrorKind::NeedsReset.into());
        }
        let result = self.transfer(address, operations);
        let disabled = self.quiesce();
        match result {
            Ok(()) if disabled => Ok(()),
            result => Err(Error {
                kind: result.err().unwrap_or(ErrorKind::Timeout(Phase::Disable)),
                recovery: if disabled {
                    Recovery::Disabled
                } else {
                    Recovery::Failed
                },
            }),
        }
    }
}

#[cfg(test)]
mod tests;
