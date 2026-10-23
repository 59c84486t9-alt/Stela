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
const SMBUS_INTR_MASK: usize = 0xcc;
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
        controller.registers.write32(SMBUS_INTR_MASK, 0);
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
            let observed = ready(&mut self.registers);
            if self.expired(start, timeout) {
                return false;
            }
            if observed {
                return true;
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
        let mut disabled = self.wait_until(start, self.config.recovery_timeout_us, |registers| {
            registers.read32(ENABLE_STATUS) & ENABLE_ON == 0
        });
        if disabled {
            self.registers.write32(INTR_MASK, 0);
            // Firmware may leave IC_SMBUS enabled independently of the
            // ordinary interrupt mask. No SMBus interrupt is serviced here.
            self.registers.write32(SMBUS_INTR_MASK, 0);
            self.registers.write32(DMA_CR, 0);
            self.registers.read32(CLR_INTR);
            disabled = !self.expired(start, self.config.recovery_timeout_us);
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

    fn transaction_deadline(&self, start: u64, phase: Phase) -> Result<(), ErrorKind> {
        if self.expired(start, self.config.timeout_us) {
            Err(ErrorKind::Timeout(phase))
        } else {
            Ok(())
        }
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
        self.transaction_deadline(start, Phase::Enable)?;
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
                self.transaction_deadline(start, Phase::Transfer)?;
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
                self.transaction_deadline(start, Phase::Transfer)?;
                if available > self.rx_depth {
                    return Err(ErrorKind::UnexpectedReceive);
                }
                if available != 0 {
                    match operation {
                        Operation::Read(bytes) if available <= queued - received => {
                            for byte in &mut bytes[received..received + available] {
                                let observed = self.registers.read32(DATA_CMD) as u8;
                                self.transaction_deadline(start, Phase::Transfer)?;
                                *byte = observed;
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
                    // No target/status/payload observation may spend the
                    // remaining budget and still permit a later wire command.
                    self.transaction_deadline(start, Phase::Transfer)?;
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
            self.transaction_deadline(start, Phase::Stop)?;
            if interrupts & INTR_STOP_DET != 0
                && status & (STATUS_TX_EMPTY | STATUS_ACTIVE) == STATUS_TX_EMPTY
            {
                let remaining = self.registers.read32(RXFLR);
                self.transaction_deadline(start, Phase::Stop)?;
                if remaining != 0 {
                    return Err(ErrorKind::UnexpectedReceive);
                }
                self.registers.read32(CLR_STOP_DET);
                self.transaction_deadline(start, Phase::Stop)?;
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
mod tests {
    use super::*;
    use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
    use core::cell::{Cell, RefCell};

    /// A wire peer and finite hardware FIFOs, driven only when emulated time moves.
    /// FIFO overflow/underflow are latched independently of the driver's accounting.
    struct Model {
        words: [u32; 64],
        time: Rc<Cell<u64>>,
        tx: VecDeque<u32>,
        rx: VecDeque<u8>,
        replies: VecDeque<u8>,
        commands: Vec<u32>,
        events: Vec<Event>,
        writes: Vec<(usize, u32)>,
        tx_depth: usize,
        rx_depth: usize,
        peak_tx: usize,
        peak_rx: usize,
        enabled: bool,
        active: bool,
        direction: Option<bool>,
        raw: u32,
        abort_source: u32,
        enable_at: Option<u64>,
        disable_at: Option<u64>,
        command_at: u64,
        latency: u64,
        enable_delay: u64,
        disable_delay: u64,
        freeze_tx: bool,
        freeze_enable: bool,
        freeze_disable: bool,
        freeze_abort: bool,
        external_busy: bool,
        drop_stop: bool,
        fixed_timing: bool,
        fault_after: Option<(usize, u32)>,
        stop_after: Option<usize>,
        aborts: usize,
        accesses: Vec<(bool, usize, u32)>,
        delay_after_access: Option<usize>,
        delay_us: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Event {
        Start { read: bool, repeated: bool },
        Write(u8),
        Read(u8),
        Stop,
    }

    impl Model {
        fn new(time: Rc<Cell<u64>>, tx_depth: usize, rx_depth: usize) -> Self {
            let mut words = [0; 64];
            words[COMP_TYPE / 4] = COMPONENT_TYPE;
            words[COMP_VERSION / 4] = SDA_HOLD_VERSION;
            words[COMP_PARAM_1 / 4] = ((tx_depth - 1) << 16) as u32
                | ((rx_depth - 1) << 8) as u32
                | PARAM_ENCODED
                | (2 << 2)
                | PARAM_WIDTH_32;
            Self {
                words,
                time,
                tx: VecDeque::new(),
                rx: VecDeque::new(),
                replies: VecDeque::new(),
                commands: Vec::new(),
                events: Vec::new(),
                writes: Vec::new(),
                tx_depth,
                rx_depth,
                peak_tx: 0,
                peak_rx: 0,
                enabled: false,
                active: false,
                direction: None,
                raw: 0,
                abort_source: 0,
                enable_at: None,
                disable_at: None,
                command_at: 0,
                latency: 3,
                enable_delay: 2,
                disable_delay: 2,
                freeze_tx: false,
                freeze_enable: false,
                freeze_disable: false,
                freeze_abort: false,
                external_busy: false,
                drop_stop: false,
                fixed_timing: false,
                fault_after: None,
                stop_after: None,
                aborts: 0,
                accesses: Vec::new(),
                delay_after_access: None,
                delay_us: 0,
            }
        }

        fn step(&mut self) {
            let now = self.time.get();
            if self.enable_at.is_some_and(|at| now >= at) {
                self.enabled = true;
                self.enable_at = None;
            }
            if self.disable_at.is_some_and(|at| now >= at) {
                self.enabled = false;
                self.disable_at = None;
                self.active = false;
                self.direction = None;
                self.tx.clear();
                self.rx.clear();
            }
            if !self.enabled
                || self.freeze_tx
                || self.tx.is_empty()
                || now < self.command_at
                || self.raw & INTR_TX_ABRT != 0
            {
                return;
            }
            self.command_at = now.saturating_add(self.latency);
            if let Some((after, source)) = self.fault_after
                && self.commands.len() == after
            {
                self.raw |= INTR_TX_ABRT;
                self.abort_source = source;
                self.tx.clear();
                self.rx.clear();
                self.active = false;
                return;
            }
            let command = self.tx.pop_front().unwrap();
            self.commands.push(command);
            let read = command & CMD_READ != 0;
            if self.direction.is_none() || command & CMD_RESTART != 0 {
                self.events.push(Event::Start {
                    read,
                    repeated: self.direction.is_some(),
                });
                self.direction = Some(read);
            } else {
                assert_eq!(
                    self.direction,
                    Some(read),
                    "direction changed without RESTART"
                );
            }
            self.active = true;
            if read {
                let byte = self.replies.pop_front().unwrap_or(0xff);
                if self.rx.len() == self.rx_depth {
                    self.raw |= INTR_RX_OVER;
                } else {
                    self.rx.push_back(byte);
                    self.peak_rx = self.peak_rx.max(self.rx.len());
                }
                self.events.push(Event::Read(byte));
            } else {
                self.events.push(Event::Write(command as u8));
            }
            if command & CMD_STOP != 0 || self.stop_after == Some(self.commands.len()) {
                self.active = false;
                self.direction = None;
                if !self.drop_stop {
                    self.raw |= INTR_STOP_DET;
                }
                self.events.push(Event::Stop);
            }
        }

        // Advance time only after the actual register result/effect. This
        // models a completed slow access, independently of polling relax().
        fn complete_access(&mut self, write: bool, offset: usize, value: u32) {
            self.accesses.push((write, offset, value));
            if self.delay_after_access == Some(self.accesses.len()) {
                self.time.set(self.time.get().wrapping_add(self.delay_us));
                self.delay_after_access = None;
            }
        }

        fn read(&mut self, offset: usize) -> u32 {
            self.step();
            let value = match offset {
                ENABLE_STATUS => u32::from(self.enabled),
                STATUS => {
                    (u32::from(self.active || self.external_busy) * STATUS_ACTIVE)
                        | (u32::from(self.active) * STATUS_MASTER_ACTIVE)
                        | if self.tx.is_empty() {
                            STATUS_TX_EMPTY
                        } else {
                            0
                        }
                }
                RAW_INTR_STAT => self.raw,
                TX_ABRT_SOURCE => self.abort_source,
                TXFLR => self.tx.len() as u32,
                RXFLR => self.rx.len() as u32,
                DATA_CMD => match self.rx.pop_front() {
                    Some(byte) => u32::from(byte),
                    None => {
                        self.raw |= INTR_RX_UNDER;
                        0
                    }
                },
                CLR_INTR => {
                    self.raw = 0;
                    self.abort_source = 0;
                    0
                }
                CLR_TX_ABRT => {
                    self.raw &= !INTR_TX_ABRT;
                    self.abort_source = 0;
                    0
                }
                CLR_STOP_DET => {
                    self.raw &= !INTR_STOP_DET;
                    0
                }
                _ => self.words[offset / 4],
            };
            self.complete_access(false, offset, value);
            value
        }

        fn write(&mut self, offset: usize, value: u32) {
            self.step();
            self.writes.push((offset, value));
            match offset {
                ENABLE => {
                    self.words[offset / 4] = value;
                    if value & ENABLE_ABORT != 0 {
                        assert!(self.enabled, "ABORT before enable acknowledgement");
                        self.aborts += 1;
                        if !self.freeze_abort {
                            self.words[offset / 4] &= !ENABLE_ABORT;
                            self.tx.clear();
                            self.rx.clear();
                            self.active = false;
                            self.direction = None;
                            self.raw |= INTR_TX_ABRT;
                            self.abort_source = 1 << 16;
                        }
                    } else if value & ENABLE_ON != 0 {
                        self.disable_at = None;
                        if !self.freeze_enable {
                            self.enable_at = Some(self.time.get() + self.enable_delay);
                        }
                    } else {
                        self.enable_at = None;
                        if !self.freeze_disable {
                            self.disable_at = Some(self.time.get() + self.disable_delay);
                        }
                    }
                }
                DATA_CMD => {
                    assert!(self.enabled, "command before enable acknowledgement");
                    if self.tx.len() == self.tx_depth {
                        self.raw |= INTR_TX_OVER;
                    } else {
                        self.tx.push_back(value);
                        self.active = true;
                        self.peak_tx = self.peak_tx.max(self.tx.len());
                    }
                }
                CON | TAR | SS_SCL_HCNT | SS_SCL_LCNT | FS_SCL_HCNT | FS_SCL_LCNT | SDA_HOLD => {
                    assert!(!self.enabled, "configuration while controller enabled");
                    if !self.fixed_timing || !matches!(offset, FS_SCL_HCNT | FS_SCL_LCNT) {
                        self.words[offset / 4] = value;
                    }
                }
                _ => self.words[offset / 4] = value,
            }
            self.complete_access(true, offset, value);
        }
    }

    #[derive(Clone)]
    struct RegisterModel(Rc<RefCell<Model>>);

    impl Registers for RegisterModel {
        fn read32(&mut self, offset: usize) -> u32 {
            self.0.borrow_mut().read(offset)
        }

        fn write32(&mut self, offset: usize, value: u32) {
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

    fn config() -> Config {
        Config {
            timing: Timing {
                speed: Speed::Fast,
                scl_high: 120,
                scl_low: 160,
                sda_hold: Some(40),
            },
            timeout_us: 20_000,
            recovery_timeout_us: 100,
        }
    }

    type Controller = DesignWare<RegisterModel, ModelTimer>;

    fn model(tx: usize, rx: usize) -> (RegisterModel, ModelTimer) {
        let time = Rc::new(Cell::new(0));
        (
            RegisterModel(Rc::new(RefCell::new(Model::new(time.clone(), tx, rx)))),
            ModelTimer(time),
        )
    }

    fn controller(tx: usize, rx: usize) -> (Controller, Rc<RefCell<Model>>) {
        let (registers, timer) = model(tx, rx);
        let state = registers.0.clone();
        let controller = DesignWare::new(registers, timer, config()).unwrap();
        (controller, state)
    }

    #[test]
    fn completed_access_deadlines_never_report_success_or_publish_later_wire_commands() {
        // First observe a real successful combined transfer, including its
        // disable/cleanup accesses. Then delay each actual access in turn.
        // The existing peer/FIFO model still executes every original effect.
        let (mut baseline, state) = controller(2, 2);
        state.borrow_mut().accesses.clear();
        let mut bytes = [0; 3];
        baseline
            .transaction(
                Address::SevenBit(0x2c),
                &mut [
                    Operation::Write(&[0x80, 0x55, 0x33]),
                    Operation::Read(&mut bytes),
                ],
            )
            .unwrap();
        let accesses = state.borrow().accesses.clone();
        assert!(
            accesses
                .iter()
                .any(|&(write, offset, _)| !write && offset == DATA_CMD)
        );
        assert!(
            accesses
                .iter()
                .any(|&(write, offset, _)| !write && offset == CLR_STOP_DET)
        );
        for delayed in 1..=accesses.len() {
            let (mut bus, state) = controller(2, 2);
            {
                let mut h = state.borrow_mut();
                h.accesses.clear();
                h.delay_after_access = Some(delayed);
                h.delay_us = config().timeout_us;
            }
            let mut data = [0xa5; 3];
            let error = bus
                .transaction(
                    Address::SevenBit(0x2c),
                    &mut [
                        Operation::Write(&[0x80, 0x55, 0x33]),
                        Operation::Read(&mut data),
                    ],
                )
                .unwrap_err();
            assert!(
                matches!(error.kind, ErrorKind::Timeout(_)),
                "access {delayed}: {error:?}"
            );
            let h = state.borrow();
            assert_eq!(h.delay_after_access, None);
            assert_eq!(&h.accesses[..delayed], &accesses[..delayed]);
            assert!(
                h.accesses[delayed..]
                    .iter()
                    .all(|&(write, offset, value)| !write
                        || (offset != DATA_CMD && !(offset == ENABLE && value == ENABLE_ON))),
                "wire publication after slow access {delayed}"
            );
            if !accesses[delayed - 1].0 && accesses[delayed - 1].1 == DATA_CMD {
                let completed_before = accesses[..delayed - 1]
                    .iter()
                    .filter(|&&(write, offset, _)| !write && offset == DATA_CMD)
                    .count();
                assert!(
                    data[completed_before..].iter().all(|&byte| byte == 0xa5),
                    "late RX read must not be copied into the caller's buffer"
                );
            }
            if error.recovery == Recovery::Failed {
                let writes = h.writes.len();
                drop(h);
                assert_eq!(
                    bus.transaction(Address::SevenBit(0x2c), &mut [Operation::Write(&[9])])
                        .unwrap_err()
                        .kind,
                    ErrorKind::NeedsReset
                );
                assert_eq!(state.borrow().writes.len(), writes);
            }
        }
    }

    #[test]
    fn late_actual_abort_remains_the_original_failure_through_cleanup() {
        for source in [ABRT_ADDRESS_NACK, ABRT_DATA_NACK, ABRT_ARBITRATION_LOST] {
            let (mut bus, state) = controller(2, 2);
            {
                let mut h = state.borrow_mut();
                h.raw = INTR_TX_ABRT;
                h.abort_source = source;
                // Test the actual common fault reader, whose clear destroys
                // the hardware source. A late observation cannot turn it into
                // an unrelated timeout or silently retry a wire operation.
                h.accesses.clear();
                h.delay_after_access = Some(2);
                h.delay_us = config().timeout_us;
            }
            let error = bus.faults().unwrap_err();
            assert!(matches!(error, ErrorKind::Aborted { source: actual, .. } if actual == source));
            assert_eq!(state.borrow().abort_source, 0);
            assert!(bus.quiesce());
            assert!(state.borrow().commands.is_empty());
        }
    }

    #[test]
    fn combined_messages_preserve_data_restarts_and_only_the_final_stop() {
        for (tx, rx) in [(2, 2), (3, 2), (2, 16), (16, 3), (256, 256)] {
            let (mut controller, state) = controller(tx, rx);
            state.borrow_mut().replies.extend(0..80);
            let mut read_first = [0; 63];
            let mut read_last = [0; 17];
            controller
                .transaction(
                    Address::SevenBit(0x2c),
                    &mut [
                        Operation::Write(&[1, 2, 3, 4, 5, 6, 7]),
                        Operation::Read(&mut read_first),
                        Operation::Write(&[9, 10]),
                        Operation::Read(&mut read_last),
                    ],
                )
                .unwrap();
            assert_eq!(read_first, core::array::from_fn(|i| i as u8));
            assert_eq!(read_last, core::array::from_fn(|i| (i + 63) as u8));
            let state = state.borrow();
            assert!(state.peak_tx <= tx);
            assert!(state.peak_rx <= rx);
            assert_eq!(state.raw & INTR_FIFO_ERROR, 0);
            assert!(!state.enabled);
            assert_eq!(state.commands.len(), 89);
            let boundaries: Vec<_> = state
                .commands
                .iter()
                .enumerate()
                .filter(|(_, command)| *command & (CMD_RESTART | CMD_STOP) != 0)
                .map(|(index, command)| (index, command & (CMD_RESTART | CMD_STOP)))
                .collect();
            assert_eq!(
                boundaries,
                [
                    (7, CMD_RESTART),
                    (70, CMD_RESTART),
                    (72, CMD_RESTART),
                    (88, CMD_STOP)
                ]
            );
            assert_eq!(state.events.last(), Some(&Event::Stop));
            assert_eq!(
                state
                    .events
                    .iter()
                    .filter(|event| **event == Event::Stop)
                    .count(),
                1
            );
            assert_eq!(state.words[TAR / 4], 0x2c);
            assert_eq!(state.words[INTR_MASK / 4], 0);
            assert_eq!(state.words[SMBUS_INTR_MASK / 4], 0);
            assert_eq!(state.words[DMA_CR / 4], 0);
        }
    }

    #[test]
    fn successive_same_direction_messages_still_generate_restarts() {
        let (mut controller, state) = controller(2, 2);
        controller
            .transaction(
                Address::TenBit(0x2ab),
                &mut [Operation::Write(&[1]), Operation::Write(&[2])],
            )
            .unwrap();
        let state = state.borrow();
        assert_eq!(state.words[TAR / 4], 0x2ab | TAR_TEN_BIT);
        assert_eq!(state.words[CON / 4] & CON_TEN_BIT, CON_TEN_BIT);
        assert_eq!(
            state.events,
            [
                Event::Start {
                    read: false,
                    repeated: false
                },
                Event::Write(1),
                Event::Start {
                    read: false,
                    repeated: true
                },
                Event::Write(2),
                Event::Stop,
            ]
        );
    }

    #[test]
    fn abort_reasons_survive_hardware_clear_and_do_not_poison_the_next_transaction() {
        for (source, kind) in [
            (1, AbortKind::AddressNack),
            (2, AbortKind::AddressNack),
            (4, AbortKind::AddressNack),
            (8, AbortKind::DataNack),
            (1 << 12, AbortKind::ArbitrationLost),
            (1 << 11, AbortKind::Other),
        ] {
            let (mut controller, state) = controller(2, 2);
            state.borrow_mut().fault_after = Some((1, source));
            let mut data = [0; 15];
            let error = controller
                .transaction(Address::SevenBit(0x50), &mut [Operation::Read(&mut data)])
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Aborted { kind, source });
            assert_eq!(error.recovery, Recovery::Disabled);
            {
                let mut state = state.borrow_mut();
                assert_eq!(state.abort_source, 0);
                assert_eq!(state.raw, 0);
                assert!(!state.enabled);
                assert!(state.tx.is_empty() && state.rx.is_empty());
                state.fault_after = None;
            }
            controller
                .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[55])])
                .unwrap();
            assert_eq!(state.borrow().events.last(), Some(&Event::Stop));
        }
    }

    #[test]
    fn stalled_transfer_is_bounded_aborted_and_can_be_retried_explicitly() {
        let (mut controller, state) = controller(2, 2);
        state.borrow_mut().freeze_tx = true;
        let before = state.borrow().time.get();
        let error = controller
            .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[1; 10])])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Transfer));
        assert_eq!(error.recovery, Recovery::Disabled);
        {
            let mut state = state.borrow_mut();
            assert_eq!(state.aborts, 1);
            assert!(!state.enabled);
            assert!(state.time.get() - before <= 20_100);
            state.freeze_tx = false;
        }
        controller
            .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[2])])
            .unwrap();
    }

    #[test]
    fn an_unacknowledged_disable_poisons_the_controller() {
        let (mut controller, state) = controller(2, 2);
        state.borrow_mut().freeze_disable = true;
        let error = controller
            .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[1])])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Disable));
        assert_eq!(error.recovery, Recovery::Failed);
        let writes = state.borrow().writes.len();
        let error = controller
            .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[2])])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::NeedsReset);
        assert_eq!(state.borrow().writes.len(), writes);
    }

    #[test]
    fn enable_bus_acquisition_and_missing_stop_all_have_finite_failure_paths() {
        for phase in [Phase::Enable, Phase::BusIdle, Phase::Stop] {
            let (mut controller, state) = controller(2, 2);
            {
                let mut state = state.borrow_mut();
                match phase {
                    Phase::Enable => state.freeze_enable = true,
                    Phase::BusIdle => state.external_busy = true,
                    Phase::Stop => state.drop_stop = true,
                    _ => unreachable!(),
                }
            }
            let error = controller
                .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[1])])
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Timeout(phase));
            assert_eq!(error.recovery, Recovery::Disabled);
            assert!(state.borrow().time.get() <= 20_200);
        }
    }

    #[test]
    fn a_stop_before_all_commands_are_queued_is_an_error() {
        let (mut controller, state) = controller(2, 2);
        state.borrow_mut().stop_after = Some(1);
        let error = controller
            .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[1; 10])])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnexpectedStop);
        assert_eq!(error.recovery, Recovery::Disabled);
    }

    #[test]
    fn a_premature_stop_is_rejected_even_when_the_entire_write_fits_in_the_fifo() {
        let (mut controller, state) = controller(16, 16);
        state.borrow_mut().stop_after = Some(1);
        let error = controller
            .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[1, 2, 3])])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnexpectedStop);
        assert_eq!(error.recovery, Recovery::Disabled);
        let state = state.borrow();
        assert!(!state.enabled);
        assert!(state.tx.is_empty());
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| **event == Event::Stop)
                .count(),
            1
        );
    }

    #[test]
    fn invalid_addresses_and_empty_messages_do_not_touch_registers() {
        let (mut controller, state) = controller(2, 2);
        let writes = state.borrow().writes.len();
        for address in [
            Address::SevenBit(0),
            Address::SevenBit(0x80),
            Address::TenBit(0x400),
        ] {
            let error = controller
                .transaction(address, &mut [Operation::Write(&[1])])
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::InvalidAddress);
        }
        assert_eq!(
            controller
                .transaction(Address::SevenBit(0x50), &mut [])
                .unwrap_err()
                .kind,
            ErrorKind::EmptyTransaction
        );
        assert_eq!(
            controller
                .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[])])
                .unwrap_err()
                .kind,
            ErrorKind::EmptyMessage
        );
        assert_eq!(state.borrow().writes.len(), writes);
    }

    #[test]
    fn component_timing_and_fifo_requirements_fail_explicitly() {
        for scenario in 0..6 {
            let (registers, timer) = model(2, 2);
            let mut config = config();
            {
                let mut state = registers.0.borrow_mut();
                match scenario {
                    0 => state.words[COMP_TYPE / 4] = 0x0140_4457,
                    1 => state.words[COMP_PARAM_1 / 4] &= !PARAM_ENCODED,
                    2 => state.words[COMP_PARAM_1 / 4] &= !3,
                    3 => state.words[COMP_VERSION / 4] = SDA_HOLD_VERSION - 1,
                    4 => state.fixed_timing = true,
                    5 => config.timing.scl_high = 0,
                    _ => unreachable!(),
                }
            }
            let error = DesignWare::new(registers, timer, config).err().unwrap();
            assert!(matches!(
                (scenario, error.kind),
                (0, ErrorKind::ComponentType(_))
                    | (1 | 2, ErrorKind::ComponentParameters(_))
                    | (3, ErrorKind::UnsupportedVersion(_))
                    | (4, ErrorKind::TimingRejected)
                    | (5, ErrorKind::InvalidConfiguration)
            ));
        }
    }

    #[test]
    fn seeded_mixed_transactions_match_the_wire_peer_across_fifo_sizes_and_delays() {
        let mut seed = 0x51c2_1907u32;
        let mut random = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..256 {
            let tx = [2, 3, 8, 32][random() as usize % 4];
            let rx = [2, 3, 16, 256][random() as usize % 4];
            let (mut controller, state) = controller(tx, rx);
            state.borrow_mut().latency = u64::from(random() % 6);
            let messages = random() as usize % 8 + 1;
            let mut buffers: Vec<_> = (0..messages)
                .map(|_| {
                    let read = random() & 1 != 0;
                    let count = random() as usize % 79 + 1;
                    (read, (0..count).map(|_| random() as u8).collect::<Vec<_>>())
                })
                .collect();
            let mut expected_events = Vec::new();
            let mut next_reply = 0u8;
            for (message, (read, bytes)) in buffers.iter().enumerate() {
                expected_events.push(Event::Start {
                    read: *read,
                    repeated: message != 0,
                });
                for &byte in bytes {
                    if *read {
                        expected_events.push(Event::Read(next_reply));
                        state.borrow_mut().replies.push_back(next_reply);
                        next_reply = next_reply.wrapping_add(1);
                    } else {
                        expected_events.push(Event::Write(byte));
                    }
                }
            }
            expected_events.push(Event::Stop);
            let mut operations: Vec<_> = buffers
                .iter_mut()
                .map(|(read, bytes)| {
                    if *read {
                        Operation::Read(bytes)
                    } else {
                        Operation::Write(bytes)
                    }
                })
                .collect();
            controller
                .transaction(Address::SevenBit(0x2c), &mut operations)
                .unwrap();
            drop(operations);
            let mut next_reply = 0u8;
            for (read, bytes) in buffers {
                if read {
                    for byte in bytes {
                        assert_eq!(byte, next_reply);
                        next_reply = next_reply.wrapping_add(1);
                    }
                }
            }
            let state = state.borrow();
            assert_eq!(state.events, expected_events);
            assert!(state.peak_tx <= tx && state.peak_rx <= rx);
            assert!(state.raw & INTR_FIFO_ERROR == 0);
        }
    }

    #[test]
    fn a_wedged_abort_and_disable_remain_bounded_and_require_platform_reset() {
        let (mut controller, state) = controller(2, 2);
        {
            let mut state = state.borrow_mut();
            state.freeze_tx = true;
            state.freeze_abort = true;
            state.freeze_disable = true;
        }
        let error = controller
            .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[1; 10])])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout(Phase::Transfer));
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(state.borrow().aborts, 1);
        assert!(state.borrow().time.get() <= 20_100);
        assert_eq!(
            controller
                .transaction(Address::SevenBit(0x50), &mut [Operation::Write(&[2])])
                .unwrap_err()
                .kind,
            ErrorKind::NeedsReset
        );
    }
}
