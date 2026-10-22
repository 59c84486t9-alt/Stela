// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Linaro Ltd.
// Copyright (c) 2026 Stela contributors
//! Parade PS8830 power/reset and register protocol from pinned ps883x.c.
//! Actual six named rails, XO clock and reset GPIO are required; native graph
//! binding and upstream orientation/mux routing remain the platform's job.
use super::{
    Error, Mode, Orientation, Pin, Power, PowerOperation, Registers, Route, Supply,
    require_orientation,
};
use crate::bus::i2c::{Address, Bus};
use crate::usb::typec::ucsi::Timer;
use alloc::vec::Vec;
const SUPPLIES: [Supply; 6] = [
    Supply::Vdd33,
    Supply::Vdd33Cap,
    Supply::Vdd,
    Supply::VddAr,
    Supply::VddAt,
    Supply::VddIo,
];
pub const DEVICE_TREE_COMPATIBLE: &str = "parade,ps8830";

pub struct Ps8830<B: Bus, P: Power, C: Timer> {
    registers: Registers<B>,
    power: P,
    timer: C,
    initialized: bool,
    in_reset: bool,
    orientation: Orientation,
    applied: Option<Mode>,
    initial_probe_error: Option<Error>,
    cleanup_errors: Vec<Error>,
}
impl<B: Bus, P: Power, C: Timer> Ps8830<B, P, C> {
    pub fn new(bus: B, address: Address, power: P, timer: C) -> Self {
        Self {
            registers: Registers::new(bus, address),
            power,
            timer,
            initialized: false,
            in_reset: false,
            orientation: Orientation::None,
            applied: None,
            initial_probe_error: None,
            cleanup_errors: Vec::new(),
        }
    }
    pub fn fault(&self) -> Option<Error> {
        self.registers.fault
    }
    pub fn applied(&self) -> Option<Mode> {
        self.applied
    }
    pub fn in_reset(&self) -> Option<bool> {
        (self.initialized && self.registers.fault.is_none()).then_some(self.in_reset)
    }
    pub fn initial_probe_error(&self) -> Option<Error> {
        self.initial_probe_error
    }
    pub fn cleanup_errors(&self) -> &[Error] {
        &self.cleanup_errors
    }
    fn power(&mut self, operation: PowerOperation) -> Result<(), Error> {
        self.power
            .set(operation)
            .map_err(|error| Error::Power { operation, error })
    }
    fn enable_supplies(&mut self) -> Result<(), Error> {
        for (index, supply) in SUPPLIES.iter().enumerate() {
            if index == 2 {
                self.timer.delay_us(4_000);
            }
            self.power(PowerOperation::Supply(*supply, true))?;
        }
        Ok(())
    }
    fn disable_supplies(&mut self) -> Result<(), Error> {
        let mut first = None;
        for supply in SUPPLIES.iter().rev() {
            match self.power(PowerOperation::Supply(*supply, false)) {
                Ok(()) => {}
                Err(error) => {
                    self.cleanup_errors.push(error);
                    first.get_or_insert(error);
                }
            }
        }
        first.map_or(Ok(()), Err)
    }
    fn reset(&mut self) -> Result<(), Error> {
        if self.in_reset {
            return Ok(());
        }
        self.power(PowerOperation::Reset(true))?;
        self.disable_supplies()?;
        self.in_reset = true;
        Ok(())
    }
    fn cleanup(&mut self) {
        if let Err(error) = self.power(PowerOperation::Reset(true)) {
            self.cleanup_errors.push(error);
        }
        let _ = self.disable_supplies();
        if let Err(error) = self.power(PowerOperation::Clock(false)) {
            self.cleanup_errors.push(error);
        }
        self.initialized = false;
        self.applied = None;
    }
    fn failed(&mut self, error: Error) -> Error {
        self.registers.poison(error);
        self.cleanup();
        error
    }
    fn healthy(&self) -> Result<(), Error> {
        self.registers.healthy()?;
        if !self.initialized {
            return Err(Error::NeedsInitialization);
        }
        Ok(())
    }
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.registers.healthy()?;
        if self.initialized {
            return Err(Error::NeedsPlatformReset);
        }
        let result = (|| {
            self.enable_supplies()?;
            self.power(PowerOperation::Clock(true))?;
            let configured = match self.registers.read_raw(0) {
                Ok(value) => value & 1 != 0,
                Err(
                    error @ Error::I2c {
                        error:
                            crate::bus::i2c::Error {
                                kind:
                                    crate::bus::i2c::ErrorKind::Aborted {
                                        kind: crate::bus::i2c::AbortKind::AddressNack,
                                        ..
                                    },
                                ..
                            },
                        ..
                    },
                ) => {
                    // A reset-held chip can NACK the initial connection test.
                    // Preserve it, then perform the real source reset/delay and
                    // require the later post-reset access to succeed.
                    self.initial_probe_error = Some(error);
                    false
                }
                Err(error) => return Err(error),
            };
            if configured {
                self.power(PowerOperation::Reset(false))?;
            } else {
                self.power(PowerOperation::Reset(true))?;
                self.timer.delay_us(4_000);
                self.power(PowerOperation::Reset(false))?;
                self.timer.delay_us(60_000);
                self.registers.read(0)?;
            }
            self.reset()?;
            self.initialized = true;
            Ok(())
        })();
        result.map_err(|error| self.failed(error))
    }
    fn configure(&mut self, cfg: [u8; 3], reset: bool) -> Result<(), Error> {
        if reset {
            return self.reset();
        }
        if self.in_reset {
            self.enable_supplies()?;
            self.power(PowerOperation::Reset(false))?;
            self.timer.delay_us(60_000);
            self.in_reset = false;
        }
        for (register, value) in cfg.iter().enumerate() {
            self.registers.write(register as u8, *value)?;
        }
        Ok(())
    }
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.healthy()?;
        self.cleanup();
        if let Some(error) = self.cleanup_errors.first().copied() {
            return Err(self.registers.poison(error));
        }
        Ok(())
    }
}
impl<B: Bus, P: Power, C: Timer> Route for Ps8830<B, P, C> {
    fn set_orientation(&mut self, orientation: Orientation) -> Result<(), Error> {
        self.healthy()?;
        if !self.in_reset
            && let Err(error) = self.registers.update(
                0,
                2,
                if orientation == Orientation::Reverse {
                    2
                } else {
                    0
                },
            )
        {
            return Err(self.failed(error));
        }
        self.orientation = orientation;
        Ok(())
    }
    fn set_mode(&mut self, mode: Mode) -> Result<(), Error> {
        self.healthy()?;
        require_orientation(self.orientation, mode)?;
        let mut cfg = [
            1 | if self.orientation == Orientation::Reverse {
                2
            } else {
                0
            },
            0,
            0,
        ];
        let mut reset = false;
        match mode {
            Mode::Safe => reset = self.orientation == Orientation::None,
            Mode::Usb2 => reset = true,
            Mode::Usb | Mode::Usb3 => cfg[0] |= 32,
            Mode::DisplayPort(data) => {
                if data.pin == Pin::F {
                    return Err(Error::UnsupportedMode(mode));
                }
                cfg[1] = 0x81;
                if data.pin == Pin::D {
                    cfg[0] |= 32;
                }
                if matches!(data.pin, Pin::C | Pin::D) {
                    cfg[1] |= 6;
                }
            }
            Mode::Thunderbolt {
                cable_mode,
                enter_vdo,
                ..
            } => {
                cfg[2] = 1;
                if cable_mode & (1 << 25) != 0 {
                    cfg[0] |= 4;
                }
                if enter_vdo & (1 << 23) != 0 {
                    cfg[2] |= 16;
                }
            }
            Mode::Usb4 { enter_usb, .. } => {
                cfg[2] = 128;
                if (enter_usb >> 19) & 3 != 0 {
                    cfg[0] |= 4;
                }
            }
        }
        if let Err(error) = self.configure(cfg, reset) {
            return Err(self.failed(error));
        }
        self.applied = Some(mode);
        Ok(())
    }
}
