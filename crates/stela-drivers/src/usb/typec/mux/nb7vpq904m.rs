// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2023 Dmitry Baryshkov <dmitry.baryshkov@linaro.org>
// Copyright (c) 2026 Stela contributors
//! OnSemi NB7VPQ904M register/channel programming from pinned Linux driver.
//! Vcc/enable resources and the board's lane map come from the platform.
use super::{
    Error, Mode, Orientation, Pin, Power, PowerOperation, Registers, Route, Supply,
    require_orientation,
};
use crate::bus::i2c::{Address, Bus};
use alloc::vec::Vec;

pub const I2C_DRIVER_ID: &str = "nb7vpq904m";
pub const DEVICE_TREE_COMPATIBLE: &str = "onnn,nb7vpq904m";
pub struct Nb7vpq904m<B: Bus, P: Power> {
    registers: Registers<B>,
    power: P,
    initialized: bool,
    orientation: Orientation,
    mode: Mode,
    swap: bool,
    version: Option<u8>,
    cleanup_errors: Vec<Error>,
}
impl<B: Bus, P: Power> Nb7vpq904m<B, P> {
    pub fn new(bus: B, address: Address, power: P) -> Self {
        Self {
            registers: Registers::new(bus, address),
            power,
            initialized: false,
            orientation: Orientation::None,
            mode: Mode::Safe,
            swap: false,
            version: None,
            cleanup_errors: Vec::new(),
        }
    }
    pub fn version(&self) -> Option<u8> {
        self.version
    }
    pub fn fault(&self) -> Option<Error> {
        self.registers.fault
    }
    pub fn cleanup_errors(&self) -> &[Error] {
        &self.cleanup_errors
    }
    fn power(&mut self, operation: PowerOperation) -> Result<(), Error> {
        self.power
            .set(operation)
            .map_err(|error| Error::Power { operation, error })
    }
    fn cleanup(&mut self) {
        for operation in [
            PowerOperation::Enable(false),
            PowerOperation::Supply(Supply::Vcc, false),
        ] {
            if let Err(error) = self.power(operation) {
                self.cleanup_errors.push(error);
            }
        }
        self.initialized = false;
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
    pub fn initialize(&mut self, data_lanes: [u8; 4]) -> Result<(), Error> {
        self.registers.healthy()?;
        if self.initialized {
            return Err(Error::NeedsPlatformReset);
        }
        self.swap = match data_lanes {
            [0, 1, 2, 3] => false,
            [3, 2, 1, 0] => true,
            other => return Err(Error::InvalidLaneMapping(other)),
        };
        let result = (|| {
            self.power(PowerOperation::Supply(Supply::Vcc, true))?;
            self.power(PowerOperation::Enable(true))?;
            self.version = Some(self.registers.read(0x17)?);
            self.initialized = true;
            Ok(())
        })();
        result.map_err(|error| self.failed(error))
    }
    fn channel(&mut self, channel: u8, dp: bool) -> Result<(), Error> {
        let ad = channel == 0 || channel == 3;
        let (eq, compression, gain, loss) = if dp {
            (if ad { 6 } else { 4 }, 3, if ad { 2 } else { 1 }, 3)
        } else {
            (4, 3, if ad { 3 } else { 1 }, if ad { 1 } else { 3 })
        };
        self.registers.update(1 + channel * 2, 0x0e, eq << 1)?;
        self.registers
            .update(2 + channel * 2, 6, compression << 1)?;
        self.registers.update(0x18 + channel * 2, 3, gain)?;
        self.registers.update(0x19 + channel * 2, 3, loss)
    }
    fn program(&mut self, orientation: Orientation, mode: Mode) -> Result<(), Error> {
        let reverse = orientation == Orientation::Reverse;
        match mode {
            Mode::Safe => {
                self.registers.write(0, 0xfb)?;
                for channel in 0..4 {
                    self.channel(channel, false)?;
                }
                self.registers.write(9, 2)
            }
            Mode::Usb | Mode::Usb3 => {
                let channels = if reverse ^ self.swap { [0, 1] } else { [2, 3] };
                let enables = (1 << (4 + channels[0])) | (1 << (4 + channels[1]));
                self.registers.write(0, 0x0b | enables)?;
                for channel in channels {
                    self.channel(channel, false)?;
                }
                self.registers.write(9, 2)
            }
            Mode::DisplayPort(data) => {
                self.registers.write(9, u8::from(reverse))?;
                match data.pin {
                    Pin::C | Pin::E => {
                        self.registers.write(0, 0xf5)?;
                        for channel in 0..4 {
                            self.channel(channel, true)?;
                        }
                    }
                    Pin::D | Pin::F => {
                        self.registers
                            .write(0, 0xf1 | if reverse ^ self.swap { 0 } else { 2 })?;
                        for channel in 0..4 {
                            self.channel(
                                channel,
                                if channel < 2 {
                                    reverse ^ self.swap
                                } else {
                                    !(reverse ^ self.swap)
                                },
                            )?;
                        }
                    }
                }
                Ok(())
            }
            _ => Err(Error::UnsupportedMode(mode)),
        }
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
impl<B: Bus, P: Power> Route for Nb7vpq904m<B, P> {
    fn set_orientation(&mut self, orientation: Orientation) -> Result<(), Error> {
        self.healthy()?;
        let mode = if orientation == Orientation::None {
            Mode::Safe
        } else {
            self.mode
        };
        if let Err(error) = self.program(orientation, mode) {
            return Err(self.failed(error));
        }
        self.orientation = orientation;
        self.mode = mode;
        Ok(())
    }
    fn set_mode(&mut self, mode: Mode) -> Result<(), Error> {
        self.healthy()?;
        if !matches!(
            mode,
            Mode::Safe | Mode::Usb | Mode::Usb3 | Mode::DisplayPort(_)
        ) {
            return Err(Error::UnsupportedMode(mode));
        }
        require_orientation(self.orientation, mode)?;
        if let Err(error) = self.program(self.orientation, mode) {
            return Err(self.failed(error));
        }
        self.mode = mode;
        Ok(())
    }
}
