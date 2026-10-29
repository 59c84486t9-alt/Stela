// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2017-2018 Hans de Goede <hdegoede@redhat.com>
// Copyright (c) 2026 Stela contributors
//! Pericom PI3USB30532 configuration, following pinned Linux pi3usb30532.c.
use super::{Error, Mode, Orientation, Pin, Registers, Route, require_orientation};
use crate::bus::i2c::{Address, Bus};

pub const I2C_DRIVER_ID: &str = "pi3usb30532";
pub struct Pi3usb30532<B: Bus> {
    registers: Registers<B>,
    configuration: u8,
    orientation: Orientation,
}
impl<B: Bus> Pi3usb30532<B> {
    /// The platform must select the real compatible, powered target and keep
    /// exclusive bus/device ownership; there is no chip-ID register to guess.
    pub fn probe(bus: B, address: Address) -> Result<Self, Error> {
        let mut registers = Registers::new(bus, address);
        let configuration = registers.read(0)?;
        Ok(Self {
            registers,
            configuration,
            orientation: Orientation::None,
        })
    }
    pub fn configuration(&self) -> u8 {
        self.configuration
    }
    pub fn fault(&self) -> Option<Error> {
        self.registers.fault
    }
    fn configure(&mut self, configuration: u8) -> Result<(), Error> {
        self.registers.healthy()?;
        if configuration != self.configuration {
            self.registers.write(0, configuration)?;
            self.configuration = configuration;
        }
        Ok(())
    }
}
impl<B: Bus> Route for Pi3usb30532<B> {
    fn set_orientation(&mut self, orientation: Orientation) -> Result<(), Error> {
        let configuration = match orientation {
            Orientation::None => 0,
            Orientation::Normal => self.configuration & !1,
            Orientation::Reverse => self.configuration | 1,
        };
        self.configure(configuration)?;
        self.orientation = orientation;
        Ok(())
    }
    fn set_mode(&mut self, mode: Mode) -> Result<(), Error> {
        let value = match mode {
            Mode::Safe => 0,
            Mode::Usb | Mode::Usb3 => 4,
            Mode::DisplayPort(data) => match data.pin {
                Pin::C | Pin::E => 2,
                Pin::D => 6,
                Pin::F => return Err(Error::UnsupportedMode(mode)),
            },
            _ => return Err(Error::UnsupportedMode(mode)),
        };
        require_orientation(self.orientation, mode)?;
        self.configure((self.configuration & 1) | value)
    }
}
