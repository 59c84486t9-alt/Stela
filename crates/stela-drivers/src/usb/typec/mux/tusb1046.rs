// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Bootlin
// Copyright (c) 2026 Stela contributors
//! TI TUSB1046-DCI crosspoint, following pinned Linux tusb1046.c.
use super::{Error, Mode, Orientation, Pin, Registers, Route, require_orientation};
use crate::bus::i2c::{Address, Bus};

pub const DEVICE_TREE_COMPATIBLE: &str = "ti,tusb1046";
pub struct Tusb1046<B: Bus> {
    registers: Registers<B>,
    orientation: Orientation,
}
impl<B: Bus> Tusb1046<B> {
    pub fn probe(bus: B, address: Address) -> Result<Self, Error> {
        let mut registers = Registers::new(bus, address);
        registers.read(0x0a)?;
        Ok(Self {
            registers,
            orientation: Orientation::None,
        })
    }
    pub fn fault(&self) -> Option<Error> {
        self.registers.fault
    }
}
impl<B: Bus> Route for Tusb1046<B> {
    fn set_orientation(&mut self, orientation: Orientation) -> Result<(), Error> {
        let old = self.registers.read(0x0a)?;
        self.registers.write(
            0x0a,
            (old & !4)
                | if orientation == Orientation::Reverse {
                    4
                } else {
                    0
                },
        )?;
        self.orientation = orientation;
        Ok(())
    }
    fn set_mode(&mut self, mode: Mode) -> Result<(), Error> {
        let value = match mode {
            Mode::Safe => 0,
            Mode::Usb | Mode::Usb3 => 1,
            Mode::DisplayPort(data) => match data.pin {
                Pin::C | Pin::E => 2,
                Pin::D => 3,
                Pin::F => return Err(Error::UnsupportedMode(mode)),
            },
            _ => return Err(Error::UnsupportedMode(mode)),
        };
        require_orientation(self.orientation, mode)?;
        let old = self.registers.read(0x0a)?;
        self.registers.write(0x0a, (old & !3) | value)
    }
}
