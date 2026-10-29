// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2017-2018 Hans de Goede <hdegoede@redhat.com>
// Copyright (C) 2024 Bootlin
// Copyright (C) 2024 Linaro Ltd.
// Copyright (C) 2023 Dmitry Baryshkov <dmitry.baryshkov@linaro.org>
// Copyright (c) 2026 Stela contributors
//! Physical Type-C switches/retimers. The platform binds actual board devices,
//! powered I²C targets, supplies, clocks, GPIOs and upstream route topology.
//! An observation or mode request never invents those resources or a GPU link.

use crate::bus::i2c::{self, Address, Bus, Operation};

pub mod nb7vpq904m;
pub mod pi3usb30532;
pub mod pmc;
pub mod ps8830;
pub mod tusb1046;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Orientation {
    None,
    Normal,
    Reverse,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pin {
    C,
    D,
    E,
    F,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayPort {
    pub pin: Pin,
    pub status: u32,
    pub configuration: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Safe,
    Usb,
    Usb2,
    Usb3,
    DisplayPort(DisplayPort),
    Thunderbolt {
        cable_mode: u32,
        enter_vdo: u32,
        device_mode: u32,
    },
    Usb4 {
        enter_usb: u32,
        active_link_training: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TimerBudget {
        microseconds: u64,
    },
    I2c {
        register: u8,
        write: bool,
        error: i2c::Error,
    },
    Power {
        operation: PowerOperation,
        error: ResourceError,
    },
    UnsupportedMode(Mode),
    NoOrientation,
    InvalidLaneMapping([u8; 4]),
    NeedsInitialization,
    NeedsPlatformReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Supply {
    Vdd33,
    Vdd33Cap,
    Vdd,
    VddAr,
    VddAt,
    VddIo,
    Vcc,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerOperation {
    Supply(Supply, bool),
    Reset(bool),
    Enable(bool),
    Clock(bool),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    Unavailable,
    Status(u64),
    I2c(i2c::Error),
}
/// Actual board-selected resource operations. Absence/failure must be explicit;
/// no dummy/no-op power provider is included. Providers retain resource leases.
/// Operations establish this device's owned enable/reset vote, not an unchecked
/// global rail refcount. Setting false is idempotent, including after a failed
/// enable whose physical effects are uncertain.
pub trait Power {
    fn set(&mut self, operation: PowerOperation) -> Result<(), ResourceError>;
}

/// One actual route node. A platform-resolved chain may call orientation from
/// upstream to downstream, then mode from retimer to upstream mux, matching the
/// Linux callbacks. There is no connector/topology inference in this trait.
pub trait Route {
    fn set_orientation(&mut self, orientation: Orientation) -> Result<(), Error>;
    fn set_mode(&mut self, mode: Mode) -> Result<(), Error>;
}

struct Registers<B: Bus> {
    bus: B,
    address: Address,
    fault: Option<Error>,
}
impl<B: Bus> Registers<B> {
    fn new(bus: B, address: Address) -> Self {
        Self {
            bus,
            address,
            fault: None,
        }
    }
    fn healthy(&self) -> Result<(), Error> {
        self.fault.map_or(Ok(()), Err)
    }
    fn poison(&mut self, error: Error) -> Error {
        self.fault = Some(error);
        error
    }
    fn read(&mut self, register: u8) -> Result<u8, Error> {
        self.healthy()?;
        self.read_raw(register).map_err(|error| self.poison(error))
    }
    fn read_raw(&mut self, register: u8) -> Result<u8, Error> {
        let mut value = [0];
        self.bus
            .transaction(
                self.address,
                &mut [Operation::Write(&[register]), Operation::Read(&mut value)],
            )
            .map_err(|error| Error::I2c {
                register,
                write: false,
                error,
            })?;
        Ok(value[0])
    }
    fn write(&mut self, register: u8, value: u8) -> Result<(), Error> {
        self.healthy()?;
        self.bus
            .transaction(self.address, &mut [Operation::Write(&[register, value])])
            .map_err(|error| {
                self.poison(Error::I2c {
                    register,
                    write: true,
                    error,
                })
            })
    }
    fn update(&mut self, register: u8, mask: u8, value: u8) -> Result<(), Error> {
        let old = self.read(register)?;
        let new = (old & !mask) | (value & mask);
        if new != old {
            self.write(register, new)?;
        }
        Ok(())
    }
}

fn require_orientation(orientation: Orientation, mode: Mode) -> Result<(), Error> {
    if orientation == Orientation::None && !matches!(mode, Mode::Safe | Mode::Usb2) {
        return Err(Error::NoOrientation);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
