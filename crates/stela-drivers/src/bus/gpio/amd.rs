// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014,2015 Ken Xue <Ken.Xue@amd.com>, Jeff Wu <Jeff.Wu@amd.com>
// Copyright (c) 2026 Stela contributors
//! AMD0030/AMDI0030/AMDI0031/AMDI0033 register protocols.
//!
//! The pinned Linux driver uses the same sparse KERNCZ pad table and register
//! layout for these four ACPI IDs; it supplies no per-ID lock or GPIO mux value.
//! Matching an ID does not establish ownership. The native adapter requires an
//! actual firmware inspection and retained native MMIO reservation; raw protocol
//! constructors remain internal to that adapter and independent peers.
//! No public unsafe assertion, numeric GSI or caller bitmap admits hardware.
//!
//! `Controller` implements serialized process/deferred register operations. It
//! is not a hard-IRQ handler and must not be put behind an IRQ-unsafe lock.
//! The optional native adapter serves ordinary installed ACPI GPIO OpRegions.
//! Native shared-IRQ registration, _AEI delivery, wake and suspend remain open.
//! Full checklist closure and physical operation remain unqualified.
mod engine;
mod registers;
pub use engine::{Controller, Interrupt, Pending, Pull, ServiceReport};
pub use registers::{NativeRegisters, RegisterIo};

/// Descriptive ACPI match, never a device or pin authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Amd0030,
    Amdi0030,
    Amdi0031,
    Amdi0033,
}
impl Profile {
    pub fn from_hid(hid: &str) -> Option<Self> {
        match hid {
            "AMD0030" => Some(Self::Amd0030),
            "AMDI0030" => Some(Self::Amdi0030),
            "AMDI0031" => Some(Self::Amdi0031),
            "AMDI0033" => Some(Self::Amdi0033),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Mapping,
    InvalidPad,
    UnownedPad,
    FirmwareWake,
    FirmwareInterrupt,
    InvalidMux,
    MissingMux,
    Readback,
    DebounceTimeout,
    InvalidDebounce,
    InvalidDriveStrength,
    Direction,
    InterruptActive,
    Faulted,
    Retired,
    Consumer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pad(u8);
impl Pad {
    /// Validate the pinned sparse pad inventory. Pad 63 is the master register,
    /// never a GPIO; offsets >=184 are not pads even in a larger ACPI resource.
    pub fn new(number: u8) -> Result<Self, Error> {
        if number < 184 && number != 63 {
            Ok(Self(number))
        } else {
            Err(Error::InvalidPad)
        }
    }
    pub fn number(self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests;
