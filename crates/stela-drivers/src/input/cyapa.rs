// SPDX-License-Identifier: GPL-2.0-only
//! Native Cypress APA Gen3 I2C firmware launch and operational touchpad engine.
//! The platform provides powered exclusive I2C ownership and a physical IRQ pin.
//! CPU IRQ delivery stays masked while the pin is polled. Firmware flashing,
//! SMBus, Gen5/6, platform rails and guest routing remain separate requirements.
pub use super::hid_i2c::{Interrupt, InterruptError};
use crate::bus::i2c::{self, Address, Bus, Operation, Timer};
mod device;
mod report;
#[cfg(test)]
mod tests;
pub use report::{Contact, Frame};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    Starting,
    Ready,
    Sleeping,
    ButtonsOnly,
    PoweredDown,
    Stopped,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareState {
    Operational,
    BootloaderIdle,
    BootloaderActive,
    BootloaderBusy,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidAddress,
    NotReady,
    AlreadyActive,
    NeedsReset,
    Bus(i2c::Error),
    Interrupt(InterruptError),
    HardwareState { state: HardwareState, raw: [u8; 3] },
    InvalidFirmware([u8; 3]),
    Timeout(HardwareState),
    PowerReadback { expected: u8, actual: u8 },
    UnsupportedGeneration(u8),
    UnsupportedProduct,
    InvalidGeometry,
    InvalidReportStatus([u8; 2]),
    ContactCount(u8),
    ContactId(u8),
    DuplicateId(u8),
    Coordinate { id: u8, x: u16, y: u16 },
    IdentityChanged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    NotAttempted,
    IrqMasked,
    MaskFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub recovery: Recovery,
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            recovery: Recovery::NotAttempted,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cypress APA {:?} ({:?})", self.kind, self.recovery)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub query: [u8; 27],
    pub product_id: [u8; 15],
    pub firmware_version: (u8, u8),
    /// Actual source capability bits 3..5, corresponding to report bits 0..2.
    pub button_capabilities: u8,
    pub maximum: (u16, u16),
    pub physical_size: (u16, u16),
}
pub struct Device<B, I, T> {
    bus: B,
    interrupt: I,
    timer: T,
    address: Address,
    state: State,
    capabilities: Option<Capabilities>,
}
impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    pub fn new(bus: B, interrupt: I, timer: T, address: Address) -> Result<Self, Error> {
        if !matches!(address, Address::SevenBit(0x08..=0x77)) {
            return Err(ErrorKind::InvalidAddress.into());
        }
        Ok(Self {
            bus,
            interrupt,
            timer,
            address,
            state: State::Fresh,
            capabilities: None,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// Last completely verified query; reports are available only in Ready.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }
}
