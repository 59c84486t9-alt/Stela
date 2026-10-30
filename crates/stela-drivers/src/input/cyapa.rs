// SPDX-License-Identifier: GPL-2.0-only
//! Native Cypress APA Gen3 I2C/SMBus and Gen5/6 PIP I2C touchpad engines.
//! The platform provides powered exclusive peripheral bus ownership and a physical IRQ pin.
//! CPU IRQ delivery stays masked while the pin is polled. Firmware flashing,
//! platform rails and guest routing remain separate requirements.
pub use super::hid_i2c::{Interrupt, InterruptError};
use crate::bus::i2c::{self, Address, Bus, Operation, Timer};
mod device;
pub mod pip;
mod register;
mod report;
pub mod smbus;

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
    Clock(crate::ClockError),
    InvalidAddress,
    NotReady,
    AlreadyActive,
    NeedsReset,
    Bus(i2c::Error),
    Smbus(crate::bus::smbus::Error),
    UnsupportedSmbusAddress(u8),
    RegisterTransfer {
        register: u8,
        length: usize,
        write: bool,
    },
    BlockLength {
        command: u8,
        expected: usize,
        actual: usize,
    },
    Interrupt(InterruptError),
    HardwareState {
        state: HardwareState,
        raw: [u8; 3],
    },
    InvalidFirmware([u8; 3]),
    Timeout(HardwareState),
    PowerReadback {
        expected: u8,
        actual: u8,
    },
    UnsupportedGeneration(u8),
    UnsupportedProduct,
    InvalidGeometry,
    InvalidReportStatus([u8; 2]),
    ContactCount(u8),
    ContactId(u8),
    DuplicateId(u8),
    Coordinate {
        id: u8,
        x: u16,
        y: u16,
    },
    IdentityChanged,
}
pub use super::TouchpadRecovery as Recovery;
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
    /// Source capability bits 3..5, corresponding to report bits 0..2.
    pub button_capabilities: u8,
    pub maximum: (u16, u16),
    pub physical_size: (u16, u16),
}
/// Complete, owned Gen3 register operations. Implementations must keep the
/// original transport error, perform the bus framing and never replay a
/// mutable transfer. An alternate read probe requires `allow_fallback` to remain
/// true after the first error. The built-in providers share the same engine.
pub trait RegisterAccess {
    fn read_register(
        &mut self,
        address: Address,
        register: u8,
        bytes: &mut [u8],
        allow_fallback: impl Fn() -> bool,
    ) -> Result<(), ErrorKind>;
    fn write_register(
        &mut self,
        address: Address,
        register: u8,
        bytes: &[u8],
    ) -> Result<(), ErrorKind>;
}
pub struct Device<B, I, T> {
    bus: B,
    interrupt: I,
    timer: T,
    address: Address,
    state: State,
    capabilities: Option<Capabilities>,
    last_status: Option<[u8; 3]>,
}
impl<B: Bus, I: Interrupt, T: Timer> Device<B, I, T> {
    pub fn new(bus: B, interrupt: I, timer: T, address: Address) -> Result<Self, Error> {
        timer.check_duration(4_000_000).map_err(ErrorKind::Clock)?;
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
            last_status: None,
        })
    }
}
impl<B: RegisterAccess, I: Interrupt, T: Timer> Device<B, I, T> {
    /// Most recent complete dedicated status read, including one that finished late.
    pub fn last_status(&self) -> Option<[u8; 3]> {
        self.last_status
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// Last completely verified query; reports are available only in Ready.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }
}

#[cfg(test)]
mod tests;
