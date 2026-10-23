// SPDX-License-Identifier: GPL-2.0-only
//! Native ELAN proprietary I2C and SMBus touchpads.
//! The platform supplies exclusive powered I2C ownership and an actual IRQ pin;
//! CPU interrupt delivery stays masked while the physical pin is polled.
//! Firmware flashing, GPIO/rail sequencing and
//! guest contact/trackpoint routing remain separate requirements.
//! Pinned donor sources and retained copyrights are in input/THIRD_PARTY.md.
pub use super::hid_i2c::{Interrupt, InterruptError};
use crate::bus::i2c::{self, Address, Bus, Timer};
mod device;
mod report;
pub mod smbus;
pub use report::{Absolute, Contact, Frame, Packet, Trackpoint};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    Starting,
    Ready,
    Sleeping,
    PoweredDown,
    Stopped,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidAddress,
    NotReady,
    AlreadyActive,
    NeedsReset,
    Bus(i2c::Error),
    Smbus(crate::bus::smbus::Error),
    BlockLength {
        command: u8,
        minimum: usize,
        maximum: usize,
        actual: usize,
    },
    HelloPacket,
    Interrupt(InterruptError),
    ResetResponse([u8; 2]),
    FirmwareMode(u16),
    InvalidGeometry,
    ReportId(u8),
    UnexpectedReset,
    Coordinate {
        slot: u8,
        x: u16,
        y: u16,
    },
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
        write!(f, "ELAN {:?} ({:?})", self.kind, self.recovery)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub descriptor: [u8; 30],
    pub report_descriptor: [u8; 158],
    pub product_id: u16,
    pub pattern: u8,
    pub ic_type: u16,
    pub sample_version: u8,
    pub clickpad: bool,
    pub firmware_version: u8,
    pub firmware_checksum: u16,
    pub iap_version: u8,
    pub maximum: (u16, u16),
    pub traces: (u8, u8),
    pub raw_resolution: (u8, u8),
    pub resolution_per_mm: (u32, u32),
    pub pressure_adjustment: u8,
    pub quick_wakeup: bool,
}
impl Capabilities {
    /// Actual full report transfer size selected by the firmware pattern.
    pub fn report_length(&self) -> usize {
        if self.pattern <= 1 { 34 } else { 39 }
    }
}
pub struct I2cDevice<B, I, T> {
    bus: B,
    interrupt: I,
    timer: T,
    address: Address,
    state: State,
    capabilities: Option<Capabilities>,
}
impl<B: Bus, I: Interrupt, T: Timer> I2cDevice<B, I, T> {
    /// Construction performs no hardware access. The platform must establish
    /// actual ELAN attachment, power, exclusive bus ownership and IRQ routing.
    pub fn new(bus: B, interrupt: I, timer: T, address: Address) -> Result<Self, Error> {
        if !matches!(
            address,
            Address::SevenBit(0x08..=0x77) | Address::TenBit(0..=0x3ff)
        ) {
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
    /// Last completely queried capabilities; state must be Ready before input
    /// is usable. Failed reinitialization never publishes partial capabilities.
    pub fn capabilities(&self) -> Option<&Capabilities> {
        self.capabilities.as_ref()
    }
}
#[cfg(test)]
mod tests;
