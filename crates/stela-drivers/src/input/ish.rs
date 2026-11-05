// SPDX-License-Identifier: GPL-2.0-only
// Protocols derived from Linux intel-ish-hid, Copyright (c) 2003-2016 Intel.
//! Explicit resident-firmware Intel ISH IPC/HBM/HID attachment.
//!
//! The finite profile is 8086:9d35, ordinary nonfixed HID clients and mailbox
//! payload transport. Startup requires the requester's DMA domain, isolated or
//! the passthrough domain, and real MSI delivery. No host DMA address or firmware is supplied.
//! Firmware clock synchronization lacks an UTC service and is explicitly
//! unsupported. Final armed-MSI retirement remains unsupported until the common
//! root owner implements posted-MSI completion; all original owners are held.
pub mod cold;
mod descriptor;
mod input;
mod native;
pub use input::{ClientRefusal, ClientRefusalCause, InputRefusal, IshInput};
mod protocol;
mod registers;
#[cfg(test)]
mod tests;

use crate::bus::{dma::mapping::DmaError, irq::IrqError, mmio::owned, pci::msi::MsiError};
pub use descriptor::{ReportKind, ReportLayout};
pub use native::{Configuration, InputPoll, Inputs, Native, NativeClock, Time};
pub use protocol::{ClientProperties, Device, FirmwareIdentity, InputReport, TimestampSupport};
pub use registers::{MappedRegisters, Registers};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ConfigAccess(crate::bus::pci::ConfigError),
    Capability(crate::bus::pci::CapabilityError),
    Requirement(&'static str),
    Mapping(owned::Error),
    Config(u16),
    Msi(MsiError),
    Irq(IrqError),
    Dma(DmaError),
    Access(u32),
    Removed,
    Readback(u32),
    Timeout(&'static str),
    Protocol(&'static str),
    Status(u8),
    FirmwareReset,
    Terminal,
    InputPollInterrupted,
    StopInterrupted,
    /// Payload drainage is independent of the missing posted-MSI completion.
    PostedMsiRetirementUnavailable,
}
pub type Result<T> = core::result::Result<T, Error>;

/// Input reports one poll reads at most, as USB HID bounds its pass.
const POLL_REPORTS: usize = 16;
