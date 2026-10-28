// SPDX-License-Identifier: GPL-2.0-only
// Protocols derived from Linux intel-ish-hid, Copyright (c) 2003-2016 Intel.
//! Explicit resident-firmware Intel ISH IPC/HBM/HID attachment.
//!
//! The finite profile is 8086:9d35, ordinary nonfixed HID clients and mailbox
//! payload transport. Startup requires the requester's DMA domain, isolated or
//! the passthrough domain, and real MSI delivery. No host DMA address or firmware is supplied.
//! Firmware clock synchronization lacks a genuine UTC service and is explicitly
//! unsupported. Final armed-MSI retirement remains unsupported until the common
//! root owner implements posted-MSI completion; all original owners are retained.
mod descriptor;
mod native;
mod protocol;
mod registers;
#[cfg(test)]
mod tests;

use super::Input;
use crate::bus::{dma::mapping::DmaError, irq::IrqError, mmio::owned, pci::msi::MsiError};
use crate::usb::hid::Translator;
use alloc::{string::String, vec::Vec};
pub use descriptor::{ReportKind, ReportLayout};
pub use native::{Configuration, Inputs, Native, NativeClock, Time};
pub use protocol::{ClientProperties, Device, FirmwareIdentity, InputReport, TimestampSupport};
pub use registers::{MappedRegisters, Registers};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
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
    /// Payload drainage is independent of the missing posted-MSI completion.
    PostedMsiRetirementUnavailable,
}
pub type Result<T> = core::result::Result<T, Error>;

/// Input reports one poll reads at most, as USB HID bounds its pass.
const POLL_REPORTS: usize = 16;

/// An ISH whose HID clients include a keyboard or pointer: each client's
/// reports pass through its own HID report translator.
pub struct IshInput {
    native: Native,
    clients: Vec<(u8, Translator)>,
    pub name: String,
}

impl IshInput {
    /// Read `native`'s started HID clients as input, or hand `native` back
    /// when none of them is a keyboard or pointer.
    #[allow(
        clippy::result_large_err,
        reason = "an ISH with no input client goes back to its owner"
    )]
    pub fn new(native: Native, name: String) -> core::result::Result<Self, Native> {
        let clients: Vec<_> = native
            .devices()
            .iter()
            .filter_map(|device| {
                Translator::describe(&device.report_descriptor)
                    .ok()
                    .map(|translator| (device.id, translator))
            })
            .collect();
        if !clients
            .iter()
            .any(|(_, translator)| translator.is_keyboard_or_pointer())
        {
            return Err(native);
        }
        Ok(Self {
            native,
            clients,
            name,
        })
    }

    /// Append the input changes of the reports the clients have ready.
    pub fn poll(&mut self, inputs: &mut Vec<Input>) -> Result<()> {
        let mut events = Vec::new();
        for _ in 0..POLL_REPORTS {
            let Some(report) = self.native.next_input()? else {
                break;
            };
            if let Some((_, translator)) = self
                .clients
                .iter_mut()
                .find(|(id, _)| *id == report.device_id)
            {
                translator.translate(&report.bytes, &mut events, inputs);
            }
        }
        Ok(())
    }

    /// Send `leds` to each keyboard client's LED output report, as Linux
    /// `hidinput_led_worker` sends it through ishtp-hid's SET_REPORT request.
    pub fn set_leds(&mut self, leds: u16) -> Result<()> {
        for (id, translator) in &self.clients {
            if let Some((_, report)) = translator.led_report(leds) {
                self.native.set_feature(*id, &report)?;
            }
        }
        Ok(())
    }

    /// The last report of the first client that sent one, as it arrived,
    /// for diagnostics.
    pub fn last_report(&self) -> &[u8] {
        self.clients
            .iter()
            .map(|(_, translator)| translator.last_report())
            .find(|report| !report.is_empty())
            .unwrap_or(&[])
    }

    /// Whether the ISH failed and is no longer read.
    pub fn stopped(&self) -> bool {
        self.native.failure().is_some()
    }
}
