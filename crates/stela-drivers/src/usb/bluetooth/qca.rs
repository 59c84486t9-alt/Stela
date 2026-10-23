// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Qualcomm Rome/WCN USB DFU controller initialization, adapted from btusb.c.
//! Uses real USB control OTP/status and fixed-EP2 firmware transfers before HCI
//! setup. Exact source ROM layouts and actual board/GF selectors bind resources.
//! A completed upload is not vendor authentication or radio/guest readiness.
mod identity;
mod initialize;
mod packet;
use super::{FirmwareReceipt, Hci, Io};
use alloc::{boxed::Box, vec::Vec};
pub use identity::{
    Kind, PROFILES, Profile, RampatchVersion, SOURCE_USB_IDS, UsbIdentity, Version,
};
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Rampatch,
    Nvm,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferKind {
    Header,
    Body,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub component: Component,
    pub kind: TransferKind,
    pub offset: usize,
    pub bytes: usize,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub usb: Option<UsbIdentity>,
    pub before: Option<Version>,
    pub status: Option<u8>,
    pub after_patch: Option<Version>,
    pub rampatch: Option<FirmwareReceipt>,
    pub nvm: Option<FirmwareReceipt>,
    pub rampatch_version: Option<RampatchVersion>,
    pub completed: Vec<Transfer>,
    pub pending: Option<Transfer>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirmwareEvidence {
    /// The controller said this component was already present. Its image and
    /// provenance remain unknown; no fabricated provider receipt is generated.
    AlreadyPresent,
    Uploaded(Box<FirmwareReceipt>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPolicy {
    pub simultaneous_discovery: bool,
    pub wideband_speech: bool,
    pub broken_enhanced_setup_sync_conn: bool,
    pub microsoft_opcode: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub usb: UsbIdentity,
    pub kind: Kind,
    pub before: Version,
    pub status: u8,
    pub after_patch: Version,
    pub rampatch: FirmwareEvidence,
    pub nvm: FirmwareEvidence,
    pub rampatch_version: Option<RampatchVersion>,
    pub completed: Vec<Transfer>,
    pub policy: HostPolicy,
}
#[derive(Debug)]
pub enum Error {
    Unsupported(&'static str),
    UnsupportedRom(u32),
    Protocol {
        requirement: &'static str,
        observed: Vec<u8>,
    },
    Resource(crate::firmware::Error),
    Usb(crate::block::BlockError),
    Timeout,
    Transport(super::Error),
    Attempt {
        cause: Box<Error>,
        observation: Box<Attempt>,
    },
    Cleanup {
        cause: Box<Error>,
        cleanup: super::Error,
    },
}
impl Error {
    fn protocol(requirement: &'static str, observed: &[u8]) -> Self {
        Self::Protocol {
            requirement,
            observed: observed.to_vec(),
        }
    }
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Transport(value)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Qualcomm USB Bluetooth initialization {self:?}")
    }
}
impl core::error::Error for Error {}
pub(super) fn is_candidate(device: &crate::usb::xhci::Device) -> bool {
    UsbIdentity::read(device).kind().is_some()
}
/// Initialize a fresh exclusively owned source-listed standard HCI binding.
/// The native consumer retains exactly one attempt, and every failed candidate
/// closes/quarantines its actual transport. No reset/recovery epoch is invented.
pub fn initialize<B: Io>(
    hci: &mut Hci<B>,
    provider: &dyn crate::firmware::Provider,
) -> Result<OwnedReport> {
    initialize::run(hci, provider)
}
#[cfg(test)]
mod tests;

pub(super) use packet::classify;
