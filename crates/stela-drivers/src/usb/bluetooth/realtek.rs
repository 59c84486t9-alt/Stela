// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Endless Mobile, Inc.
//! Realtek USB firmware staging adapted from pinned Linux `btrtl.c`/`btrtl.h`.
//! See THIRD_PARTY.md for exact provenance and limits. Explicit initialization
//! observes an exact USB/HCI/ROM/security profile, stages exact Provider images
//! and requires real download completions and post-upload version/address.
//! This establishes observed protocol execution, never vendor authentication,
//! radio validation or guest services. Generic firmware status is unchanged.
mod firmware;
mod identity;
mod initialize;
pub mod media;
mod v2;
pub use firmware::{Configuration, Fragment, Patch, Project, Staged};
pub use identity::{Identity, LocalVersion, UsbIdentity};
pub use v2::{ExtensionRecord, SectionObservation, SubsectionObservation, V2Metadata, V2Patch};

/// Malformed or explicitly unsupported Realtek input. Parsing never emits a
/// partially selected download or silently substitutes another ROM/project.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    Size,
    Signature,
    Extension,
    Project,
    PatchTable,
    PatchBounds,
    OverlappingPatches,
    DuplicateChip,
    MissingRom,
    ConfigHeader,
    ConfigEntry,
    OverlappingConfig,
    Section,
    Subsection,
    Security,
}
impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Realtek firmware format {self:?}")
    }
}
impl core::error::Error for FormatError {}

use super::{FirmwareReceipt, Hci, Io};
use alloc::{boxed::Box, vec::Vec};
pub type Result<T> = core::result::Result<T, Error>;

/// Exact config image or a named Missing error permitted by this
/// profile. Malformed/integrity/target failures can never enter OptionalMissing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationEvidence {
    Supplied(FirmwareReceipt),
    OptionalMissing(crate::firmware::Error),
}
/// Download return index kept without inventing an undocumented
/// echo rule. The pinned donor checks return shape, not index equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DownloadResponse {
    pub sent_index: u8,
    pub returned_index: u8,
}
/// Partial observed identity and immutable receipts survive every failure;
/// acknowledged commands never credit a ready or successfully booted image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub version: Option<LocalVersion>,
    pub register_subversion: Option<u16>,
    pub register_revision: Option<u16>,
    pub rom_version: Option<u8>,
    pub security: Option<[u8; 2]>,
    pub identity: Option<Identity>,
    pub firmware: Option<FirmwareReceipt>,
    pub configuration: Option<core::result::Result<FirmwareReceipt, crate::firmware::Error>>,
    pub container_version: Option<ContainerVersion>,
    pub v2: Option<V2Metadata>,
    pub download: Vec<DownloadResponse>,
    pub after: Option<LocalVersion>,
}
/// Container versions have different wire layouts. V2 keeps all eight raw
/// bytes in their original order; no truncation or invented scalar endianness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerVersion {
    V1(u32),
    V2([u8; 8]),
}
/// Historical owned protocol/image evidence, not current transport/radio state
/// or vendor-signature authentication. No Image/provider/firmware-byte borrow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub before: Identity,
    pub after: LocalVersion,
    pub address: [u8; 6],
    pub firmware: Box<FirmwareReceipt>,
    pub configuration: ConfigurationEvidence,
    pub container_version: ContainerVersion,
    /// Validated v2 hierarchy/control observations, absent for a v1 container.
    pub v2: Option<V2Metadata>,
    pub download: Vec<DownloadResponse>,
}
#[derive(Debug)]
pub enum Error {
    Unsupported(&'static str),
    Protocol {
        requirement: &'static str,
        observed: Vec<u8>,
    },
    Format(FormatError),
    Resource(crate::firmware::Error),
    Controller {
        opcode: u16,
        status: u8,
        parameters: Vec<u8>,
    },
    Timeout(&'static str),
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
impl From<FormatError> for Error {
    fn from(e: FormatError) -> Self {
        Self::Format(e)
    }
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Transport(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Realtek Bluetooth initialization {self:?}")
    }
}
impl core::error::Error for Error {}

pub(super) fn is_candidate(device: &crate::usb::xhci::Device) -> bool {
    UsbIdentity::read(device).project().is_some()
}
/// Initialize an exclusively owned attached candidate exactly once through the
/// native consumer wrapper. Any failed candidate attempt closes/quarantines its
/// transport and preserves typed failure/partial receipts; rebind is required.
/// Unsupported running variants are refused, never dropped or guessed ready.
pub fn initialize<B: Io>(
    hci: &mut Hci<B>,
    provider: &dyn crate::firmware::Provider,
) -> Result<OwnedReport> {
    initialize::run(hci, provider)
}

#[cfg(test)]
mod tests;
