// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Bounded MT79xx Bluetooth firmware parsing and WMT download framing adapted
//! from pinned Linux btmtk.c. The explicit native initializer requires observed
//! silicon/ROM/flavor, exact Provider input and EP0 WMT events. Image
//! authenticity, physical/radio validation and guest services remain separate.
//! Normal USB initialization is separate from the source WLAN restart path;
//! the pinned source establishes no mandatory cross-function probe order.
//! Each function keeps its resource owner. A failed firmware setup,
//! a command timeout and a completed dump run btusb_mtk_reset as Linux does:
//! the btmtk subsystem reset, then a queued USB reset that rebinds the device.
pub mod coredump;
mod firmware;
mod identity;
mod initialize;
pub(super) mod packet;
pub mod reset;
mod wmt;
pub use firmware::{FirmwareMetadata, Fragment, Patch, Section, SectionMetadata};
pub use identity::{Chip, Identity, UsbIdentity};
pub use wmt::{WmtCommandReceipt, WmtEvent};

pub mod media;

use super::{FirmwareReceipt, Hci, Io};
use alloc::{boxed::Box, vec::Vec};
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterObservation {
    pub address: u32,
    pub value: u32,
}
/// Already-present controller state is not proof that our candidate image was
/// uploaded, verified by the ROM, or is the active executable image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionDisposition {
    Transferred,
    AlreadyPresentUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionReceipt {
    pub index: usize,
    pub queries: Vec<WmtEvent>,
    pub acknowledged_fragments: usize,
    pub last_download_response: Option<WmtEvent>,
    pub disposition: Option<SectionDisposition>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attempt {
    pub registers: Vec<RegisterObservation>,
    pub identity: Option<Identity>,
    pub firmware: Option<FirmwareReceipt>,
    pub metadata: Option<FirmwareMetadata>,
    pub sections: Vec<SectionReceipt>,
    pub pending_wmt: Option<WmtCommandReceipt>,
    /// Latest parsed EP0 observation, including a response rejected by
    /// subsequent timing/interrupt/status validation. It never credits success.
    pub last_wmt: Option<WmtEvent>,
    pub endpoint_reset_option_completed: bool,
    pub function_enable: Option<WmtEvent>,
    pub auxiliary_hci_events: Vec<Vec<u8>>,
    pub reset_completion: Option<Vec<u8>>,
    pub local_version: Option<[u8; 9]>,
    pub address: Option<[u8; 6]>,
    /// The btusb_mtk_reset that followed a failed firmware setup or command.
    pub reset: Option<reset::Reset>,
}
/// What Linux btusb/btmtk tell the host stack about a MediaTek controller
/// (btusb_probe's BTUSB_MEDIATEK branch and btmtk_usb_setup for MT79xx).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPolicy {
    /// The Bluetooth SIG company identifier Linux assigns: MediaTek, 70.
    pub manufacturer: u16,
    /// BTUSB_WIDEBAND_SPEECH from the explicit device table entry.
    pub wideband_speech: bool,
    pub broken_enhanced_setup_sync_conn: bool,
    /// HCI_QUIRK_NON_PERSISTENT_SETUP: setup runs again on every power-on.
    pub non_persistent_setup: bool,
    pub microsoft_opcode: Option<u16>,
    pub aosp: bool,
}
impl HostPolicy {
    pub(super) fn for_device(usb: UsbIdentity) -> Self {
        Self {
            manufacturer: 70,
            wideband_speech: usb.wideband_speech(),
            broken_enhanced_setup_sync_conn: true,
            non_persistent_setup: true,
            // btmtk_usb_setup's MT7922/MT7925/MT7961 case.
            microsoft_opcode: Some(0xfd30),
            aosp: true,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPolicy {
    FreshRebindRequired,
}
/// Owned historical execution evidence. Per-section dispositions preserve the
/// distinction between transferred bytes and unknown already-present firmware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedReport {
    pub identity: Identity,
    pub firmware: Box<FirmwareReceipt>,
    pub metadata: FirmwareMetadata,
    pub sections: Vec<SectionReceipt>,
    pub function_enable: WmtEvent,
    pub auxiliary_hci_events: Vec<Vec<u8>>,
    pub reset_completion: Vec<u8>,
    pub local_version: [u8; 9],
    pub address: [u8; 6],
    /// The HCI command allowance setup's last Command Complete returned.
    pub command_credits: u8,
    pub recovery: RecoveryPolicy,
    pub policy: HostPolicy,
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
        write!(f, "MediaTek Bluetooth initialization {self:?}")
    }
}
impl core::error::Error for Error {}
pub fn is_candidate(device: &crate::usb::xhci::Device) -> bool {
    UsbIdentity::read(device).candidate()
        && crate::usb::descriptor::interfaces(&device.configuration)
            .iter()
            .any(|i| i.alternate == 0 && (i.class, i.subclass, i.protocol) == (super::CLASS, 1, 1))
}
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub fn initialize<B: Io>(
    hci: &mut Hci<B>,
    provider: &dyn crate::firmware::Provider,
) -> Result<OwnedReport> {
    initialize::run(hci, provider)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    Size,
    Header,
    SectionTable,
    SectionBounds,
    DownloadBounds,
    OverlappingSections,
    NoDownload,
}
impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek firmware format {self:?}")
    }
}
impl core::error::Error for FormatError {}

#[cfg(test)]
mod tests;
