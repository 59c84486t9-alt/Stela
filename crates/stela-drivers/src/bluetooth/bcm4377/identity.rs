// SPDX-License-Identifier: MIT
// Copyright (C) The Asahi Linux Contributors
//! Chip, OTP and board selection adapted from pinned hci_bcm4377.c.
use super::{Error, Result};
use crate::{bus::pci::Address, firmware::Target};
use alloc::{format, string::String};
use stela_crypto::{Sha256, digest::Digest};

pub const OTP_BYTES: usize = 0xe0;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciIdentity {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub revision: u8,
    /// PCI's 24-bit class/subclass/programming-interface value.
    pub class: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chip {
    Bcm4377,
    Bcm4378,
    Bcm4387,
    Bcm4388,
}
impl Chip {
    pub(super) fn select(identity: PciIdentity) -> Result<Self> {
        if identity.vendor != 0x14e4 || identity.class & 0xffff00 != 0x028000 {
            return Err(Error::Unsupported(
                "source Broadcom PCI network-other Function",
            ));
        }
        match identity.device {
            0x5fa0 => Ok(Self::Bcm4377),
            0x5f69 => Ok(Self::Bcm4378),
            0x5f71 => Ok(Self::Bcm4387),
            0x5f72 => Ok(Self::Bcm4388),
            _ => Err(Error::Unsupported("source Broadcom PCIe device ID")),
        }
    }
    pub fn number(self) -> u16 {
        match self {
            Self::Bcm4377 => 0x4377,
            Self::Bcm4378 => 0x4378,
            Self::Bcm4387 => 0x4387,
            Self::Bcm4388 => 0x4388,
        }
    }
    pub(super) fn otp_offset(self) -> u32 {
        match self {
            Self::Bcm4377 | Self::Bcm4378 => 0x4120,
            Self::Bcm4387 => 0x413c,
            Self::Bcm4388 => 0x415c,
        }
    }
    pub(super) fn bar2(self, offset: u32) -> u32 {
        offset + if self == Self::Bcm4388 { 0x200000 } else { 0 }
    }
    pub(super) fn windows(self) -> (u32, u32, Option<u32>) {
        match self {
            Self::Bcm4377 => (0x1800b000, 0x1810c000, None),
            Self::Bcm4378 => (0x18002000, 0x1810a000, Some(0x18107000)),
            Self::Bcm4387 | Self::Bcm4388 => (0x18002000, 0x18109000, Some(0x18106000)),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardSource {
    Dmi {
        vendor: String,
        product: String,
    },
    /// Original brcm,board-type property bytes, including any terminating NUL.
    FirmwareProperty(alloc::vec::Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Board {
    name: String,
    source: BoardSource,
}
impl Board {
    /// Parse captured DMI observations. Only the source's three exact
    /// checked products select its formosa board; no generic Apple fallback.
    pub fn from_dmi(vendor: &str, product: &str) -> Result<Self> {
        if vendor != "Apple Inc."
            || !matches!(
                product,
                "MacBookAir9,1" | "MacBookPro15,4" | "MacBookPro16,3"
            )
        {
            return Err(Error::Unsupported("source Broadcom DMI board"));
        }
        Ok(Self {
            name: "apple,formosa".into(),
            source: BoardSource::Dmi {
                vendor: vendor.into(),
                product: product.into(),
            },
        })
    }
    /// Parse the board property. Platform construction must bind this
    /// observation to the same physical Function, rather than inventing a board.
    pub fn from_property(bytes: &[u8]) -> Result<Self> {
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        if bytes[end..].iter().any(|b| *b != 0) {
            return Err(Error::Unsupported("ambiguous Broadcom board property"));
        }
        let name = component(&bytes[..end], 63)?;
        Ok(Self {
            name,
            source: BoardSource::FirmwareProperty(bytes.into()),
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn source(&self) -> &BoardSource {
        &self.source
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub pci: PciIdentity,
    pub chip: Chip,
    pub board: Board,
    pub stepping: String,
    pub antenna_vendor: String,
    /// Complete OTP, including unknown TLVs and padding.
    pub otp: [u8; OTP_BYTES],
}
impl Identity {
    pub(super) fn parse(pci: PciIdentity, board: Board, otp: [u8; OTP_BYTES]) -> Result<Self> {
        let chip = Chip::select(pci)?;
        let mut selected = None;
        let mut at = 0;
        while at + 1 < otp.len() {
            let kind = otp[at];
            if kind == 0 {
                break;
            }
            let end = at + 2 + usize::from(otp[at + 1]);
            let data = otp
                .get(at + 2..end)
                .ok_or(Error::Unsupported("truncated Broadcom OTP TLV"))?;
            if kind == 0x15 {
                if selected.is_some() || data.len() < 6 || data[..4] != 8u32.to_le_bytes() {
                    return Err(Error::Unsupported("unambiguous Broadcom OTP vendor header"));
                }
                let chip_end = data[4..]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|i| i + 4)
                    .ok_or(Error::Unsupported(
                        "terminated Broadcom OTP chip parameters",
                    ))?;
                let board_at = chip_end + 1;
                let board_end = data[board_at..]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|i| i + board_at)
                    .ok_or(Error::Unsupported(
                        "terminated Broadcom OTP board parameters",
                    ))?;
                let stepping = parameter(&data[4..chip_end], b's')?
                    .ok_or(Error::Unsupported("observed Broadcom stepping"))?
                    .to_ascii_lowercase();
                let vendor = parameter(&data[board_at..board_end], b'V')?
                    .ok_or(Error::Unsupported("observed Broadcom antenna vendor"))?;
                selected = Some((stepping, vendor));
            }
            at = end;
        }
        let (stepping, antenna_vendor) =
            selected.ok_or(Error::Unsupported("Broadcom OTP vendor parameters"))?;
        Ok(Self {
            pci,
            chip,
            board,
            stepping,
            antenna_vendor,
            otp,
        })
    }
    pub fn hardware_label(&self) -> String {
        format!(
            "pci:{:04x}:{:04x}:{:04x}:{:04x}",
            self.pci.vendor, self.pci.device, self.pci.subsystem_vendor, self.pci.subsystem_device
        )
    }
    pub fn revision_label(&self) -> String {
        format!(
            "{:02x}:otp-v1:sha256:{:x}",
            self.pci.revision,
            Sha256::digest(self.otp)
        )
    }
    pub(super) fn names(&self, suffix: &str) -> Result<[String; 2]> {
        let prefix = format!(
            "brcm/brcmbt{:04x}{}-{}",
            self.chip.number(),
            self.stepping,
            self.board.name()
        );
        let names = [
            format!("{prefix}-{}.{suffix}", self.antenna_vendor),
            format!("{prefix}.{suffix}"),
        ];
        if names.iter().any(|name| name.len() >= 64) {
            return Err(Error::Unsupported(
                "source Broadcom firmware filename capacity",
            ));
        }
        Ok(names)
    }
    pub(super) fn target<'a>(&'a self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: "broadcom-bluetooth-pcie",
            hardware,
            revision,
            board: Some(self.board.name()),
        }
    }
}
fn component(bytes: &[u8], maximum: usize) -> Result<String> {
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.windows(2).any(|p| p == b"..")
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b','))
    {
        return Err(Error::Unsupported(
            "bounded safe Broadcom firmware name component",
        ));
    }
    Ok(core::str::from_utf8(bytes).unwrap().into())
}
fn parameter(bytes: &[u8], selected: u8) -> Result<Option<String>> {
    let mut value = None;
    for token in bytes
        .split(|b| b.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
    {
        if token.len() < 2 || token[1] != b'=' || token.len() - 2 > 15 {
            return Err(Error::Unsupported("bounded Broadcom OTP parameters"));
        }
        if token[0] == selected {
            if value.is_some() {
                return Err(Error::Unsupported("unambiguous Broadcom OTP parameter"));
            }
            value = Some(component(&token[2..], 15)?);
        }
    }
    Ok(value)
}
