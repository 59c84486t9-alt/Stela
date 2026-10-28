// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Explicit USB candidates from pinned btusb, with independent btmtk live
//! register/ROM/flavor selection. No USB ID alone selects a firmware image.
use super::{Error, Result};
use crate::{firmware::Target, usb::xhci::Device};
use alloc::{format, string::String};
const CANDIDATES: &[(u16, u16)] = &[
    (0x0489, 0xe0c8),
    (0x0489, 0xe0cd),
    (0x0489, 0xe0d8),
    (0x0489, 0xe0d9),
    (0x0489, 0xe0e0),
    (0x0489, 0xe0e2),
    (0x0489, 0xe0e4),
    (0x0489, 0xe0f1),
    (0x0489, 0xe0f2),
    (0x0489, 0xe0f5),
    (0x0489, 0xe0f6),
    (0x0489, 0xe102),
    (0x0489, 0xe111),
    (0x0489, 0xe113),
    (0x0489, 0xe118),
    (0x0489, 0xe11d),
    (0x0489, 0xe11e),
    (0x0489, 0xe124),
    (0x0489, 0xe139),
    (0x0489, 0xe14e),
    (0x0489, 0xe14f),
    (0x0489, 0xe150),
    (0x0489, 0xe151),
    (0x0489, 0xe152),
    (0x0489, 0xe153),
    (0x0489, 0xe170),
    (0x0489, 0xe174),
    (0x04ca, 0x3802),
    (0x04ca, 0x3804),
    (0x04ca, 0x3807),
    (0x04ca, 0x38e4),
    (0x0e8d, 0x0608),
    (0x0e8d, 0x223c),
    (0x0e8d, 0x8c38),
    (0x13d3, 0x3563),
    (0x13d3, 0x3564),
    (0x13d3, 0x3567),
    (0x13d3, 0x3568),
    (0x13d3, 0x3576),
    (0x13d3, 0x3578),
    (0x13d3, 0x3583),
    (0x13d3, 0x3584),
    (0x13d3, 0x3585),
    (0x13d3, 0x3602),
    (0x13d3, 0x3603),
    (0x13d3, 0x3604),
    (0x13d3, 0x3605),
    (0x13d3, 0x3606),
    (0x13d3, 0x3607),
    (0x13d3, 0x3608),
    (0x13d3, 0x3609),
    (0x13d3, 0x3610),
    (0x13d3, 0x3613),
    (0x13d3, 0x3614),
    (0x13d3, 0x3615),
    (0x13d3, 0x3625),
    (0x13d3, 0x3627),
    (0x13d3, 0x3628),
    (0x13d3, 0x3630),
    (0x13d3, 0x3633),
    (0x2c7c, 0x7009),
    (0x35f5, 0x7922),
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbIdentity {
    pub vendor: u16,
    pub product: u16,
    pub revision: u16,
}
impl UsbIdentity {
    pub(super) fn read(d: &Device) -> Self {
        let p = &d.descriptor;
        Self {
            vendor: u16::from_le_bytes([p[8], p[9]]),
            product: u16::from_le_bytes([p[10], p[11]]),
            revision: u16::from_le_bytes([p[12], p[13]]),
        }
    }
    pub(super) fn candidate(self) -> bool {
        self.vendor == 0x0e8d || CANDIDATES.contains(&(self.vendor, self.product))
    }
    /// Every explicit btusb MediaTek entry Stela admits carries
    /// BTUSB_WIDEBAND_SPEECH; the vendor-wide 0e8d class match does not.
    pub(super) fn wideband_speech(self) -> bool {
        CANDIDATES.contains(&(self.vendor, self.product))
    }
    pub fn hardware_label(self) -> String {
        format!(
            "usb:{:04x}:{:04x}:{:04x}",
            self.vendor, self.product, self.revision
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chip {
    Mt7961,
    Mt7922,
    Mt7925,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub usb: UsbIdentity,
    pub legacy_device_id: u32,
    pub device_id: u32,
    pub firmware_version: u32,
    pub flavor: u32,
    pub chip: Chip,
}
impl Identity {
    pub(super) fn select(
        usb: UsbIdentity,
        legacy_device_id: u32,
        device_id: u32,
        firmware_version: u32,
        flavor: u32,
    ) -> Result<Self> {
        if !usb.candidate() || legacy_device_id == 0x7663 {
            return Err(Error::Unsupported("USB/legacy hardware variant"));
        }
        let chip = match (device_id, firmware_version & 0xff) {
            (0x7961, 1) if flavor & 0x80 == 0 => Chip::Mt7961,
            (0x7922, 0) => Chip::Mt7922,
            (0x7925, 0) => Chip::Mt7925,
            _ => {
                return Err(Error::Unsupported(
                    "device/ROM/flavor has no qualified MT79xx image selector",
                ));
            }
        };
        Ok(Self {
            usb,
            legacy_device_id,
            device_id,
            firmware_version,
            flavor,
            chip,
        })
    }
    pub fn firmware_name(&self) -> &'static str {
        match self.chip {
            Chip::Mt7961 => "mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin",
            Chip::Mt7922 => "mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin",
            Chip::Mt7925 => "mediatek/mt7925/BT_RAM_CODE_MT7925_1_1_hdr.bin",
        }
    }
    pub fn revision_label(&self) -> String {
        format!(
            "mt79xx-v1:legacy-{:08x}:device-{:08x}:firmware-{:08x}:flavor-{:08x}",
            self.legacy_device_id, self.device_id, self.firmware_version, self.flavor
        )
    }
    pub(super) fn target<'a>(&self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: "mediatek-bluetooth-usb-mt79xx-v1",
            hardware,
            revision,
            board: None,
        }
    }
}
