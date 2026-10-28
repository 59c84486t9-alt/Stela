// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2008-2009 Atheros Communications Inc.
//! USB identities of the Atheros AR3011 and AR3012 bootloaders.
use super::{Error, Result};
use crate::{firmware::Target, usb::xhci::Device};
use alloc::{format, string::String};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ar3011,
    Ar3012,
}
pub const SOURCE_USB_IDS: &[(u16, u16, Kind)] = &[
    (0x0cf3, 0x3000, Kind::Ar3011),
    (0x0489, 0xe027, Kind::Ar3011),
    (0x0489, 0xe03d, Kind::Ar3011),
    (0x04f2, 0xaff1, Kind::Ar3011),
    (0x0930, 0x0215, Kind::Ar3011),
    (0x0cf3, 0x3002, Kind::Ar3011),
    (0x0cf3, 0xe019, Kind::Ar3011),
    (0x13d3, 0x3304, Kind::Ar3011),
    (0x03f0, 0x311d, Kind::Ar3011),
    (0x0489, 0xe04d, Kind::Ar3012),
    (0x0489, 0xe04e, Kind::Ar3012),
    (0x0489, 0xe057, Kind::Ar3012),
    (0x0489, 0xe056, Kind::Ar3012),
    (0x0489, 0xe05f, Kind::Ar3012),
    (0x0489, 0xe076, Kind::Ar3012),
    (0x0489, 0xe078, Kind::Ar3012),
    (0x0489, 0xe095, Kind::Ar3012),
    (0x04c5, 0x1330, Kind::Ar3012),
    (0x04ca, 0x3004, Kind::Ar3012),
    (0x04ca, 0x3005, Kind::Ar3012),
    (0x04ca, 0x3006, Kind::Ar3012),
    (0x04ca, 0x3007, Kind::Ar3012),
    (0x04ca, 0x3008, Kind::Ar3012),
    (0x04ca, 0x300b, Kind::Ar3012),
    (0x04ca, 0x300d, Kind::Ar3012),
    (0x04ca, 0x300f, Kind::Ar3012),
    (0x04ca, 0x3010, Kind::Ar3012),
    (0x04ca, 0x3014, Kind::Ar3012),
    (0x04ca, 0x3018, Kind::Ar3012),
    (0x0930, 0x0219, Kind::Ar3012),
    (0x0930, 0x021c, Kind::Ar3012),
    (0x0930, 0x0220, Kind::Ar3012),
    (0x0930, 0x0227, Kind::Ar3012),
    (0x0b05, 0x17d0, Kind::Ar3012),
    (0x0cf3, 0x0036, Kind::Ar3012),
    (0x0cf3, 0x3004, Kind::Ar3012),
    (0x0cf3, 0x3008, Kind::Ar3012),
    (0x0cf3, 0x311d, Kind::Ar3012),
    (0x0cf3, 0x311e, Kind::Ar3012),
    (0x0cf3, 0x311f, Kind::Ar3012),
    (0x0cf3, 0x3121, Kind::Ar3012),
    (0x0cf3, 0x817a, Kind::Ar3012),
    (0x0cf3, 0x817b, Kind::Ar3012),
    (0x0cf3, 0xe003, Kind::Ar3012),
    (0x0cf3, 0xe004, Kind::Ar3012),
    (0x0cf3, 0xe005, Kind::Ar3012),
    (0x0cf3, 0xe006, Kind::Ar3012),
    (0x13d3, 0x3362, Kind::Ar3012),
    (0x13d3, 0x3375, Kind::Ar3012),
    (0x13d3, 0x3393, Kind::Ar3012),
    (0x13d3, 0x3395, Kind::Ar3012),
    (0x13d3, 0x3402, Kind::Ar3012),
    (0x13d3, 0x3408, Kind::Ar3012),
    (0x13d3, 0x3423, Kind::Ar3012),
    (0x13d3, 0x3432, Kind::Ar3012),
    (0x13d3, 0x3472, Kind::Ar3012),
    (0x13d3, 0x3474, Kind::Ar3012),
    (0x13d3, 0x3487, Kind::Ar3012),
    (0x13d3, 0x3490, Kind::Ar3012),
    (0x0489, 0xe02c, Kind::Ar3011),
    (0x0489, 0xe036, Kind::Ar3012),
    (0x0489, 0xe03c, Kind::Ar3012),
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbIdentity {
    pub vendor: u16,
    pub product: u16,
    pub revision: u16,
}
impl UsbIdentity {
    pub fn read(device: &Device) -> Self {
        Self {
            vendor: u16::from_le_bytes([device.descriptor[8], device.descriptor[9]]),
            product: u16::from_le_bytes([device.descriptor[10], device.descriptor[11]]),
            revision: u16::from_le_bytes([device.descriptor[12], device.descriptor[13]]),
        }
    }
    pub fn kind(self) -> Option<Kind> {
        SOURCE_USB_IDS
            .iter()
            .find(|(v, p, _)| (*v, *p) == (self.vendor, self.product))
            .and_then(|(_, _, k)| {
                if *k == Kind::Ar3012 && self.revision > 1 {
                    None
                } else {
                    Some(*k)
                }
            })
    }
    pub fn hardware(self) -> String {
        format!(
            "usb:{:04x}:{:04x}:{:04x}",
            self.vendor, self.product, self.revision
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub raw: [u8; 20],
}
impl Version {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            raw: bytes
                .try_into()
                .map_err(|_| Error::protocol("ATH3K version response length", bytes))?,
        })
    }
    pub fn rom(&self) -> u32 {
        u32::from_le_bytes(self.raw[0..4].try_into().unwrap())
    }
    pub fn build(&self) -> u32 {
        u32::from_le_bytes(self.raw[4..8].try_into().unwrap())
    }
    pub fn ram(&self) -> u32 {
        u32::from_le_bytes(self.raw[8..12].try_into().unwrap())
    }
    pub fn clock(&self) -> u8 {
        self.raw[12]
    }
    pub fn patch_name(&self) -> String {
        format!("ar3k/AthrBT_0x{:08x}.dfu", self.rom())
    }
    pub fn config_name(&self) -> String {
        format!(
            "ar3k/ramps_0x{:08x}_{}.dfu",
            self.rom(),
            match self.clock() {
                0 => 26,
                1 => 40,
                2 => 19,
                _ => 0,
            }
        )
    }
    pub fn revision(&self) -> String {
        format!(
            "rom-{:08x}:ram-{:08x}:clock-{:02x}",
            self.rom(),
            self.ram(),
            self.clock()
        )
    }
}
pub(super) fn target<'a>(hardware: &'a str, revision: &'a str) -> Target<'a> {
    Target {
        driver: "atheros-bluetooth-usb-bootloader",
        hardware,
        revision,
        board: None,
    }
}
