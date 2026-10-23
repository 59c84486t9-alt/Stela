// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Exact source USB candidate IDs and runtime OTP/DFU identities.
use super::{Error, Result};
use crate::{firmware::Target, usb::xhci::Device};
use alloc::{format, string::String};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbIdentity {
    pub vendor: u16,
    pub product: u16,
    pub revision: u16,
}
impl UsbIdentity {
    pub fn read(device: &Device) -> Self {
        let d = &device.descriptor;
        Self {
            vendor: u16::from_le_bytes([d[8], d[9]]),
            product: u16::from_le_bytes([d[10], d[11]]),
            revision: u16::from_le_bytes([d[12], d[13]]),
        }
    }
    pub fn kind(self) -> Option<Kind> {
        SOURCE_USB_IDS
            .iter()
            .find(|&&(v, p, _)| (v, p) == (self.vendor, self.product))
            .map(|&(_, _, kind)| kind)
    }
    pub fn hardware_label(self) -> String {
        format!(
            "usb:{:04x}:{:04x}:{:04x}",
            self.vendor, self.product, self.revision
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Rome,
    Wcn,
}
pub const SOURCE_USB_IDS: &[(u16, u16, Kind)] = &[
    (0x0cf3, 0x535b, Kind::Rome),
    (0x0cf3, 0xe007, Kind::Rome),
    (0x0cf3, 0xe009, Kind::Rome),
    (0x0cf3, 0xe010, Kind::Rome),
    (0x0cf3, 0xe300, Kind::Rome),
    (0x0cf3, 0xe301, Kind::Rome),
    (0x0cf3, 0xe360, Kind::Rome),
    (0x0cf3, 0xe500, Kind::Rome),
    (0x0489, 0xe092, Kind::Rome),
    (0x0489, 0xe09f, Kind::Rome),
    (0x0489, 0xe0a2, Kind::Rome),
    (0x04ca, 0x3011, Kind::Rome),
    (0x04ca, 0x3015, Kind::Rome),
    (0x04ca, 0x3016, Kind::Rome),
    (0x04ca, 0x301a, Kind::Rome),
    (0x04ca, 0x3021, Kind::Rome),
    (0x13d3, 0x3491, Kind::Rome),
    (0x13d3, 0x3496, Kind::Rome),
    (0x13d3, 0x3501, Kind::Rome),
    (0x13d3, 0x3503, Kind::Rome),
    (0x0489, 0xe0c7, Kind::Wcn),
    (0x0489, 0xe0c9, Kind::Wcn),
    (0x0489, 0xe0ca, Kind::Wcn),
    (0x0489, 0xe0cb, Kind::Wcn),
    (0x0489, 0xe0cc, Kind::Wcn),
    (0x0489, 0xe0ce, Kind::Wcn),
    (0x0489, 0xe0d0, Kind::Wcn),
    (0x0489, 0xe0d6, Kind::Wcn),
    (0x0489, 0xe0de, Kind::Wcn),
    (0x0489, 0xe0df, Kind::Wcn),
    (0x0489, 0xe0e1, Kind::Wcn),
    (0x0489, 0xe0e3, Kind::Wcn),
    (0x0489, 0xe0ea, Kind::Wcn),
    (0x0489, 0xe0ec, Kind::Wcn),
    (0x04ca, 0x3022, Kind::Wcn),
    (0x04ca, 0x3023, Kind::Wcn),
    (0x04ca, 0x3024, Kind::Wcn),
    (0x04ca, 0x3a22, Kind::Wcn),
    (0x04ca, 0x3a24, Kind::Wcn),
    (0x04ca, 0x3a26, Kind::Wcn),
    (0x04ca, 0x3a27, Kind::Wcn),
    (0x0cf3, 0xe600, Kind::Wcn),
    (0x10ab, 0x9108, Kind::Wcn),
    (0x10ab, 0x9109, Kind::Wcn),
    (0x10ab, 0x9208, Kind::Wcn),
    (0x10ab, 0x9209, Kind::Wcn),
    (0x10ab, 0x9308, Kind::Wcn),
    (0x10ab, 0x9309, Kind::Wcn),
    (0x10ab, 0x9408, Kind::Wcn),
    (0x10ab, 0x9409, Kind::Wcn),
    (0x10ab, 0x9508, Kind::Wcn),
    (0x10ab, 0x9509, Kind::Wcn),
    (0x10ab, 0x9608, Kind::Wcn),
    (0x10ab, 0x9609, Kind::Wcn),
    (0x10ab, 0x9f09, Kind::Wcn),
    (0x28de, 0x1401, Kind::Wcn),
    (0x0cf3, 0xe700, Kind::Wcn),
    (0x0489, 0xe0fc, Kind::Wcn),
    (0x0489, 0xe0f3, Kind::Wcn),
    (0x0489, 0xe100, Kind::Wcn),
    (0x0489, 0xe103, Kind::Wcn),
    (0x0489, 0xe10a, Kind::Wcn),
    (0x0489, 0xe10d, Kind::Wcn),
    (0x0489, 0xe11b, Kind::Wcn),
    (0x0489, 0xe11c, Kind::Wcn),
    (0x0489, 0xe11f, Kind::Wcn),
    (0x0489, 0xe141, Kind::Wcn),
    (0x0489, 0xe14a, Kind::Wcn),
    (0x0489, 0xe14b, Kind::Wcn),
    (0x0489, 0xe14d, Kind::Wcn),
    (0x13d3, 0x3623, Kind::Wcn),
    (0x13d3, 0x3624, Kind::Wcn),
    (0x2c7c, 0x0130, Kind::Wcn),
    (0x2c7c, 0x0131, Kind::Wcn),
    (0x2c7c, 0x0132, Kind::Wcn),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub raw: [u8; 20],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub rom: u32,
    pub rampatch_header: usize,
    pub nvm_header: usize,
    pub version_offset: usize,
}
pub const PROFILES: &[Profile] = &[
    Profile {
        rom: 0x100,
        rampatch_header: 20,
        nvm_header: 4,
        version_offset: 8,
    },
    Profile {
        rom: 0x101,
        rampatch_header: 20,
        nvm_header: 4,
        version_offset: 8,
    },
    Profile {
        rom: 0x200,
        rampatch_header: 28,
        nvm_header: 4,
        version_offset: 16,
    },
    Profile {
        rom: 0x201,
        rampatch_header: 28,
        nvm_header: 4,
        version_offset: 16,
    },
    Profile {
        rom: 0x300,
        rampatch_header: 28,
        nvm_header: 4,
        version_offset: 16,
    },
    Profile {
        rom: 0x302,
        rampatch_header: 28,
        nvm_header: 4,
        version_offset: 16,
    },
    Profile {
        rom: 0x00130100,
        rampatch_header: 40,
        nvm_header: 4,
        version_offset: 16,
    },
    Profile {
        rom: 0x00130200,
        rampatch_header: 40,
        nvm_header: 4,
        version_offset: 16,
    },
    Profile {
        rom: 0x00130201,
        rampatch_header: 40,
        nvm_header: 4,
        version_offset: 16,
    },
    Profile {
        rom: 0x00190200,
        rampatch_header: 40,
        nvm_header: 4,
        version_offset: 16,
    },
];
impl Version {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            raw: bytes
                .try_into()
                .map_err(|_| Error::protocol("target version response length", bytes))?,
        })
    }
    pub fn rom(&self) -> u32 {
        u32::from_le_bytes(self.raw[..4].try_into().unwrap())
    }
    pub fn patch(&self) -> u32 {
        u32::from_le_bytes(self.raw[4..8].try_into().unwrap())
    }
    pub fn ram(&self) -> u32 {
        u32::from_le_bytes(self.raw[8..12].try_into().unwrap())
    }
    pub fn flags(&self) -> u16 {
        u16::from_le_bytes([self.raw[14], self.raw[15]])
    }
    pub fn profile(&self) -> Result<Profile> {
        PROFILES
            .iter()
            .find(|p| p.rom == self.rom())
            .copied()
            .ok_or(Error::UnsupportedRom(self.rom()))
    }
    pub fn board_id(&self) -> u16 {
        if self.flags() >> 8 != 0x80 {
            return 0;
        }
        let board = u16::from_be_bytes([self.raw[12], self.raw[13]]);
        if board == 0xffff { 0 } else { board }
    }
    fn subdirectory(&self) -> &'static str {
        if self.rom() == 0x00130201 && matches!(self.board_id(), 0x030a | 0x030b) {
            "QCA2066/"
        } else {
            ""
        }
    }
    pub fn rampatch_name(&self) -> String {
        format!(
            "qca/{}rampatch_usb_{:08x}.bin",
            self.subdirectory(),
            self.rom()
        )
    }
    pub fn nvm_name(&self) -> String {
        let gf = if matches!(self.ram(), 0x400c1200 | 0x400c1211) {
            "_gf"
        } else {
            ""
        };
        let board = if self.board_id() != 0 {
            format!("_{:04x}", self.board_id())
        } else {
            String::new()
        };
        format!(
            "qca/{}nvm_usb_{:08x}{}{}.bin",
            self.subdirectory(),
            self.rom(),
            gf,
            board
        )
    }
    pub fn revision_label(&self) -> String {
        // Running patch build is not a silicon selector; the actual rampatch
        // header independently guards against downgrade. Preserve it in raw.
        format!(
            "rom-{:08x}:ram-{:08x}:chip-{:02x}:platform-{:02x}:flags-{:04x}",
            self.rom(),
            self.ram(),
            self.raw[12],
            self.raw[13],
            self.flags()
        )
    }
    pub fn target<'a>(&self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: "qualcomm-bluetooth-usb-dfu",
            hardware,
            revision,
            board: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RampatchVersion {
    pub rom: u32,
    pub patch: u16,
}
impl RampatchVersion {
    pub fn parse(bytes: &[u8], version: &Version, profile: Profile) -> Result<Self> {
        if bytes.len() < profile.rampatch_header {
            return Err(Error::protocol(
                "rampatch shorter than complete header",
                bytes,
            ));
        }
        let end = profile
            .version_offset
            .checked_add(6)
            .ok_or_else(|| Error::protocol("rampatch version bounds", bytes))?;
        let p = bytes
            .get(profile.version_offset..end)
            .ok_or_else(|| Error::protocol("rampatch version bounds", bytes))?;
        let low = u32::from(u16::from_le_bytes([p[2], p[3]]));
        let rom = if version.rom() & 0xffff0000 != 0 {
            u32::from(u16::from_le_bytes([p[0], p[1]])) << 16 | low
        } else {
            low
        };
        let patch = u16::from_le_bytes([p[4], p[5]]);
        if rom != version.rom() || u32::from(patch) < version.patch() {
            return Err(Error::protocol("rampatch ROM mismatch or downgrade", p));
        }
        Ok(Self { rom, patch })
    }
}
