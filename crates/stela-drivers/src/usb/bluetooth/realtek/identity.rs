// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Endless Mobile, Inc.
//! Exact USB/ROM profiles from pinned btusb.c and btrtl.c. No filename alone
//! identifies a controller, and no unknown running firmware is silently dropped.
use super::{Error, Project, Result};
use crate::{firmware::Target, usb::xhci::Device};
use alloc::{format, string::String};

/// All bytes of a genuine standard Read Local Version return, including status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalVersion {
    pub raw: [u8; 9],
}
impl LocalVersion {
    pub(super) fn parse(p: &[u8]) -> Result<Self> {
        let raw = p
            .try_into()
            .map_err(|_| Error::protocol("Read Local Version length", p))?;
        if p[0] != 0 {
            return Err(Error::protocol("Read Local Version status", p));
        }
        Ok(Self { raw })
    }
    pub fn hci_version(&self) -> u8 {
        self.raw[1]
    }
    pub fn hci_revision(&self) -> u16 {
        u16::from_le_bytes([self.raw[2], self.raw[3]])
    }
    pub fn lmp_version(&self) -> u8 {
        self.raw[4]
    }
    pub fn manufacturer(&self) -> u16 {
        u16::from_le_bytes([self.raw[5], self.raw[6]])
    }
    pub fn lmp_subversion(&self) -> u16 {
        u16::from_le_bytes([self.raw[7], self.raw[8]])
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbIdentity {
    pub vendor: u16,
    pub product: u16,
    pub revision: u16,
}
impl UsbIdentity {
    pub(super) fn read(device: &Device) -> Self {
        let d = &device.descriptor;
        Self {
            vendor: u16::from_le_bytes([d[8], d[9]]),
            product: u16::from_le_bytes([d[10], d[11]]),
            revision: u16::from_le_bytes([d[12], d[13]]),
        }
    }
    pub(super) fn project(self) -> Option<Project> {
        match (self.vendor, self.product) {
            // Explicit btusb 8761BU/8761BUV entries; no vendor-wide expansion.
            (0x0bda, 0xa728 | 0x8771) | (0x0b05, 0x190e) => Some(Project::Rtl8761Bu),
            // Explicit btusb additional 8822BE entries.
            (0x13d3, 0x3526) | (0x0b05, 0x185c) => Some(Project::Rtl8822B),
            _ => None,
        }
    }
    pub fn hardware_label(self) -> String {
        format!(
            "usb:{:04x}:{:04x}:{:04x}",
            self.vendor, self.product, self.revision
        )
    }
}
/// Complete independently observed selection, bound into every resource request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub usb: UsbIdentity,
    pub version: LocalVersion,
    pub register_subversion: u16,
    pub register_revision: Option<u16>,
    pub rom_version: u8,
    /// Both register response bytes retained; byte0 selects the security key.
    pub security: [u8; 2],
    pub project: Project,
}
impl Identity {
    pub(super) fn select(
        usb: UsbIdentity,
        version: LocalVersion,
        register_subversion: u16,
        register_revision: Option<u16>,
        rom_version: u8,
        security: [u8; 2],
    ) -> Result<Self> {
        let project = usb.project().ok_or(Error::Unsupported("USB identity"))?;
        let (lmp, hci_rev, hci_ver) = match project {
            Project::Rtl8761Bu => (0x8761, 0xb, 0xa),
            Project::Rtl8822B => (0x8822, 0xb, 7),
            Project::Rtl8852Bu => {
                return Err(Error::Unsupported(
                    "EPATCH v2 live admission not implemented",
                ));
            }
        };
        if version.manufacturer() != 0x005d
            || version.lmp_subversion() != lmp
            || version.hci_revision() != hci_rev
            || version.hci_version() != hci_ver
            || register_subversion != lmp
            || (project == Project::Rtl8822B
                && (register_revision.is_none() || register_revision == Some(0x000e)))
        {
            return Err(Error::Unsupported(
                "USB and observed stock ROM/HCI profile mismatch",
            ));
        }
        if security[0] != 0 {
            return Err(Error::Unsupported(
                "nonzero Realtek security key requires EPATCH v2 validation",
            ));
        }
        Ok(Self {
            usb,
            version,
            register_subversion,
            register_revision,
            rom_version,
            security,
            project,
        })
    }
    pub fn revision_label(&self) -> String {
        let revision = self
            .register_revision
            .map_or_else(|| "none".into(), |v| format!("{v:04x}"));
        format!(
            "epatch-v1:hci-{:02x}-{:04x}:lmp-{:02x}-{:04x}:manufacturer-{:04x}:register-{:04x}-{revision}:rom-{:02x}:security-{:02x}-{:02x}",
            self.version.hci_version(),
            self.version.hci_revision(),
            self.version.lmp_version(),
            self.version.lmp_subversion(),
            self.version.manufacturer(),
            self.register_subversion,
            self.rom_version,
            self.security[0],
            self.security[1]
        )
    }
    pub(super) fn target<'a>(&self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: "realtek-bluetooth-usb-epatch-v1",
            hardware,
            revision,
            board: None,
        }
    }
    pub fn firmware_name(&self) -> &'static str {
        match self.project {
            Project::Rtl8761Bu => "rtl_bt/rtl8761bu_fw.bin",
            Project::Rtl8822B => "rtl_bt/rtl8822b_fw.bin",
            Project::Rtl8852Bu => "rtl_bt/rtl8852bu_fw.bin",
        }
    }
    pub fn configuration_name(&self) -> &'static str {
        match self.project {
            Project::Rtl8761Bu => "rtl_bt/rtl8761bu_config.bin",
            Project::Rtl8822B => "rtl_bt/rtl8822b_config.bin",
            Project::Rtl8852Bu => "rtl_bt/rtl8852bu_config.bin",
        }
    }
    pub fn configuration_required(&self) -> bool {
        self.project == Project::Rtl8822B
    }
}
