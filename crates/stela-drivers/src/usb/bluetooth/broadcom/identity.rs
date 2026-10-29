// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Broadcom USB Bluetooth identities: USB and HCI versions, chip names and patch-file names.
use super::{Error, Result};
use crate::{
    firmware::Target,
    usb::xhci::{Device, Interface},
};
use alloc::{format, string::String, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbIdentity {
    pub vendor: u16,
    pub product: u16,
    pub revision: u16,
}
impl UsbIdentity {
    pub fn read(device: &Device) -> Self {
        let identity = super::super::identity::read(&device.descriptor);
        Self {
            vendor: identity.vendor,
            product: identity.product,
            revision: identity.revision,
        }
    }
    pub fn hardware_label(self) -> String {
        format!(
            "usb:{:04x}:{:04x}:{:04x}",
            self.vendor, self.product, self.revision
        )
    }
}

/// Exact Linux btusb BCM_PATCHRAM vendor/interface entries. This is candidate
/// admission only; HCI version/manufacturer still binds firmware.
pub fn is_vendor_interface(device: &Device, interface: &Interface) -> bool {
    let usb = UsbIdentity::read(device);
    interface.number == 0
        && interface.alternate == 0
        && (interface.class, interface.subclass, interface.protocol) == (0xff, 1, 1)
        && ((usb.vendor, usb.product) == (0x19ff, 0x0239)
            || matches!(
                usb.vendor,
                0x105b
                    | 0x0bb4
                    | 0x0489
                    | 0x04ca
                    | 0x0a5c
                    | 0x0b05
                    | 0x050d
                    | 0x13d3
                    | 0x413c
                    | 0x0930
            ))
}

pub(super) fn is_candidate(device: &Device) -> bool {
    let usb = UsbIdentity::read(device);
    crate::usb::xhci::interfaces(&device.configuration)
        .iter()
        .any(|i| {
            is_vendor_interface(device, i)
                || ((usb.vendor, usb.product) == (0x19ff, 0x0239)
                    && i.number == 0
                    && i.alternate == 0
                    && (i.class, i.subclass, i.protocol) == (0xe0, 1, 1))
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalVersion {
    pub raw: [u8; 9],
}
impl LocalVersion {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let raw = bytes
            .try_into()
            .map_err(|_| Error::protocol("Read Local Version length", bytes))?;
        if bytes[0] != 0 || u16::from_le_bytes([bytes[5], bytes[6]]) != 15 {
            return Err(Error::protocol("Broadcom manufacturer/status", bytes));
        }
        Ok(Self { raw })
    }
    pub fn subversion(&self) -> u16 {
        u16::from_le_bytes([self.raw[7], self.raw[8]])
    }
    pub fn revision(&self) -> u16 {
        u16::from_le_bytes([self.raw[2], self.raw[3]])
    }
    pub fn hardware_name(&self) -> Option<&'static str> {
        Some(match self.subversion() {
            0x2105 => "BCM20703A1",
            0x210b => "BCM43142A0",
            0x2112 => "BCM4314A0",
            0x2118 => "BCM20702A0",
            0x2126 => "BCM4335A0",
            0x220e => "BCM20702A1",
            0x230f => "BCM4356A2",
            0x4106 => "BCM4335B0",
            0x410e => "BCM20702B0",
            0x6109 => "BCM4335C0",
            0x610c => "BCM4354",
            0x6607 => "BCM4350C5",
            _ => return None,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub usb: UsbIdentity,
    pub version: LocalVersion,
    pub verbose: [u8; 7],
    pub features: [u8; 9],
    pub local_name: Vec<u8>,
    /// Fc5a response, may differ from descriptor identity; no substitution.
    pub product: [u8; 5],
}
impl Identity {
    pub fn revision_label(&self) -> String {
        let v = &self.version.raw;
        format!(
            "hci-{:02x}-{:04x}:lmp-{:02x}-{:04x}:manufacturer-000f:chip-{:02x}:product-{:04x}-{:04x}",
            v[1],
            self.version.revision(),
            v[4],
            self.version.subversion(),
            self.verbose[1],
            u16::from_le_bytes([self.product[1], self.product[2]]),
            u16::from_le_bytes([self.product[3], self.product[4]])
        )
    }
    pub fn target<'a>(&self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: "broadcom-bluetooth-usb-patchram",
            hardware,
            revision,
            board: None,
        }
    }
    pub fn firmware_names(&self) -> Vec<String> {
        let suffix = format!(
            "-{:04x}-{:04x}.hcd",
            u16::from_le_bytes([self.product[1], self.product[2]]),
            u16::from_le_bytes([self.product[3], self.product[4]])
        );
        let mut names = Vec::new();
        if let Some(name) = self.version.hardware_name() {
            names.push(format!("brcm/{name}{suffix}"));
        }
        names.push(format!("brcm/BCM{suffix}"));
        names
    }
}
