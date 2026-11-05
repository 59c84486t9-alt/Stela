// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Legacy identity/naming adapted from pinned Linux btintel.c/btintel.h.
use super::{Error, Result};
use crate::{firmware::Target, usb::xhci::Device};
use alloc::{format, string::String};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub usb_vendor: u16,
    pub usb_product: u16,
    pub usb_revision: u16,
    pub hardware_variant: u8,
    pub hardware_revision: u8,
    pub firmware_variant: u8,
    pub firmware_revision: u8,
    pub firmware_patch: u8,
    /// Build number, calendar week and year since 2000.
    pub build: [u8; 3],
}
impl Identity {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub(crate) fn usb(device: &Device) -> Result<(u16, u16, u16)> {
        let d = &device.descriptor;
        let vendor = u16::from_le_bytes([d[8], d[9]]);
        let product = u16::from_le_bytes([d[10], d[11]]);
        // Exact pinned combined USB IDs; HCI identity and platform requirements
        // independently decide which initialization path is supported.
        if vendor != 0x8087
            || !matches!(
                product,
                0x0a2b
                    | 0x0aaa
                    | 0x0025
                    | 0x0026
                    | 0x0029
                    | 0x0032
                    | 0x0033
                    | 0x0035
                    | 0x0036
                    | 0x0037
                    | 0x0038
                    | 0x0039
                    | 0x0040
            )
        {
            return Err(Error::Unsupported("Intel combined USB identity"));
        }
        Ok((vendor, product, u16::from_le_bytes([d[12], d[13]])))
    }
    #[cfg(test)]
    #[expect(
        clippy::result_large_err,
        reason = "This test-only return keeps the shared typed source and cleanup causes without allocating on propagation."
    )]
    pub(super) fn parse(device: &Device, p: &[u8]) -> Result<Self> {
        let (usb_vendor, usb_product, usb_revision) = Self::usb(device)?;
        Self::parse_usb((usb_vendor, usb_product, usb_revision), p)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub(super) fn parse_usb(
        (usb_vendor, usb_product, usb_revision): (u16, u16, u16),
        p: &[u8],
    ) -> Result<Self> {
        if p.len() != 10 || p[0] != 0 || p[1] != 0x37 {
            return Err(Error::Unsupported("legacy Intel version required"));
        }
        if !matches!(p[2], 0x0b | 0x0c | 0x11..=0x14) || !matches!(p[4], 0x06 | 0x23) {
            return Err(Error::Unsupported("Intel hardware/firmware variant"));
        }
        Ok(Self {
            usb_vendor,
            usb_product,
            usb_revision,
            hardware_variant: p[2],
            hardware_revision: p[3],
            firmware_variant: p[4],
            firmware_revision: p[5],
            firmware_patch: p[9],
            build: [p[6], p[7], p[8]],
        })
    }
    pub fn hardware_label(&self) -> String {
        format!(
            "usb:{:04x}:{:04x}:{:04x}",
            self.usb_vendor, self.usb_product, self.usb_revision
        )
    }
    pub fn revision_label(&self, boot: &BootParameters) -> String {
        format!(
            "37:{:02x}:{:02x}:{:02x}:dev-{:04x}:otp-{:02x}-{:02x}-{:02x}:key-{:02x}-{:02x}:locks-{:02x}-{:02x}-{:02x}:min-{:02x}-{:02x}-{:02x}:loader-{:02x}-{:02x}-{:02x}-{:02x}:unlock-{:02x}",
            self.hardware_variant,
            self.hardware_revision,
            self.firmware_revision,
            boot.device_revision,
            boot.raw[1],
            boot.raw[2],
            boot.raw[3],
            boot.raw[7],
            boot.raw[8],
            boot.raw[9],
            boot.raw[10],
            boot.raw[11],
            boot.raw[18],
            boot.raw[19],
            boot.raw[20],
            self.build[0],
            self.build[1],
            self.build[2],
            self.firmware_patch,
            boot.raw[22]
        )
    }
    pub fn filename(&self, boot: &BootParameters, suffix: &str) -> String {
        if matches!(self.hardware_variant, 0x0b | 0x0c) {
            format!(
                "intel/ibt-{}-{}.{}",
                self.hardware_variant, boot.device_revision, suffix
            )
        } else {
            format!(
                "intel/ibt-{}-{}-{}.{}",
                self.hardware_variant, self.hardware_revision, self.firmware_revision, suffix
            )
        }
    }
    pub fn target<'a>(&self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: "intel-bluetooth-usb-rsa",
            hardware,
            revision,
            board: None,
        }
    }
    pub(super) fn same_hardware(&self, other: &Self) -> bool {
        (
            self.usb_vendor,
            self.usb_product,
            self.usb_revision,
            self.hardware_variant,
            self.hardware_revision,
        ) == (
            other.usb_vendor,
            other.usb_product,
            other.usb_revision,
            other.hardware_variant,
            other.hardware_revision,
        )
    }
}

#[derive(Clone, Debug)]
pub struct BootParameters {
    pub device_revision: u16,
    pub minimum_build: [u8; 3],
    pub address: [u8; 6],
    raw: [u8; 23],
}
impl BootParameters {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub(super) fn parse(p: &[u8]) -> Result<Self> {
        let raw: [u8; 23] = p
            .try_into()
            .map_err(|_| Error::Protocol("Intel boot parameter length"))?;
        if raw[0] != 0 || raw[6] != 1 || raw[21] != 0 {
            return Err(Error::Unsupported(
                "secure boot and per-fragment command completions required",
            ));
        }
        let address: [u8; 6] = raw[12..18].try_into().unwrap();
        valid_address(address)?;
        Ok(Self {
            device_revision: u16::from_le_bytes([raw[4], raw[5]]),
            minimum_build: [raw[18], raw[19], raw[20]],
            address,
            raw,
        })
    }
}
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub(super) fn valid_address(address: [u8; 6]) -> Result<()> {
    if address == [0; 6] || address == [0xff; 6] || address == [0, 0x8b, 0x9e, 0x19, 0x03, 0] {
        return Err(Error::Protocol("invalid/default Intel Bluetooth address"));
    }
    Ok(())
}
pub(super) fn build_key(build: [u8; 3]) -> (u8, u8, u8) {
    (build[2], build[1], build[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn firmware_selection_keeps_exact_usb_silicon_and_boot_loader_identity() {
        let (device, _, _) = super::super::tests::fixture();
        let mut version = [0, 0x37, 0x14, 1, 6, 3, 1, 30, 26, 0];
        let identity = Identity::parse(&device, &version).unwrap();
        let mut bytes = [0; 23];
        bytes[4] = 5;
        bytes[6] = 1;
        bytes[12..18].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        let boot = BootParameters::parse(&bytes).unwrap();
        assert_eq!(identity.filename(&boot, "sfi"), "intel/ibt-20-1-3.sfi");
        for variant in [0x0b, 0x0c] {
            version[2] = variant;
            let id = Identity::parse(&device, &version).unwrap();
            assert_eq!(
                id.filename(&boot, "ddc"),
                format!("intel/ibt-{variant}-5.ddc")
            );
        }
        let original = identity.revision_label(&boot);
        for at in [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 18, 19, 20, 22] {
            let mut changed = bytes;
            changed[at] ^= 1;
            assert_ne!(
                identity.revision_label(&BootParameters::parse(&changed).unwrap()),
                original,
                "boot field {at}"
            );
        }
        for at in [0, 6, 21] {
            let mut changed = bytes;
            changed[at] ^= 1;
            assert!(BootParameters::parse(&changed).is_err());
        }
        version[2] = 0x17;
        assert!(Identity::parse(&device, &version).is_err());
        let mut unknown = device;
        unknown.descriptor[10] = 0xff;
        assert!(Identity::usb(&unknown).is_err());
    }
}
