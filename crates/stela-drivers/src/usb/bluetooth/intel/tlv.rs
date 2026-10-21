// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! TLV identity and CNVI/CNVR naming adapted from pinned btintel.c/btintel.h.
use super::{
    Error, Result,
    identity::{Identity, valid_address},
};
use crate::{firmware::Target, usb::xhci::Device};
use alloc::{format, string::String, vec::Vec};
use core::fmt::Write;
use sha2::{Digest, Sha256};

const CNVI_TOP: u8 = 0x10;
const CNVR_TOP: u8 = 0x11;
const CNVI_BT: u8 = 0x12;
const CNVR_BT: u8 = 0x13;
const DEVICE_REV: u8 = 0x16;
const IMAGE_TYPE: u8 = 0x1c;
const TIMESTAMP: u8 = 0x1d;
const BUILD: u8 = 0x1f;
const SECURE_BOOT: u8 = 0x28;
const MINIMUM: u8 = 0x2d;
const LIMITED_CCE: u8 = 0x2e;
const SBE: u8 = 0x2f;
const OTP_ADDRESS: u8 = 0x30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlvIdentity {
    pub usb_vendor: u16,
    pub usb_product: u16,
    pub usb_revision: u16,
    pub cnvi_top: u32,
    pub cnvr_top: u32,
    pub cnvi_bt: u32,
    pub cnvr_bt: u32,
    pub device_revision: u16,
    /// 1 is secure bootloader, 3 is an operational image; IML is unsupported.
    pub image_type: u8,
    pub build: Option<[u8; 3]>,
    pub build_number: Option<u32>,
    pub secure_boot: Option<u8>,
    pub minimum_build: Option<[u8; 3]>,
    pub secure_engine: Option<u8>,
    pub address: Option<[u8; 6]>,
    fields: Vec<(u8, Vec<u8>)>,
}
impl TlvIdentity {
    // Legacy operational firmware may answer the FF query with TLVs but its
    // upload filename requires a fresh legacy-format read, not lossy conversion.
    pub(super) fn legacy_fallback(p: &[u8]) -> Result<Option<u8>> {
        if p.first() != Some(&0) {
            return Err(Error::Protocol("TLV version status"));
        }
        let mut seen = Vec::new();
        let mut cnvi = None;
        let mut at = 1;
        while at < p.len() {
            let h = p
                .get(at..at + 2)
                .ok_or(Error::Protocol("truncated Intel TLV header"))?;
            let value = p
                .get(at + 2..at + 2 + usize::from(h[1]))
                .ok_or(Error::Protocol("truncated Intel TLV value"))?;
            if seen.contains(&h[0]) {
                return Err(Error::Protocol("duplicate Intel version TLV"));
            }
            seen.push(h[0]);
            if h[0] == CNVI_BT {
                let raw: [u8; 4] = value
                    .try_into()
                    .map_err(|_| Error::Protocol("CNVI identity length"))?;
                cnvi = Some(u32::from_le_bytes(raw));
            }
            at += 2 + value.len();
        }
        let cnvi = cnvi.ok_or(Error::Protocol("missing CNVI identity"))?;
        if (cnvi >> 8) & 0xff != 0x37 {
            return Err(Error::Unsupported("Intel TLV platform"));
        }
        let variant = ((cnvi >> 16) & 0x3f) as u8;
        Ok(matches!(variant, 0x11..=0x14).then_some(variant))
    }
    pub(super) fn parse(device: &Device, p: &[u8]) -> Result<Self> {
        let (usb_vendor, usb_product, usb_revision) = Identity::usb(device)?;
        if p.first() != Some(&0) {
            return Err(Error::Protocol("TLV version status"));
        }
        let mut fields: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut at = 1;
        while at < p.len() {
            let hdr = p
                .get(at..at + 2)
                .ok_or(Error::Protocol("truncated Intel TLV header"))?;
            let n = usize::from(hdr[1]);
            let value = p
                .get(at + 2..at + 2 + n)
                .ok_or(Error::Protocol("truncated Intel TLV value"))?;
            if fields.iter().any(|(kind, _)| *kind == hdr[0]) {
                return Err(Error::Protocol("duplicate Intel version TLV"));
            }
            let expected = match hdr[0] {
                CNVI_TOP | CNVR_TOP | CNVI_BT | CNVR_BT | BUILD | 0x32 => Some(4),
                DEVICE_REV | TIMESTAMP | 0x17 | 0x18 => Some(2),
                IMAGE_TYPE | 0x1e | SECURE_BOOT | 0x29..=0x2c | LIMITED_CCE | SBE | 0x31 => Some(1),
                MINIMUM => Some(3),
                OTP_ADDRESS => Some(6),
                _ => None,
            };
            if expected.is_some_and(|e| e != n) {
                return Err(Error::Protocol("Intel TLV field length"));
            }
            fields.push((hdr[0], value.to_vec()));
            at += 2 + n;
        }
        fields.sort_by_key(|(kind, _)| *kind);
        let get = |kind| {
            fields
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, v)| v.as_slice())
        };
        let req = |kind| get(kind).ok_or(Error::Protocol("missing required Intel identity TLV"));
        let u32field =
            |kind| -> Result<u32> { Ok(u32::from_le_bytes(req(kind)?.try_into().unwrap())) };
        let cnvi_top = u32field(CNVI_TOP)?;
        let cnvr_top = u32field(CNVR_TOP)?;
        let cnvi_bt = u32field(CNVI_BT)?;
        let cnvr_bt = u32field(CNVR_BT)?;
        if (cnvi_bt >> 8) & 0xff != 0x37 {
            return Err(Error::Unsupported("Intel TLV platform"));
        }
        let variant = ((cnvi_bt >> 16) & 0x3f) as u8;
        // 0x11–14 are parsed only to trigger the legacy-version fallback.
        if !matches!(variant,0x11..=0x14|0x17..=0x19|0x1b..=0x1d) {
            return Err(Error::Unsupported(
                "Intel TLV hardware; IML/hybrid is separate",
            ));
        }
        let image_type = req(IMAGE_TYPE)?[0];
        if !matches!(image_type, 1 | 3) {
            return Err(Error::Unsupported("Intel intermediate/unknown image type"));
        }
        let build_number = get(BUILD).map(|v| u32::from_le_bytes(v.try_into().unwrap()));
        let build = match (build_number, get(TIMESTAMP)) {
            (Some(number), Some(time)) => Some([number as u8, time[0], time[1]]),
            _ => None,
        };
        let secure_boot = get(SECURE_BOOT).map(|v| v[0]);
        let secure_engine = get(SBE).map(|v| v[0]);
        let minimum_build = get(MINIMUM).map(|v| v.try_into().unwrap());
        let address = get(OTP_ADDRESS).map(|v| v.try_into().unwrap());
        if image_type == 1 && variant >= 0x17 {
            if secure_boot != Some(1)
                || get(LIMITED_CCE) != Some(&[0][..])
                || !matches!(secure_engine, Some(0 | 1))
                || minimum_build.is_none()
                || address.is_none()
            {
                return Err(Error::Unsupported(
                    "TLV secure boot/individual completions/RSA-ECDSA parameters required",
                ));
            }
            for field in [0x2a, 0x2b, 0x2c] {
                req(field)?;
            }
            valid_address(address.unwrap())?;
        }
        if image_type == 3 && build.is_none() {
            return Err(Error::Protocol("operational TLV build/timestamp missing"));
        }
        for (kind, observed) in [(0x17, usb_vendor), (0x18, usb_product)] {
            if get(kind)
                .is_some_and(|value| u16::from_le_bytes(value.try_into().unwrap()) != observed)
            {
                return Err(Error::Protocol("TLV USB ID differs from descriptor"));
            }
        }
        let device_revision = u16::from_le_bytes(req(DEVICE_REV)?.try_into().unwrap());
        Ok(Self {
            usb_vendor,
            usb_product,
            usb_revision,
            cnvi_top,
            cnvr_top,
            cnvi_bt,
            cnvr_bt,
            device_revision,
            image_type,
            build,
            build_number,
            secure_boot,
            minimum_build,
            secure_engine,
            address,
            fields,
        })
    }
    pub fn hardware_variant(&self) -> u8 {
        ((self.cnvi_bt >> 16) & 0x3f) as u8
    }
    pub fn hardware_label(&self) -> String {
        format!(
            "usb:{:04x}:{:04x}:{:04x}",
            self.usb_vendor, self.usb_product, self.usb_revision
        )
    }
    /// Canonical sorted, complete TLV identity. Unknown fields are retained,
    /// duplicates rejected and the versioned schema never masks future bits.
    pub fn canonical_tlvs(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (kind, value) in &self.fields {
            bytes.extend_from_slice(&[*kind, value.len() as u8]);
            bytes.extend_from_slice(value);
        }
        bytes
    }
    pub fn revision_label(&self) -> String {
        let digest = Sha256::digest(self.canonical_tlvs());
        let mut label = String::from("tlv-v1:sha256:");
        for byte in digest {
            write!(&mut label, "{byte:02x}").unwrap();
        }
        label
    }
    pub fn filename(&self, suffix: &str) -> String {
        let pack = |v: u32| ((((v & 0xfff) << 4) | ((v >> 24) & 0xf)) as u16).swap_bytes();
        format!(
            "intel/ibt-{:04x}-{:04x}.{suffix}",
            pack(self.cnvi_top),
            pack(self.cnvr_top)
        )
    }
    pub fn target<'a>(&self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: "intel-bluetooth-usb-tlv",
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
            self.cnvi_top,
            self.cnvr_top,
            self.cnvi_bt,
            self.cnvr_bt,
            self.device_revision,
        ) == (
            other.usb_vendor,
            other.usb_product,
            other.usb_revision,
            other.cnvi_top,
            other.cnvr_top,
            other.cnvi_bt,
            other.cnvr_bt,
            other.device_revision,
        )
    }
}
