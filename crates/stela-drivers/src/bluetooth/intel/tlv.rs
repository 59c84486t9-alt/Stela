// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! TLV identity and CNVI/CNVR naming adapted from pinned btintel.c/btintel.h.
use super::{Error, Result, TransportIdentity, identity::valid_address};
use crate::firmware::Target;
#[cfg(test)]
use crate::usb::xhci::Device;
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
    pub transport: TransportIdentity,
    pub cnvi_top: u32,
    pub cnvr_top: u32,
    pub cnvi_bt: u32,
    pub cnvr_bt: u32,
    pub device_revision: u16,
    /// 1 is secure bootloader, 2 is IML, 3 is operational firmware.
    pub image_type: u8,
    pub build: Option<[u8; 3]>,
    pub build_number: Option<u32>,
    pub secure_boot: Option<u8>,
    pub minimum_build: Option<[u8; 3]>,
    pub secure_engine: Option<u8>,
    pub address: Option<[u8; 6]>,
    pub firmware_id: Option<String>,
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
    #[cfg(test)]
    pub(super) fn parse(device: &Device, p: &[u8]) -> Result<Self> {
        Self::parse_transport(TransportIdentity::Usb(super::Identity::usb(device)?), p)
    }
    pub(crate) fn parse_transport(transport: TransportIdentity, p: &[u8]) -> Result<Self> {
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
        let supported = match transport {
            TransportIdentity::Usb(_) => {
                matches!(variant,0x11..=0x14|0x17..=0x19|0x1b..=0x22)
            }
            TransportIdentity::Pcie(_) => matches!(variant, 0x1e..=0x22),
        };
        if !supported {
            return Err(Error::Unsupported("Intel TLV hardware unsupported"));
        }
        let image_type = req(IMAGE_TYPE)?[0];
        if !matches!(image_type, 1 | 3) && !(image_type == 2 && variant >= 0x1e) {
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
                || !secure_engine.is_some_and(|engine| supported_engine(variant, engine))
                || minimum_build.is_none()
                || address.is_none()
            {
                return Err(Error::Unsupported(
                    "TLV secure boot/individual completions/engine parameters required",
                ));
            }
            for field in [0x2a, 0x2b, 0x2c] {
                req(field)?;
            }
            valid_address(address.unwrap())?;
        }
        if matches!(image_type, 2 | 3) && build.is_none() {
            return Err(Error::Protocol("operational TLV build/timestamp missing"));
        }
        for (kind, observed) in transport
            .usb_ids()
            .into_iter()
            .flat_map(|(vendor, product)| [(0x17, vendor), (0x18, product)])
        {
            if get(kind)
                .is_some_and(|value| u16::from_le_bytes(value.try_into().unwrap()) != observed)
            {
                return Err(Error::Protocol("TLV USB ID differs from descriptor"));
            }
        }
        let firmware_id = if variant >= 0x1e && image_type != 1 {
            match get(0x50) {
                Some(raw) => {
                    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                    if end >= 64
                        || raw[end..].iter().any(|b| *b != 0)
                        || !raw[..end]
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_'))
                    {
                        return Err(Error::Unsupported("unsafe/oversized Intel FW_ID"));
                    }
                    if end == 0 {
                        None
                    } else {
                        Some(core::str::from_utf8(&raw[..end]).unwrap().into())
                    }
                }
                None => None,
            }
        } else {
            None
        };
        let device_revision = u16::from_le_bytes(req(DEVICE_REV)?.try_into().unwrap());
        Ok(Self {
            transport,
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
            firmware_id,
            fields,
        })
    }
    pub fn hardware_variant(&self) -> u8 {
        ((self.cnvi_bt >> 16) & 0x3f) as u8
    }
    pub fn hardware_label(&self) -> String {
        self.transport.hardware_label()
    }
    /// Canonical sorted, complete TLV identity. Unknown fields are held,
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
        let base = format!(
            "intel/ibt-{:04x}-{:04x}",
            pack(self.cnvi_top),
            pack(self.cnvr_top)
        );
        if self.hardware_variant() >= 0x1e {
            if self.image_type == 1 {
                return format!("{base}-iml.{suffix}");
            }
            if let Some(id) = &self.firmware_id {
                return format!("{base}-{id}.{suffix}");
            }
        }
        format!("{base}.{suffix}")
    }
    /// Source-linked IML selector: exact domain, then u32 LE length + complete
    /// sorted TLVs for initial boot and current IML respectively. This binds
    /// inherited observed security data without rewriting the current response.
    pub fn iml_revision_label(&self, initial: &Self) -> String {
        let mut hash = Sha256::new();
        hash.update(match self.transport {
            TransportIdentity::Usb(_) => &b"stela.intel-usb.iml-target\0v1\0"[..],
            TransportIdentity::Pcie(_) => &b"stela.intel-pcie.iml-target\0v1\0"[..],
        });
        for bytes in [initial.canonical_tlvs(), self.canonical_tlvs()] {
            hash.update((bytes.len() as u32).to_le_bytes());
            hash.update(bytes);
        }
        let mut label = String::from("tlv-iml-v1:sha256:");
        for byte in hash.finalize() {
            write!(&mut label, "{byte:02x}").unwrap();
        }
        label
    }
    pub(super) fn validate_security(&self, prior: &Self) -> Result<()> {
        for kind in [
            SECURE_BOOT,
            LIMITED_CCE,
            SBE,
            MINIMUM,
            OTP_ADDRESS,
            0x2a,
            0x2b,
            0x2c,
        ] {
            if let (Some(a), Some(b)) = (self.field(kind), prior.field(kind))
                && a != b
            {
                return Err(Error::Protocol(
                    "contradictory Intel stage security observations",
                ));
            }
        }
        Ok(())
    }
    fn field(&self, id: u8) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(kind, _)| *kind == id)
            .map(|(_, value)| value.as_slice())
    }
    pub(super) fn boot_requirements<'a>(
        &'a self,
        initial: Option<&'a Self>,
    ) -> Result<BootRequirements> {
        if let Some(old) = initial
            && !self.same_hardware(old)
        {
            return Err(Error::Protocol("inherited Intel hardware identity changed"));
        }
        let mut inherited = Vec::new();
        let mut required = |kind, name| -> Result<&[u8]> {
            let current = self.field(kind);
            let prior = initial.and_then(|i| i.field(kind));
            if let (Some(a), Some(b)) = (current, prior)
                && a != b
            {
                return Err(Error::Protocol(
                    "contradictory Intel stage security observations",
                ));
            }
            if current.is_none() && prior.is_some() {
                inherited.push(name);
            }
            current.or(prior).ok_or(Error::Unsupported(
                "fresh IML missing observed security/OTP/minimum parameters",
            ))
        };
        if required(SECURE_BOOT, InheritedField::SecureBoot)? != [1]
            || required(LIMITED_CCE, InheritedField::IndividualCompletions)? != [0]
        {
            return Err(Error::Unsupported(
                "IML secure boot/individual completions required",
            ));
        }
        let engine = required(SBE, InheritedField::SecureEngine)?[0];
        if !supported_engine(self.hardware_variant(), engine) {
            return Err(Error::Unsupported("IML secure engine unsupported"));
        }
        let minimum = required(MINIMUM, InheritedField::MinimumBuild)?
            .try_into()
            .unwrap();
        let address = required(OTP_ADDRESS, InheritedField::OtpAddress)?
            .try_into()
            .unwrap();
        valid_address(address)?;
        for (kind, name) in [
            (0x2a, InheritedField::OtpLock),
            (0x2b, InheritedField::ApiLock),
            (0x2c, InheritedField::DebugLock),
        ] {
            required(kind, name)?;
        }
        Ok(BootRequirements {
            engine,
            minimum,
            address,
            inherited,
        })
    }
    pub fn target<'a>(&self, hardware: &'a str, revision: &'a str) -> Target<'a> {
        Target {
            driver: match self.transport {
                TransportIdentity::Usb(_) => "intel-bluetooth-usb-tlv",
                TransportIdentity::Pcie(_) => "intel-bluetooth-pcie-tlv",
            },
            hardware,
            revision,
            board: None,
        }
    }
    pub(super) fn same_hardware(&self, other: &Self) -> bool {
        (
            self.transport,
            self.cnvi_top,
            self.cnvr_top,
            self.cnvi_bt,
            self.cnvr_bt,
            self.device_revision,
        ) == (
            other.transport,
            other.cnvi_top,
            other.cnvr_top,
            other.cnvi_bt,
            other.cnvr_bt,
            other.device_revision,
        )
    }
}

fn supported_engine(variant: u8, engine: u8) -> bool {
    engine <= 1 || (variant >= 0x20 && engine <= 3)
}

/// Named fields reused only from prior observations after verified IML boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InheritedField {
    SecureBoot,
    IndividualCompletions,
    SecureEngine,
    MinimumBuild,
    OtpAddress,
    OtpLock,
    ApiLock,
    DebugLock,
}
pub(super) struct BootRequirements {
    pub engine: u8,
    pub minimum: [u8; 3],
    pub address: [u8; 6],
    pub inherited: Vec<InheritedField>,
}
