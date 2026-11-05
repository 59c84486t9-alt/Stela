// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! RSA/ECDSA/LMS section ordering adapted from pinned Linux btintel.c.
//! Signed sections are opaque here; authentication is performed by secure ROM.
use super::{Error, Result, identity::build_key};
use alloc::vec::Vec;

pub(super) const RSA_BYTES: usize = 644;
const CSS_BYTES: usize = 128;
const KEY_END: usize = 384;
const SIGNATURE_START: usize = 388;
const MAX_IMAGE: usize = 4 * 1024 * 1024;
const WRITE_BOOT_PARAMS: u16 = 0xfc0e;
const INTEL_VENDOR: u32 = 0x8086;
const RSA_DWORDS: u32 = 64;
const RSA_EXPONENT: [u8; 4] = [1, 0, 1, 0];
const HYBRID_VERSION: u32 = 0x0006_9700;
const HYBRID_ECDSA_KEY: usize = 128;
const HYBRID_ECDSA_SIGNATURE: usize = 224;
const HYBRID_LMS_KEY: usize = 320;
const HYBRID_LMS_SIGNATURE: usize = 372;
pub(super) const HYBRID_PAYLOAD: usize = 2116;

pub(super) struct Sfi<'a> {
    pub sections: Vec<(u8, &'a [u8])>,
    pub boot_address: u32,
    pub build: [u8; 3],
}
impl<'a> Sfi<'a> {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn parse(bytes: &'a [u8], minimum: [u8; 3]) -> Result<Self> {
        Self::parse_format(bytes, minimum, None)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn parse_tlv(
        bytes: &'a [u8],
        minimum: [u8; 3],
        engine: u8,
        hardware_variant: u8,
    ) -> Result<Self> {
        if bytes
            .get(8..12)
            .is_some_and(|version| version == HYBRID_VERSION.to_le_bytes())
        {
            if hardware_variant < 0x20 || engine > 3 {
                return Err(Error::Unsupported("hybrid SFI hardware/secure boot engine"));
            }
            if bytes.len() <= HYBRID_PAYLOAD || bytes.len() > MAX_IMAGE {
                return Err(Error::FirmwareFormat("hybrid SFI size"));
            }
            // The donor fixes these opaque CSS/key/signature byte ranges; it
            // sends both ECDSA and LMS sections even for an LMS-only engine.
            // Do not invent meanings for unobserved hybrid CSS fields. Secure
            // ROM, its result event and the resulting live image authenticate.
            let sections = vec![
                (0, &bytes[..HYBRID_ECDSA_KEY]),
                (3, &bytes[HYBRID_ECDSA_KEY..HYBRID_ECDSA_SIGNATURE]),
                (2, &bytes[HYBRID_ECDSA_SIGNATURE..HYBRID_LMS_KEY]),
                (5, &bytes[HYBRID_LMS_KEY..HYBRID_LMS_SIGNATURE]),
                (4, &bytes[HYBRID_LMS_SIGNATURE..HYBRID_PAYLOAD]),
            ];
            if sections.iter().skip(1).any(|(_, section)| empty(section)) {
                return Err(Error::FirmwareFormat("empty hybrid key/signature"));
            }
            return Self::parse_payload(bytes, minimum, sections, HYBRID_PAYLOAD);
        }
        Self::parse_format(bytes, minimum, Some(engine))
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn parse_format(bytes: &'a [u8], minimum: [u8; 3], engine: Option<u8>) -> Result<Self> {
        const ECDSA_BYTES: usize = 320;
        let payload = RSA_BYTES + if engine.is_some() { ECDSA_BYTES } else { 0 };
        if bytes.len() <= payload || bytes.len() > MAX_IMAGE {
            return Err(Error::FirmwareFormat("SFI size"));
        }
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let rsa_image = bytes.len() - if engine.is_some() { ECDSA_BYTES } else { 0 };
        if word(0) != 6
            || word(4) != RSA_BYTES as u32 / 4
            || word(8) != 0x0001_0000
            || word(16) != INTEL_VENDOR
            || u64::from(word(24)) * 4 != rsa_image as u64
            || word(28) != RSA_DWORDS
            || word(32) != RSA_DWORDS
            || word(36) != 1
            || bytes[KEY_END..SIGNATURE_START] != RSA_EXPONENT
        {
            return Err(Error::FirmwareFormat("RSA CSS layout/vendor/exponent"));
        }
        for region in [
            &bytes[CSS_BYTES..KEY_END],
            &bytes[SIGNATURE_START..RSA_BYTES],
        ] {
            if empty(region) {
                return Err(Error::FirmwareFormat("empty RSA key/signature"));
            }
        }
        if engine.is_some() {
            let at = RSA_BYTES;
            if word(at) != 6
                || word(at + 4) != ECDSA_BYTES as u32 / 4
                || word(at + 8) != 0x0002_0000
                || word(at + 16) != INTEL_VENDOR
                || u64::from(word(at + 24)) * 4 != (bytes.len() - RSA_BYTES) as u64
                || word(at + 28) != 24
                || word(at + 32) != 12
                || word(at + 36) != 12
            {
                return Err(Error::FirmwareFormat("ECDSA CSS layout/vendor/lengths"));
            }
            if empty(&bytes[at + 128..at + 224]) || empty(&bytes[at + 224..at + 320]) {
                return Err(Error::FirmwareFormat("empty ECDSA key/signature"));
            }
        }
        let sections = match engine {
            None | Some(0) => vec![
                (0, &bytes[..CSS_BYTES]),
                (3, &bytes[CSS_BYTES..KEY_END]),
                (2, &bytes[SIGNATURE_START..RSA_BYTES]),
            ],
            Some(1) => vec![
                (0, &bytes[RSA_BYTES..RSA_BYTES + 128]),
                (3, &bytes[RSA_BYTES + 128..RSA_BYTES + 224]),
                (2, &bytes[RSA_BYTES + 224..payload]),
            ],
            _ => return Err(Error::Unsupported("SFI secure boot engine")),
        };
        Self::parse_payload(bytes, minimum, sections, payload)
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn parse_payload(
        bytes: &'a [u8],
        minimum: [u8; 3],
        mut sections: Vec<(u8, &'a [u8])>,
        payload: usize,
    ) -> Result<Self> {
        let mut at = payload;
        let mut group = at;
        let mut boot = None;
        while at < bytes.len() {
            let header = bytes
                .get(at..at + 3)
                .ok_or(Error::FirmwareFormat("truncated SFI command header"))?;
            let opcode = u16::from_le_bytes([header[0], header[1]]);
            let end = at + 3 + usize::from(header[2]);
            let data = bytes
                .get(at + 3..end)
                .ok_or(Error::FirmwareFormat("truncated SFI command payload"))?;
            if opcode == WRITE_BOOT_PARAMS {
                if data.len() != 7 || boot.is_some() {
                    return Err(Error::FirmwareFormat(
                        "missing/duplicate/invalid boot parameters",
                    ));
                }
                boot = Some((
                    u32::from_le_bytes(data[..4].try_into().unwrap()),
                    [data[4], data[5], data[6]],
                ));
            }
            at = end;
            if (at - group).is_multiple_of(4) {
                sections.push((1, &bytes[group..at]));
                group = at;
            }
        }
        if group != bytes.len() {
            return Err(Error::FirmwareFormat("unaligned SFI command tail"));
        }
        let (boot_address, build) = boot.ok_or(Error::FirmwareFormat("missing boot parameters"))?;
        if build[1] == 0 || build[1] > 53 || build_key(build) < build_key(minimum) {
            return Err(Error::FirmwareFormat(
                "firmware below ROM minimum/invalid calendar week",
            ));
        }
        Ok(Self {
            sections,
            boot_address,
            build,
        })
    }
}
fn empty(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0) || bytes.iter().all(|b| *b == 0xff)
}

#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub(super) fn ddc(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(Error::FirmwareFormat("DDC size"));
    }
    let mut records = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let length = usize::from(bytes[at]) + 1;
        if !(3..=255).contains(&length) {
            return Err(Error::FirmwareFormat("DDC record length"));
        }
        let record = bytes
            .get(at..at + length)
            .ok_or(Error::FirmwareFormat("truncated DDC record"))?;
        records.push(record);
        at += length;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hybrid_image_parses_only_for_known_hardware_and_engine() {
        let valid = super::super::tests::hybrid_image();
        for variant in [0x20, 0x21, 0x22] {
            for engine in 0..=3 {
                let image = Sfi::parse_tlv(&valid, [1, 1, 25], engine, variant).unwrap();
                assert_eq!(image.boot_address, 0x0020_0000);
                assert_eq!(image.build, [9, 30, 26]);
                assert_eq!(
                    image
                        .sections
                        .iter()
                        .map(|(kind, bytes)| (*kind, bytes.len()))
                        .collect::<Vec<_>>(),
                    [(0, 128), (3, 96), (2, 96), (5, 52), (4, 1744), (1, 16)]
                );
            }
        }
        for end in 0..valid.len() {
            assert!(Sfi::parse_tlv(&valid[..end], [0; 3], 3, 0x20).is_err());
        }
        for (start, end) in [(128, 224), (224, 320), (320, 372), (372, 2116)] {
            for fill in [0, 0xff] {
                let mut invalid = valid.clone();
                invalid[start..end].fill(fill);
                assert!(Sfi::parse_tlv(&invalid, [0; 3], 3, 0x20).is_err());
            }
        }
        assert!(Sfi::parse_tlv(&valid, [0; 3], 3, 0x1f).is_err());
        assert!(Sfi::parse_tlv(&valid, [0; 3], 4, 0x20).is_err());
        assert!(Sfi::parse_tlv(&valid, [10, 30, 26], 3, 0x20).is_err());
        let mut invalid = valid.clone();
        invalid[8] ^= 1;
        assert!(Sfi::parse_tlv(&invalid, [0; 3], 3, 0x20).is_err());
        let mut duplicate_boot = valid.clone();
        duplicate_boot.extend_from_slice(&valid[2116..]);
        assert!(Sfi::parse_tlv(&duplicate_boot, [0; 3], 3, 0x20).is_err());
    }
    #[test]
    fn css_size_fields_exponent_and_complete_command_stream_are_required() {
        let valid = super::super::tests::image();
        for at in [0, 4, 8, 16, 24, 28, 32, 36, 384, 385, 386, 387] {
            let mut bad = valid.clone();
            bad[at] ^= 1;
            assert!(Sfi::parse(&bad, [0; 3]).is_err(), "CSS field {at}");
        }
        let mut no_boot = valid.clone();
        no_boot[644] = 0;
        assert!(Sfi::parse(&no_boot, [0; 3]).is_err());
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&valid[644..]);
        let dwords = (duplicate.len() / 4) as u32;
        duplicate[24..28].copy_from_slice(&dwords.to_le_bytes());
        assert!(Sfi::parse(&duplicate, [0; 3]).is_err());
        assert!(Sfi::parse(&valid, [10, 30, 26]).is_err());
        assert!(Sfi::parse(&valid, [9, 31, 26]).is_err());
        assert!(Sfi::parse(&valid, [9, 30, 27]).is_err());
        assert!(Sfi::parse(&valid, [9, 30, 26]).is_ok());
        for length in 2..=254u8 {
            let mut record = vec![0; usize::from(length) + 1];
            record[0] = length;
            assert_eq!(ddc(&record).unwrap(), vec![record.as_slice()]);
            record.pop();
            assert!(ddc(&record).is_err());
        }
    }
}
