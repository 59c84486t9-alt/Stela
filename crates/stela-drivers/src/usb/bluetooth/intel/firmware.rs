// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! RSA section/fragment ordering adapted from pinned Linux btintel.c.
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

pub(super) struct Sfi<'a> {
    pub sections: Vec<(u8, &'a [u8])>,
    pub boot_address: u32,
    pub build: [u8; 3],
}
impl<'a> Sfi<'a> {
    pub fn parse(bytes: &'a [u8], minimum: [u8; 3]) -> Result<Self> {
        if bytes.len() <= RSA_BYTES || bytes.len() > MAX_IMAGE {
            return Err(Error::FirmwareFormat("RSA SFI size"));
        }
        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != 6
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 0x0001_0000
        {
            return Err(Error::FirmwareFormat("RSA CSS type/version"));
        }
        // Strict full-length RSA CSS subset: all component lengths and the
        // complete-image length must match, rather than trusting fixed offsets
        // after a superficially valid version. Truncated CSS variants, ECDSA
        // and alternate exponents are explicit unsupported image formats.
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        if word(4) != RSA_BYTES as u32 / 4
            || word(16) != INTEL_VENDOR
            || word(24) as usize * 4 != bytes.len()
            || word(28) != RSA_DWORDS
            || word(32) != RSA_DWORDS
            || word(36) != 1
            || bytes[KEY_END..SIGNATURE_START] != RSA_EXPONENT
        {
            return Err(Error::FirmwareFormat(
                "RSA CSS component/image lengths, vendor or exponent",
            ));
        }
        // Bounds and nonempty signature/key material are host checks, not an
        // authentication proof. The secure ROM validates their actual contents.
        for section in [
            &bytes[CSS_BYTES..KEY_END],
            &bytes[KEY_END..SIGNATURE_START],
            &bytes[SIGNATURE_START..RSA_BYTES],
        ] {
            if section.iter().all(|byte| *byte == 0) || section.iter().all(|byte| *byte == 0xff) {
                return Err(Error::FirmwareFormat("empty RSA key/exponent/signature"));
            }
        }
        let mut sections = vec![
            (0, &bytes[..CSS_BYTES]),
            (3, &bytes[CSS_BYTES..KEY_END]),
            (2, &bytes[SIGNATURE_START..RSA_BYTES]),
        ];
        let mut at = RSA_BYTES;
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
