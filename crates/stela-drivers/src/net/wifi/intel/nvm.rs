// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Unified-init command bytes and exact NVM_GET_INFO response decoding.
//! Raw OTP/channel properties grant no regulatory or RF permission.
use super::{command::Id, firmware::Firmware};
use alloc::vec::Vec;

/// These three source call sites deliberately use WIDE_ID without version
/// bits. The documented payload ABI version is not a header-version override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    ExtendedConfiguration,
    AccessComplete,
    GetInformation,
}
impl Request {
    pub const fn id(self) -> Id {
        let (group, opcode) = match self {
            Self::ExtendedConfiguration => (2, 3),
            Self::AccessComplete => (12, 0),
            Self::GetInformation => (12, 2),
        };
        Id {
            group,
            opcode,
            version: 0,
        }
    }
    pub const fn payload(self) -> [u8; 4] {
        match self {
            // IWL_INIT_NVM is enum index1; admitted standalone profiles do
            // not request source tx_with_siso_diversity PHY initialization.
            Self::ExtendedConfiguration => 2u32.to_le_bytes(),
            Self::AccessComplete | Self::GetInformation => [0; 4],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MissingApi,
    UnsupportedVersion(u8),
    InconsistentApi,
    Length { expected: usize, actual: usize },
    ChannelCount(u32),
    HardwareAddress,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Information {
    pub response_version: u8,
    pub general_flags: u32,
    pub nvm_version: u16,
    pub board_type: u8,
    pub hardware_addresses: u8,
    pub mac_sku_flags: u32,
    pub tx_chains: u32,
    pub rx_chains: u32,
    pub lar_enabled: u32,
    /// Firmware's declared valid prefix. Remaining exact array words remain
    /// retained in channel_profiles and raw, without becoming valid channels.
    pub channel_count: usize,
    pub channel_profiles: Vec<u32>,
    pub raw: Vec<u8>,
}
impl Information {
    /// Select the exact declared notification ABI. Unknown or missing versions
    /// are explicit unsupported requirements rather than a v3 default.
    pub fn decode(firmware: &Firmware<'_>, bytes: &[u8]) -> Result<Self, Error> {
        let version = firmware
            .command_version(12, 2)
            .ok_or(Error::MissingApi)?
            .notification_version;
        let (capacity, width, offset) = match version {
            3 => (51, 2, 24),
            4 => (110, 4, 28),
            5 => (115, 4, 28),
            n => return Err(Error::UnsupportedVersion(n)),
        };
        // The donor separately switches array stride using API48. Refuse
        // contradictory input rather than reading one declared ABI as another.
        if firmware.supports_api(48) != (version >= 4) {
            return Err(Error::InconsistentApi);
        }
        let expected = if version == 3 {
            128
        } else {
            offset + capacity * width
        };
        if bytes.len() != expected {
            return Err(Error::Length {
                expected,
                actual: bytes.len(),
            });
        }
        let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let count = if version == 3 { 51 } else { word(24) as usize };
        if count > capacity {
            return Err(Error::ChannelCount(word(24)));
        }
        let profiles = (0..capacity)
            .map(|i| {
                let at = offset + i * width;
                if width == 2 {
                    u32::from(u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()))
                } else {
                    word(at)
                }
            })
            .collect();
        Ok(Self {
            response_version: version,
            general_flags: word(0),
            nvm_version: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            board_type: bytes[6],
            hardware_addresses: bytes[7],
            mac_sku_flags: word(8),
            tx_chains: word(12),
            rx_chains: word(16),
            lar_enabled: word(20),
            channel_count: count,
            channel_profiles: profiles,
            raw: bytes.to_vec(),
        })
    }
    pub fn empty_otp(&self) -> bool {
        self.general_flags & 1 != 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSource {
    Strap,
    Otp,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareAddress {
    pub bytes: [u8; 6],
    pub source: AddressSource,
}
impl HardwareAddress {
    /// Pure source byte permutation, not an observation of actual CSR state.
    pub fn decode(word0: u32, word1: u32) -> [u8; 6] {
        let first = word0.to_le_bytes();
        let second = word1.to_le_bytes();
        [first[3], first[2], first[1], first[0], second[1], second[0]]
    }
    pub fn valid(bytes: [u8; 6]) -> bool {
        bytes[0] & 1 == 0 && bytes != [0; 6]
    }
    /// An actual consumer reads strap registers first and requests OTP words
    /// only on invalid strap. Missing required OTP words are not fabricated.
    pub fn select(strap: [u32; 2], otp: Option<[u32; 2]>) -> Result<Self, Error> {
        let bytes = Self::decode(strap[0], strap[1]);
        if Self::valid(bytes) {
            return Ok(Self {
                bytes,
                source: AddressSource::Strap,
            });
        }
        let otp = otp.ok_or(Error::HardwareAddress)?;
        let bytes = Self::decode(otp[0], otp[1]);
        if !Self::valid(bytes) {
            return Err(Error::HardwareAddress);
        }
        Ok(Self {
            bytes,
            source: AddressSource::Otp,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::net::wifi::intel::firmware::Family;
    fn image(version: u8, api48: bool) -> Vec<u8> {
        let mut b = alloc::vec![0;88];
        b[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
        b[72..76].copy_from_slice(&(77u32 << 8).to_le_bytes());
        let mut tlv = |kind: u32, data: &[u8]| {
            b.extend(kind.to_le_bytes());
            b.extend((data.len() as u32).to_le_bytes());
            b.extend(data);
            b.resize(b.len().next_multiple_of(4), 0);
        };
        tlv(48, &[2, 12, 1, version]);
        if api48 {
            tlv(29, &[1, 0, 0, 0, 0, 0, 1, 0]);
        }
        b
    }
    fn fixture(version: u8) -> Vec<u8> {
        let count = match version {
            3 => 51,
            4 => 110,
            _ => 115,
        };
        let mut b = alloc::vec![0;if version==3{128}else{28+count*4}];
        b[..24].copy_from_slice(&[
            1, 0, 0, 0, 0x34, 0x12, 0xa5, 4, 0x3f, 0x80, 0x44, 0x99, 3, 0, 0, 0, 2, 0, 0, 0, 1, 0,
            0, 0,
        ]);
        let width = if version == 3 { 2 } else { 4 };
        let offset = if version == 3 { 24 } else { 28 };
        if version != 3 {
            b[24..28].copy_from_slice(&(count as u32).to_le_bytes());
        }
        for n in 0..count {
            let v = (n as u32 * 0x101 + 0x4321).to_le_bytes();
            b[offset + n * width..offset + (n + 1) * width].copy_from_slice(&v[..width]);
        }
        b
    }
    #[test]
    fn exact_versions_retain_every_channel_word_and_refuse_truncation_or_inconsistent_abi() {
        for version in 3..=5 {
            let input = image(version, version >= 4);
            let fw = Firmware::parse(&input).unwrap();
            let bytes = fixture(version);
            let info = Information::decode(&fw, &bytes).unwrap();
            assert_eq!(
                (
                    info.response_version,
                    info.nvm_version,
                    info.board_type,
                    info.hardware_addresses
                ),
                (version, 0x1234, 0xa5, 4)
            );
            assert_eq!(
                (
                    info.mac_sku_flags,
                    info.tx_chains,
                    info.rx_chains,
                    info.lar_enabled
                ),
                (0x9944803f, 3, 2, 1)
            );
            assert!(info.empty_otp());
            assert_eq!(info.raw, bytes);
            for (n, value) in info.channel_profiles.iter().enumerate() {
                assert_eq!(
                    *value,
                    if version == 3 {
                        (n as u32 * 0x101 + 0x4321) & 0xffff
                    } else {
                        n as u32 * 0x101 + 0x4321
                    }
                );
            }
            for n in 0..bytes.len() {
                assert!(matches!(
                    Information::decode(&fw, &bytes[..n]),
                    Err(Error::Length { .. })
                ));
            }
            let mut too_long = bytes.clone();
            too_long.push(0);
            assert!(matches!(
                Information::decode(&fw, &too_long),
                Err(Error::Length { .. })
            ));
            if version >= 4 {
                let mut malformed = bytes.clone();
                malformed[24..28].copy_from_slice(&116u32.to_le_bytes());
                assert!(matches!(
                    Information::decode(&fw, &malformed),
                    Err(Error::ChannelCount(116))
                ));
                malformed[24..28].fill(0);
                let info = Information::decode(&fw, &malformed).unwrap();
                assert_eq!(info.channel_count, 0);
                assert!(!info.channel_profiles.is_empty());
            }
            let other = image(version, version < 4);
            let other = Firmware::parse(&other).unwrap();
            assert_eq!(
                Information::decode(&other, &bytes),
                Err(Error::InconsistentApi)
            );
        }
        let mut no_table = image(4, true);
        no_table[88..92].copy_from_slice(&999u32.to_le_bytes());
        let no_table = Firmware::parse(&no_table).unwrap();
        assert_eq!(Information::decode(&no_table, &[]), Err(Error::MissingApi));
        for version in [0, 1, 2, 6, 255] {
            let b = image(version, false);
            let fw = Firmware::parse(&b).unwrap();
            assert_eq!(
                Information::decode(&fw, &[]),
                Err(Error::UnsupportedVersion(version))
            );
        }
    }
    #[test]
    fn source_header_versions_are_distinct_from_documented_payload_abi() {
        for (request, group, opcode, payload) in [
            (Request::ExtendedConfiguration, 2, 3, [2, 0, 0, 0]),
            (Request::AccessComplete, 12, 0, [0; 4]),
            (Request::GetInformation, 12, 2, [0; 4]),
        ] {
            assert_eq!(
                request.id(),
                Id {
                    group,
                    opcode,
                    version: 0
                }
            );
            assert_eq!(request.payload(), payload);
        }
        assert_eq!(
            HardwareAddress::decode(0x02123456, 0xa5a5789a),
            [2, 0x12, 0x34, 0x56, 0x78, 0x9a]
        );
        assert_eq!(
            HardwareAddress::select([0x02123456, 0x789a], None)
                .unwrap()
                .source,
            AddressSource::Strap
        );
        for invalid in [[0, 0], [0x01123456, 0x789a], [u32::MAX, u32::MAX]] {
            assert_eq!(
                HardwareAddress::select(invalid, None),
                Err(Error::HardwareAddress)
            );
            assert_eq!(
                HardwareAddress::select(invalid, Some([0x02123456, 0x789a]))
                    .unwrap()
                    .source,
                AddressSource::Otp
            );
            assert_eq!(
                HardwareAddress::select(invalid, Some([0, 0])),
                Err(Error::HardwareAddress)
            );
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_NVM_ORACLE"]
    fn exact_linux_structures_and_unchanged_mac_permutation_oracle() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_NVM_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "5847329c6de91aa50c5811a37f2329062f966e14eae802d869aa1714cadc6ee5"
        );
        let text = core::str::from_utf8(&bytes).unwrap();
        let hex = |bytes: &[u8]| -> alloc::string::String {
            bytes.iter().map(|b| std::format!("{b:02x}")).collect()
        };
        let mut infos = 0;
        let mut addresses = 0;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields[0] {
                "sizes" => assert_eq!(fields, ["sizes", "128", "468", "488", "4", "4", "4"]),
                "init" => assert_eq!(fields[1], hex(&Request::ExtendedConfiguration.payload())),
                "info" => {
                    let version = fields[1].parse::<u8>().unwrap();
                    assert_eq!(fields[2], hex(&fixture(version)));
                    infos += 1;
                }
                "mac" => {
                    let first = fields[1].parse::<u32>().unwrap();
                    let second = fields[2].parse::<u32>().unwrap();
                    assert_eq!(fields[3], hex(&HardwareAddress::decode(first, second)));
                    addresses += 1;
                }
                _ => panic!("unknown oracle row"),
            }
        }
        assert_eq!((infos, addresses), (3, 5));
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
    fn actual_images_advertise_nvm_v4_with_correct_api_stride() {
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        for family in [Family::Ax200, Family::Ax210] {
            let b =
                std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
            let fw = Firmware::parse(&b).unwrap();
            let v = fw.command_version(12, 2).unwrap();
            assert_eq!((v.command_version, v.notification_version), (1, 4));
            let info = Information::decode(&fw, &fixture(4)).unwrap();
            assert_eq!(info.channel_count, 110);
            assert_eq!(fw.command_version(12, 0).unwrap().command_version, 1);
            // INIT_EXTENDED_CFG and INIT_COMPLETE have no CMD_VERSIONS rows in
            // these images. Their explicit source WIDE_ID/version0 remains.
            assert!(fw.command_version(2, 3).is_none());
            assert!(fw.command_version(0, 4).is_none());
        }
    }
}
