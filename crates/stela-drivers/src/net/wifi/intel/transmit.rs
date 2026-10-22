// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Pure initial non-QoS new-TX-API command serialization. This is not a
//! station/key/regulatory lease, DMA publication or proof of transmission.
use super::{
    command::{FIRST_TB_BYTES, Tfd},
    context::Region,
    firmware::{Family, Firmware},
};
use alloc::vec::Vec;
pub mod queue;
pub mod response;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MissingApi { group: u8, command: u8 },
    CommandVersion(u8),
    RateVersions,
    FrameLength,
    FrameControl,
    Fragment,
    Encryption,
    Antenna,
    Queue,
    Split,
    Descriptor(super::command::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyRate {
    Cck1,
    Cck2,
    Cck5_5,
    Cck11,
    Ofdm6,
    Ofdm9,
    Ofdm12,
    Ofdm18,
    Ofdm24,
    Ofdm36,
    Ofdm48,
    Ofdm54,
}
impl LegacyRate {
    fn rate_v2(self) -> u32 {
        match self {
            Self::Cck1 => 0,
            Self::Cck2 => 1,
            Self::Cck5_5 => 2,
            Self::Cck11 => 3,
            Self::Ofdm6 => 0x100,
            Self::Ofdm9 => 0x101,
            Self::Ofdm12 => 0x102,
            Self::Ofdm18 => 0x103,
            Self::Ofdm24 => 0x104,
            Self::Ofdm36 => 0x105,
            Self::Ofdm48 => 0x106,
            Self::Ofdm54 => 0x107,
        }
    }
}
/// Pure inputs corresponding to the source station and rate selection. These
/// copied observations grant no actual station, antenna, rate or key authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub station_authorized: Option<bool>,
    /// Source explicit host/injected-rate path, distinct from firmware RS.
    pub force_host_rate: bool,
    pub host_rate: LegacyRate,
    /// Source actual selected A=1 or B=2, not a PHY mask/default selection.
    pub host_antenna: u8,
    /// Actual future owner must retain the generation-bound firmware key and
    /// firmware nonce context through publication and all completion/drain.
    pub firmware_encryption: bool,
}
#[derive(Debug)]
pub struct Prepared {
    family: Family,
    command_and_mac: Vec<u8>,
    payload: Vec<u8>,
    mpdu_bytes: u16,
    host_rate: Option<u32>,
}
/// Complete source command/notification consistency for the admitted initial
/// format-2 families. Shared by native TX preparation and RX normalization.
pub(crate) fn rate_format_2(fw: &Firmware<'_>, family: Family) -> Result<(), Error> {
    let lookup = |group, command| {
        fw.command_version(group, command)
            .ok_or(Error::MissingApi { group, command })
    };
    let tx = lookup(1, 0x1c)?;
    let expected = if family == Family::Ax200 { 9 } else { 10 };
    if tx.command_version != expected {
        return Err(Error::CommandVersion(tx.command_version));
    }
    // Complete source ops.c format2/3 consistency checks. This initial
    // encoder admits only the source-matched format2 schemas above.
    let tlc = lookup(5, 0xf7)?.notification_version;
    let rx = lookup(0, 0xc1)?.notification_version;
    let checks2 = [
        tx.command_version >= 8,
        tlc >= 3,
        rx >= 4,
        tx.notification_version >= 6,
    ];
    let checks3 = [
        tx.command_version >= 11,
        tlc >= 4,
        rx >= 6,
        fw.command_version(5, 0xf5)
            .is_some_and(|v| v.notification_version >= 4),
        tx.notification_version >= 9,
    ];
    if !checks2.iter().all(|v| *v) || checks3.iter().any(|v| *v) {
        return Err(Error::RateVersions);
    }
    Ok(())
}
impl Prepared {
    pub fn prepare(
        fw: &Firmware<'_>,
        family: Family,
        mpdu: &[u8],
        parameters: Parameters,
    ) -> Result<Self, Error> {
        rate_format_2(fw, family)?;
        // Explicit bounded initial profile: full 24-byte non-QoS MAC header,
        // ordinary ToDS data or management; no fragmentation, MFP, checksum,
        // aggregation, four-address, HT-control or host-generated crypto bytes.
        if !(24..=4096).contains(&mpdu.len()) {
            return Err(Error::FrameLength);
        }
        let fc = u16::from_le_bytes(mpdu[..2].try_into().unwrap());
        let data = fc & 0x00fc == 0x0008;
        let management = fc & 0x000c == 0;
        if fc & 3 != 0
            || fc & 0x8000 != 0
            || !(data || management)
            || (data && fc & 0x0300 != 0x0100)
            || (management && fc & 0x0300 != 0)
        {
            return Err(Error::FrameControl);
        }
        if fc & 0x0400 != 0 || mpdu[22] & 0x0f != 0 {
            return Err(Error::Fragment);
        }
        if parameters.firmware_encryption != (fc & 0x4000 != 0)
            || (management && parameters.firmware_encryption)
        {
            return Err(Error::Encryption);
        }
        let use_host = parameters.station_authorized.is_none()
            || parameters.force_host_rate
            || !data
            || parameters.station_authorized != Some(true);
        let rate = if use_host {
            if ![1, 2].contains(&parameters.host_antenna) {
                return Err(Error::Antenna);
            }
            Some(parameters.host_rate.rate_v2() | u32::from(parameters.host_antenna) << 14)
        } else {
            None
        };
        let flags = u16::from(use_host) | if parameters.firmware_encryption { 0 } else { 2 };
        let mut bytes = alloc::vec![0; if family == Family::Ax200 {20} else {28}];
        bytes[..2].copy_from_slice(&(mpdu.len() as u16).to_le_bytes());
        if family == Family::Ax200 {
            bytes[2..4].copy_from_slice(&0x0c00u16.to_le_bytes());
            bytes[4..8].copy_from_slice(&u32::from(flags).to_le_bytes());
        } else {
            bytes[2..4].copy_from_slice(&flags.to_le_bytes());
            bytes[4..8].copy_from_slice(&0x0c00u32.to_le_bytes());
        }
        // DRAM security info (8..16) is firmware-owned storage, not an observed
        // PN or host seed. AX210 reserved tail (20..28) stays zero.
        bytes[16..20].copy_from_slice(&rate.unwrap_or(0).to_le_bytes());
        bytes.extend(&mpdu[..24]);
        Ok(Self {
            family,
            command_and_mac: bytes,
            payload: mpdu[24..].to_vec(),
            mpdu_bytes: mpdu.len() as u16,
            host_rate: rate,
        })
    }
    pub fn command_and_mac(&self) -> &[u8] {
        &self.command_and_mac
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn host_rate(&self) -> Option<u32> {
        self.host_rate
    }
    /// TVQM queue identity is 9-bit; the source echo sequence deliberately
    /// contains only its low5 bits. Actual completion must use the complete
    /// source response queue and retained epoch, never this echo alone.
    pub fn encode(&self, queue: u16, index: u16) -> Result<Encoded, Error> {
        if queue >= 512 {
            return Err(Error::Queue);
        }
        let sequence = ((queue & 0x1f) << 8) | (index & 0xff);
        let mut command = alloc::vec![0x1c, 0];
        command.extend(sequence.to_le_bytes());
        command.extend(&self.command_and_mac);
        Ok(Encoded {
            family: self.family,
            queue,
            sequence,
            command,
            payload: self.payload.clone(),
            mpdu_bytes: self.mpdu_bytes,
        })
    }
}
#[derive(Debug)]
pub struct Encoded {
    family: Family,
    queue: u16,
    sequence: u16,
    command: Vec<u8>,
    payload: Vec<u8>,
    mpdu_bytes: u16,
}
impl Encoded {
    pub fn queue(&self) -> u16 {
        self.queue
    }
    pub fn sequence(&self) -> u16 {
        self.sequence
    }
    pub fn command(&self) -> &[u8] {
        &self.command
    }
    /// Actual source TB0 is bidirectional coherent firmware storage; callers
    /// must not map it read-only or overwrite before a real CPU handoff.
    pub fn first_tb(&self) -> &[u8] {
        &self.command[..FIRST_TB_BYTES]
    }
    pub fn second_tb(&self) -> &[u8] {
        &self.command[FIRST_TB_BYTES..]
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Wire inputs only; Region values do not prove live mappings/visibility.
    pub fn tfd(
        &self,
        first: Region,
        second: Region,
        payload: Option<Region>,
    ) -> Result<(Tfd, u16), Error> {
        if first.bytes != self.first_tb().len() || second.bytes != self.second_tb().len() {
            return Err(Error::Split);
        }
        let mut regions = alloc::vec![first, second];
        match (self.payload.is_empty(), payload) {
            (true, None) => (),
            (false, Some(region)) if region.bytes == self.payload.len() => regions.push(region),
            _ => return Err(Error::Split),
        }
        let tfd = Tfd::encode(&regions).map_err(Error::Descriptor)?;
        // Two/three TBs occupy <=64 bytes, hence zero fetch-chunk extension.
        let byte_count = if self.family == Family::Ax200 {
            self.mpdu_bytes.div_ceil(4)
        } else {
            self.mpdu_bytes
        };
        Ok((tfd, byte_count))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    const RATES: [LegacyRate; 12] = [
        LegacyRate::Cck1,
        LegacyRate::Cck2,
        LegacyRate::Cck5_5,
        LegacyRate::Cck11,
        LegacyRate::Ofdm6,
        LegacyRate::Ofdm9,
        LegacyRate::Ofdm12,
        LegacyRate::Ofdm18,
        LegacyRate::Ofdm24,
        LegacyRate::Ofdm36,
        LegacyRate::Ofdm48,
        LegacyRate::Ofdm54,
    ];
    pub(super) fn firmware(rows: &[[u8; 4]]) -> Vec<u8> {
        let mut b = alloc::vec![0;88];
        b[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
        if !rows.is_empty() {
            b.extend(48u32.to_le_bytes());
            b.extend((rows.len() as u32 * 4).to_le_bytes());
            b.extend(rows.iter().flatten());
        }
        b
    }
    pub(super) fn rows(family: Family) -> [[u8; 4]; 4] {
        [
            [0x1c, 1, if family == Family::Ax200 { 9 } else { 10 }, 7],
            [0xf7, 5, 99, 3],
            [0xc1, 0, 99, if family == Family::Ax200 { 4 } else { 5 }],
            [0xf5, 5, 99, 3],
        ]
    }
    fn parameters() -> Parameters {
        Parameters {
            station_authorized: Some(true),
            force_host_rate: false,
            host_rate: LegacyRate::Ofdm6,
            host_antenna: 1,
            firmware_encryption: false,
        }
    }
    fn frame(data: bool, key: bool, len: usize, scene: u32) -> Vec<u8> {
        let mut f: Vec<_> = (0..len).map(|i| (i as u32 * 29 + scene) as u8).collect();
        f[..2].copy_from_slice(
            &(if data { 0x108u16 } else { 0xb0 } | if key { 0x4000 } else { 0 }).to_le_bytes(),
        );
        f[22] &= 0xf0;
        f
    }
    #[test]
    fn schema_consistency_is_required_before_any_frame_preparation() {
        for family in [Family::Ax200, Family::Ax210] {
            let mut r = rows(family);
            let f = frame(true, false, 24, 0);
            for schema in [0, 7, 8, 11, 99, 255] {
                r[0][2] = schema;
                let b = firmware(&r);
                assert_eq!(
                    Prepared::prepare(&Firmware::parse(&b).unwrap(), family, &f, parameters())
                        .unwrap_err(),
                    Error::CommandVersion(schema)
                );
            }
            for missing in 0..3 {
                let r: Vec<_> = rows(family)
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, v)| (i != missing).then_some(v))
                    .collect();
                let b = firmware(&r);
                assert!(matches!(
                    Prepared::prepare(&Firmware::parse(&b).unwrap(), family, &f, parameters()),
                    Err(Error::MissingApi { .. })
                ));
            }
            for (row, field, value) in [
                (0, 3, 5),
                (0, 3, 9),
                (1, 3, 2),
                (1, 3, 4),
                (2, 3, 3),
                (2, 3, 6),
                (3, 3, 4),
            ] {
                let mut r = rows(family);
                r[row][field] = value;
                let b = firmware(&r);
                assert_eq!(
                    Prepared::prepare(&Firmware::parse(&b).unwrap(), family, &f, parameters())
                        .unwrap_err(),
                    Error::RateVersions
                );
            }
        }
    }
    #[test]
    fn bounded_profile_preserves_header_sequence_and_refuses_unrepresented_effects() {
        let b = firmware(&rows(Family::Ax200));
        let fw = Firmware::parse(&b).unwrap();
        for len in [0, 1, 23, 4097] {
            assert_eq!(
                Prepared::prepare(&fw, Family::Ax200, &alloc::vec![0;len], parameters())
                    .unwrap_err(),
                Error::FrameLength
            );
        }
        for (fc, error) in [
            (0x109, Error::FrameControl),
            (0x188, Error::FrameControl),
            (0x308, Error::FrameControl),
            (0x208, Error::FrameControl),
            (0x8108, Error::FrameControl),
            (0x508, Error::Fragment),
            (0x4108, Error::Encryption),
            (0x104, Error::FrameControl),
        ] {
            let mut f = frame(true, false, 24, 0);
            f[..2].copy_from_slice(&(fc as u16).to_le_bytes());
            assert_eq!(
                Prepared::prepare(&fw, Family::Ax200, &f, parameters()).unwrap_err(),
                error
            );
        }
        let mut f = frame(true, false, 25, 0);
        f[22] |= 1;
        assert_eq!(
            Prepared::prepare(&fw, Family::Ax200, &f, parameters()).unwrap_err(),
            Error::Fragment
        );
        let f = frame(true, false, 25, 0);
        let p = Parameters {
            host_antenna: 0,
            ..parameters()
        };
        assert!(
            Prepared::prepare(&fw, Family::Ax200, &f, p)
                .unwrap()
                .host_rate()
                .is_none()
        ); // unused host input.
        assert_eq!(
            Prepared::prepare(
                &fw,
                Family::Ax200,
                &f,
                Parameters {
                    force_host_rate: true,
                    ..p
                }
            )
            .unwrap_err(),
            Error::Antenna
        );
        for sequence in (0..=u16::MAX).step_by(16) {
            let mut f = f.clone();
            f[22..24].copy_from_slice(&sequence.to_le_bytes());
            let cmd = Prepared::prepare(&fw, Family::Ax200, &f, parameters()).unwrap();
            assert_eq!(&cmd.command_and_mac()[20..], &f[..24]);
        }
        let mut p = parameters();
        p.firmware_encryption = true;
        assert_eq!(
            Prepared::prepare(&fw, Family::Ax200, &f, p).unwrap_err(),
            Error::Encryption
        );
        assert_eq!(
            Prepared::prepare(&fw, Family::Ax200, &frame(false, true, 24, 0), p).unwrap_err(),
            Error::Encryption
        );
    }
    #[test]
    fn source_short_header_full_queue_echo_and_exact_three_dma_ranges() {
        for family in [Family::Ax200, Family::Ax210] {
            let b = firmware(&rows(family));
            let fw = Firmware::parse(&b).unwrap();
            for len in [24, 25, 4096] {
                let f = frame(true, true, len, 123);
                let plan = Prepared::prepare(
                    &fw,
                    family,
                    &f,
                    Parameters {
                        firmware_encryption: true,
                        ..parameters()
                    },
                )
                .unwrap();
                for queue in [0, 31, 32, 255, 511] {
                    let encoded = plan.encode(queue, 0x12ab).unwrap();
                    assert_eq!(encoded.queue(), queue);
                    assert_eq!(
                        &encoded.command()[..4],
                        &[0x1c, 0, 0xab, (queue & 31) as u8]
                    );
                    assert_eq!(encoded.sequence(), ((queue & 31) << 8) | 0xab);
                    assert_eq!(encoded.first_tb().len(), 20);
                    assert_eq!(&encoded.command()[12..20], &[0; 8]);
                    assert_eq!(encoded.payload(), &f[24..]);
                    let first = Region {
                        address: 0x100000,
                        bytes: 20,
                    };
                    let second = Region {
                        address: 0x200001,
                        bytes: encoded.second_tb().len(),
                    };
                    let payload = (!encoded.payload().is_empty()).then_some(Region {
                        address: 0x300003,
                        bytes: encoded.payload().len(),
                    });
                    let (tfd, bc) = encoded.tfd(first, second, payload).unwrap();
                    assert_eq!(
                        u16::from_le_bytes(tfd.bytes()[..2].try_into().unwrap()),
                        if len == 24 { 2 } else { 3 }
                    );
                    assert_eq!(
                        bc,
                        if family == Family::Ax200 {
                            len.div_ceil(4) as u16
                        } else {
                            len as u16
                        }
                    );
                    assert_eq!(
                        encoded
                            .tfd(Region { bytes: 19, ..first }, second, payload)
                            .unwrap_err(),
                        Error::Split
                    );
                    assert_eq!(
                        encoded
                            .tfd(
                                first,
                                Region {
                                    bytes: second.bytes + 1,
                                    ..second
                                },
                                payload
                            )
                            .unwrap_err(),
                        Error::Split
                    );
                }
                assert_eq!(plan.encode(512, 0).unwrap_err(), Error::Queue);
            }
        }
    }
    #[test]
    #[ignore = "requires actual pinned Intel firmware images"]
    fn actual_images_negotiate_source_rate2_and_family9_10_layouts() {
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        for family in [Family::Ax200, Family::Ax210] {
            let b =
                std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
            let fw = Firmware::parse(&b).unwrap();
            let plan =
                Prepared::prepare(&fw, family, &frame(true, false, 60, 0), parameters()).unwrap();
            assert_eq!(
                plan.command_and_mac().len(),
                if family == Family::Ax200 { 44 } else { 52 }
            );
            assert_eq!(plan.host_rate(), None);
        }
    }
    #[test]
    #[ignore = "requires fresh unchanged Linux complete new TX command helper oracle"]
    fn unchanged_linux_new_tx_helpers_match_complete_commands_and_byte_counts() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_TRANSMIT_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "5bdcc7ad438bed3d044f5ebc9148589c43a5e7b448fb0496abb6708f6f7797cf"
        );
        let mut count = 0;
        for line in core::str::from_utf8(&bytes).unwrap().lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            let u = |i: usize| f[i].parse::<u32>().unwrap();
            assert_eq!(f[0], "tx");
            let family = if u(1) == 0 {
                Family::Ax200
            } else {
                Family::Ax210
            };
            let b = firmware(&rows(family));
            let fw = Firmware::parse(&b).unwrap();
            let len = [24, 25, 60, 1514, 4096][u(8) as usize];
            let mpdu = frame(u(2) != 0, u(3) != 0, len, u(9));
            let p = Parameters {
                station_authorized: if u(4) == 0 { None } else { Some(u(4) == 2) },
                force_host_rate: u(5) != 0,
                host_rate: RATES[u(6) as usize],
                host_antenna: u(7) as u8,
                firmware_encryption: u(3) != 0,
            };
            let plan = Prepared::prepare(&fw, family, &mpdu, p).unwrap();
            let encoded = plan.encode(u(10) as u16, u(11) as u16).unwrap();
            let hex: std::string::String = encoded
                .command()
                .iter()
                .map(|b| std::format!("{b:02x}"))
                .collect();
            assert_eq!(hex, f[12], "{line}");
            let (_, bc) = encoded
                .tfd(
                    Region {
                        address: 0x100000,
                        bytes: 20,
                    },
                    Region {
                        address: 0x200000,
                        bytes: encoded.second_tb().len(),
                    },
                    (len > 24).then_some(Region {
                        address: 0x300000,
                        bytes: len - 24,
                    }),
                )
                .unwrap();
            assert_eq!(u32::from(bc), u(13));
            count += 1;
        }
        assert_eq!(count, 4320);
    }
}
