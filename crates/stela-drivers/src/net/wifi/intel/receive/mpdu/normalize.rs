// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2012-2014, 2018-2025 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
// Frequency conversion: Copyright 2007-2009 Johannes Berg;
// 2013-2014 Intel Mobile Communications GmbH; 2017 Intel Deutschland GmbH;
// 2018-2023, 2025-2026 Intel Corporation. See THIRD_PARTY.md.
//! CPU-owned RX normalization following rxmq.c. Hardware crypto observations
//! remain unauthenticated: no copied status can manufacture an installed key,
//! association, software replay check or authenticated shared MPDU.
use super::{
    Band as RawBand, Metadata, Observation, ReplayOrTtak, SEC_CCM, SEC_EXT_ENC, SEC_GCM, SEC_NONE,
    SEC_TKIP, SEC_UNKNOWN, SEC_WEP, Status,
};
use crate::net::wifi::{
    Band, RadioStatus, RawRate, Timestamp,
    frame::{self, Header, Mpdu},
    intel::{
        firmware::{Family, Firmware},
        transmit,
    },
    security::{HardwareReplay, Integrity, PacketNumber, SecurityStatus},
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Frame(frame::Error),
    RateFormat,
    Band(u8),
    Channel,
    CryptoRejected,
    UnsupportedCipher(u8),
    ManagementProtection,
    Aggregation,
    Length,
    PacketNumber,
}

/// Exact source crypto helper observations, not an authentication receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Crypto {
    pub decrypted: bool,
    pub mic_stripped: bool,
    pub tkip_mic_error: bool,
    pub icv_stripped: bool,
    pub tkip_mic_stripped: bool,
    pub iv_bytes: u8,
}
impl Crypto {
    fn observe(
        status: Status,
        protected: bool,
        management: bool,
        ampdu: bool,
        monitor: bool,
        rada: bool,
    ) -> Result<Self, Error> {
        let cipher = status.cipher_code();
        if ampdu && cipher == SEC_UNKNOWN && !monitor {
            return Err(Error::CryptoRejected);
        }
        if management && !protected && cipher != SEC_NONE {
            return Err(Error::ManagementProtection);
        }
        let mut result = Self::default();
        if !protected || cipher == SEC_NONE {
            return Ok(result);
        }
        match cipher {
            SEC_CCM | SEC_GCM => {
                if !status.mic_ok_bit() {
                    return Err(Error::CryptoRejected);
                }
                result.decrypted = true;
                result.mic_stripped = true;
                result.iv_bytes = 8;
            }
            SEC_WEP | SEC_TKIP => {
                if cipher == SEC_TKIP {
                    if status.replay_or_ttak() == ReplayOrTtak::TtakOk(false) {
                        return Ok(result);
                    }
                    result.tkip_mic_error = !status.mic_ok_bit();
                    result.iv_bytes = 8;
                }
                if !status.icv_ok_bit() {
                    return Err(Error::CryptoRejected);
                }
                result.decrypted = true;
                if cipher == SEC_WEP {
                    result.iv_bytes = 4;
                }
                result.icv_stripped = rada;
                result.tkip_mic_stripped = rada;
            }
            SEC_EXT_ENC => {
                if !status.mic_ok_bit() {
                    return Err(Error::CryptoRejected);
                }
                result.decrypted = true;
            }
            _ => {}
        }
        Ok(result)
    }
}

pub struct Normalized {
    pub frame: Mpdu,
    pub crypto: Crypto,
    /// Observed IV index only. It does not resolve a physical slot/generation.
    pub key_index: Option<u8>,
}

/// Source create_skb logical byte result, without its SKB/page allocator. The
/// caller supplies already CPU-owned bytes and an actual parsed MAC length.
fn copy_bytes(
    raw: &[u8],
    header: usize,
    iv: usize,
    pad: usize,
    tail: usize,
) -> Result<Vec<u8>, Error> {
    let len = raw.len().checked_sub(pad).ok_or(Error::Length)?;
    // Source removes the reported tail only when len > tail. Reject the other
    // case here rather than presenting retained CRC/MIC bytes as normalized.
    if len <= tail {
        return Err(Error::Length);
    }
    let len = len - tail;
    let head = header.checked_add(iv).ok_or(Error::Length)?;
    if len < head || head.checked_add(pad).ok_or(Error::Length)? > raw.len() {
        return Err(Error::Length);
    }
    let end = len.checked_add(pad).ok_or(Error::Length)?;
    let mut bytes = Vec::with_capacity(len);
    bytes.extend_from_slice(&raw[..head]);
    bytes.extend_from_slice(raw.get(head + pad..end).ok_or(Error::Length)?);
    Ok(bytes)
}

fn radio(metadata: Metadata) -> Result<RadioStatus, Error> {
    let raw = metadata.radio;
    let band = match raw.band {
        RawBand::Explicit(0) | RawBand::ChannelInferred { five_ghz: true } => Band::Ghz5,
        RawBand::Explicit(1) | RawBand::ChannelInferred { five_ghz: false } => Band::Ghz2,
        RawBand::Explicit(2) => Band::Ghz6,
        RawBand::Explicit(value) => return Err(Error::Band(value)),
    };
    let channel = u16::from(raw.channel);
    let frequency_mhz = match (band, channel) {
        (_, 0) => return Err(Error::Channel),
        (Band::Ghz2, 14) => 2484,
        (Band::Ghz2, 1..=13) => 2407 + 5 * channel,
        (Band::Ghz2, _) => return Err(Error::Channel),
        (Band::Ghz5, 182..=196) => 4000 + 5 * channel,
        (Band::Ghz5, _) => 5000 + 5 * channel,
        (Band::Ghz6, 2) => 5935,
        (Band::Ghz6, 1..=253) => 5950 + 5 * channel,
        (Band::Ghz6, _) => return Err(Error::Channel),
    };
    // Zero means not measured. Refuse unrepresentable magnitudes rather than
    // reproducing a narrowing wrap into a positive signal. No beacon-average
    // override is fabricated without the actual source per-link state.
    let energy = |n: u8| (1..=128).contains(&n).then(|| (-(i16::from(n))) as i8);
    let a = energy(raw.energy[0]);
    let b = energy(raw.energy[1]);
    let antenna = (raw.raw_rate >> 14) & 3;
    Ok(RadioStatus {
        band,
        channel,
        frequency_mhz,
        signal_dbm: a.into_iter().chain(b).max(),
        chain_signal_dbm: [
            if antenna & 1 != 0 { a } else { None },
            if antenna & 2 != 0 { b } else { None },
            None,
            None,
        ],
        rate: RawRate {
            layout: 2,
            words: [raw.raw_rate, 0, 0, 0],
        },
        rx_rate: None,
        tsf: match raw.timestamp {
            super::Timestamp::Counter(value) => Some(Timestamp::Full64(value)),
            super::Timestamp::Overloaded { .. } => None,
        },
    })
}

pub(crate) fn normalize(
    metadata: Metadata,
    raw: &[u8],
    packet_flags: u32,
    rate_format_2: bool,
) -> Result<Normalized, Error> {
    if !rate_format_2 {
        return Err(Error::RateFormat);
    }
    let header = Header::parse(raw).map_err(Error::Frame)?;
    let management = header.control & 12 == 0;
    // Initial station security has no reorder/PN-sharing or MFP owner. Keep
    // those explicit instead of inventing an AMPDU reference from its toggle.
    if metadata.mac.ampdu()
        || metadata.mac.amsdu()
        || header.amsdu
        || metadata.reorder.ba_id.is_some()
    {
        return Err(Error::Aggregation);
    }
    if management && (header.protected() || metadata.status.cipher_code() != SEC_NONE) {
        return Err(Error::ManagementProtection);
    }
    if header.protected() && !header.data_present() {
        return Err(Error::Frame(frame::Error::Unsupported(
            "protected non-data frame",
        )));
    }
    if header.protected() && !matches!(metadata.status.cipher_code(), SEC_CCM | SEC_GCM) {
        return Err(Error::UnsupportedCipher(metadata.status.cipher_code()));
    }
    let crypto = Crypto::observe(
        metadata.status,
        header.protected(),
        management,
        false,
        false,
        packet_flags & (1 << 26) != 0,
    )?;
    let bytes = copy_bytes(
        raw,
        header.length,
        usize::from(crypto.iv_bytes),
        metadata.mac.padding_bytes(),
        metadata.mac.mic_crc_tail_bytes(),
    )?;
    let (key_index, pn) = if crypto.iv_bytes == 8 {
        let (pn, index) = PacketNumber::from_header(
            bytes
                .get(header.length..header.length + 8)
                .ok_or(Error::Length)?,
        )
        .map_err(|_| Error::PacketNumber)?;
        (Some(index), Some(pn))
    } else {
        (None, None)
    };
    let security = SecurityStatus {
        pn,
        decrypted: crypto.decrypted,
        mic_stripped: crypto.mic_stripped,
        // MIC_OK alone cannot bind cipher width, installed key generation,
        // station/association lifetime or software PN state.
        integrity: Integrity::Unknown,
        hardware_replay: match metadata.status.replay_or_ttak() {
            ReplayOrTtak::ReplayError(true) => HardwareReplay::Failed { layout: 41 },
            _ => HardwareReplay::Unknown,
        },
        ..SecurityStatus::default()
    };
    let mut frame = Mpdu::new(bytes, radio(metadata)?, security).map_err(Error::Frame)?;
    frame.fcs_error = metadata.status.failed_fcs_or_overrun();
    frame.raw_status = [
        metadata.status.raw(),
        metadata.reorder.raw,
        metadata.radio.raw_rate,
        packet_flags,
    ];
    Ok(Normalized {
        frame,
        crypto,
        key_index,
    })
}

impl Observation<'_> {
    /// Normalize diagnostic CPU-owned bytes. This grants no native key or
    /// receive epoch; actual transport receipts retain their separate owner.
    pub fn normalize(&self, fw: &Firmware<'_>, family: Family) -> Result<Normalized, Error> {
        normalize(
            self.metadata(),
            self.raw_mpdu(),
            self.packet_flags,
            transmit::rate_format_2(fw, family).is_ok(),
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{Mac, Radio, Reorder};
    use super::*;
    use alloc::vec;

    fn metadata() -> Metadata {
        Metadata {
            status: Status {
                raw: 3 | (2 << 8) | (1 << 6),
                deprecate_ttak: true,
            },
            mac: Mac {
                flags1: 4 << 4,
                flags2: 0x20,
                amsdu_info: 0,
                phy_info: 0,
            },
            reorder: Reorder {
                raw: 127 << 24,
                next_sequence: 0,
                sequence: 0,
                ba_id: None,
                old_sequence: false,
            },
            radio: Radio {
                raw_rate: 3 << 14,
                energy: [44, 56],
                channel: 6,
                mac_context: 0,
                mac_phy_band: 1,
                band: RawBand::Explicit(1),
                gp2_on_air_rise: 99,
                timestamp: super::super::Timestamp::Counter(1234),
                raw_timestamp: 1234,
                phy_data0: 0,
                phy_data1: 0,
                phy_data2: 0,
                phy_data3: 0,
                phy_word4: 0,
                phy_data5: None,
            },
        }
    }
    fn protected_frame() -> Vec<u8> {
        let mut bytes = vec![0; 24];
        bytes[..2].copy_from_slice(&0x4208u16.to_le_bytes());
        bytes.extend([1, 0, 0, 0x60, 0, 0, 0, 0]); // retained PN=1, index=1
        bytes.extend([0xa5, 0x5a]); // pad is after header AND IV
        bytes.extend(b"payload");
        bytes.extend([0xcc; 8]); // source reported MIC/CRC tail
        bytes
    }
    #[test]
    fn normalized_crypto_observations_never_manufacture_key_or_integrity() {
        let mut metadata = metadata();
        let raw = protected_frame();
        let normalized = normalize(metadata, &raw, 1 << 26, true).unwrap();
        assert_eq!(
            &normalized.frame.bytes()[24..32],
            &[1, 0, 0, 0x60, 0, 0, 0, 0]
        );
        assert_eq!(&normalized.frame.bytes()[32..], b"payload");
        assert_eq!(normalized.key_index, Some(1));
        assert_eq!(normalized.frame.security.pn.unwrap().value(), 1);
        assert!(normalized.frame.security.decrypted); // source MIC_OK, even though raw decrypted bit is clear
        assert!(normalized.frame.security.mic_stripped);
        assert!(!normalized.frame.security.iv_stripped);
        assert_eq!(normalized.frame.security.integrity, Integrity::Unknown);
        assert_eq!(normalized.frame.security.key, None);
        assert_eq!(
            normalized.frame.security.hardware_replay,
            HardwareReplay::Unknown
        );
        assert_eq!(normalized.frame.radio.frequency_mhz, 2437);
        assert_eq!(normalized.frame.radio.signal_dbm, Some(-44));
        assert_eq!(
            normalized.frame.radio.chain_signal_dbm,
            [Some(-44), Some(-56), None, None]
        );
        assert_eq!(normalized.frame.radio.tsf, Some(Timestamp::Full64(1234)));
        assert!(!normalized.frame.fcs_error);
        metadata.status.raw |= 0x80;
        assert_eq!(
            normalize(metadata, &raw, 0, true)
                .unwrap()
                .frame
                .security
                .hardware_replay,
            HardwareReplay::Failed { layout: 41 }
        );
        metadata.status.raw &= !(1 << 6);
        assert!(matches!(
            normalize(metadata, &raw, 0, true),
            Err(Error::CryptoRejected)
        ));
        for cipher in [0, 1, 3, 4, 6, 7] {
            metadata.status.raw = 3 | (cipher << 8) | (1 << 6);
            assert!(matches!(
                normalize(metadata, &raw, 0, true),
                Err(Error::UnsupportedCipher(_))
            ));
        }
        metadata.status.raw = 3 | (5 << 8) | (1 << 6);
        assert!(normalize(metadata, &raw, 0, true).is_ok());
        assert!(matches!(
            normalize(metadata, &raw, 0, false),
            Err(Error::RateFormat)
        ));
        for length in 0..42 {
            // header + IV + pad + reported tail
            assert!(normalize(metadata, &raw[..length], 0, true).is_err());
        }
        // Like mac80211, the reserved CCMP header byte is not read.
        let mut reserved = raw.clone();
        reserved[26] = 1;
        let normalized = normalize(metadata, &reserved, 0, true).unwrap();
        assert_eq!(normalized.frame.security.pn.unwrap().value(), 1);
        let mut control = raw.clone();
        control[..2].copy_from_slice(&0x40c4u16.to_le_bytes());
        control[10..18].copy_from_slice(&[1, 0, 0, 0x20, 0, 0, 0, 0]);
        assert!(matches!(
            normalize(metadata, &control, 0, true),
            Err(Error::Frame(frame::Error::Unsupported(
                "protected non-data frame"
            )))
        ));
        for (ampdu, amsdu, baid) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut m = metadata;
            m.mac.phy_info = if ampdu { 0x20 } else { 0 };
            m.mac.flags2 |= if amsdu { 0x40 } else { 0 };
            m.reorder.ba_id = baid.then_some(1);
            assert!(matches!(
                normalize(m, &raw, 0, true),
                Err(Error::Aggregation)
            ));
        }
    }
    #[test]
    fn plaintext_management_and_radio_boundaries_are_explicit() {
        let mut m = metadata();
        m.status.raw = 3;
        m.mac.flags1 = 0;
        m.mac.flags2 = 0;
        let mut bytes = vec![0; 24];
        bytes[..2].copy_from_slice(&0x80u16.to_le_bytes());
        let plain = normalize(m, &bytes, 0, true).unwrap();
        assert_eq!(plain.frame.bytes(), bytes);
        assert!(!plain.frame.security.decrypted);
        assert_eq!(plain.frame.security.key, None);
        m.status.raw |= 6 << 8;
        assert!(matches!(
            normalize(m, &bytes, 0, true),
            Err(Error::ManagementProtection)
        ));
        m.status.raw = 0;
        assert!(normalize(m, &bytes, 0, true).unwrap().frame.fcs_error);
        for (band, channel, frequency) in [
            (1, 14, 2484),
            (0, 36, 5180),
            (0, 184, 4920),
            (2, 2, 5935),
            (2, 253, 7215),
        ] {
            m.radio.band = RawBand::Explicit(band);
            m.radio.channel = channel;
            assert_eq!(
                normalize(m, &bytes, 0, true)
                    .unwrap()
                    .frame
                    .radio
                    .frequency_mhz,
                frequency
            );
        }
        for (band, channel) in [(3, 1), (1, 0), (1, 15), (2, 254)] {
            m.radio.band = RawBand::Explicit(band);
            m.radio.channel = channel;
            assert!(normalize(m, &bytes, 0, true).is_err());
        }
        m.radio.band = RawBand::ChannelInferred { five_ghz: true };
        m.radio.channel = 36;
        m.radio.energy = [0, 255];
        m.radio.timestamp = super::super::Timestamp::Overloaded { low: 12, high: 34 };
        let radio = normalize(m, &bytes, 0, true).unwrap().frame.radio;
        assert_eq!(radio.signal_dbm, None);
        assert_eq!(radio.tsf, None); // GP2 and overloaded words never become TSF
        for n in 1..=128 {
            m.radio.energy = [n, 0];
            assert_eq!(
                super::radio(m).unwrap().signal_dbm,
                Some(-(i16::from(n)) as i8)
            );
        }
    }
    #[test]
    #[ignore = "requires unchanged pinned Linux RX crypto/create-SKB oracle"]
    fn unchanged_linux_crypto_and_logical_skb_bytes_match() {
        let path = std::env::var("STELA_IWLWIFI_RX_CRYPTO_ORACLE").unwrap();
        let trace = std::fs::read_to_string(path).unwrap();
        use sha2::{Digest, Sha256};
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(trace.as_bytes())),
            [
                0x27, 0x90, 0x53, 0xfd, 0x3d, 0x7b, 0xc1, 0x0b, 0x8e, 0x3e, 0xff, 0x39, 0x07, 0xd2,
                0xde, 0x56, 0x52, 0xa8, 0x95, 0x12, 0x46, 0xf8, 0xe6, 0x08, 0x69, 0x41, 0x86, 0xf7,
                0x8d, 0x51, 0x27, 0x82
            ]
        );
        let (mut crypto_cases, mut copies) = (0, 0);
        for line in trace.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let n = |i: usize| fields[i].parse::<u32>().unwrap();
            if fields[0] == "crypto" {
                let cipher = n(1);
                let flags = n(2);
                let status = Status {
                    raw: 3
                        | (cipher << 8)
                        | if flags & 1 != 0 { 1 << 3 } else { 0 }
                        | if flags & 2 != 0 { 1 << 5 } else { 0 }
                        | if flags & 4 != 0 { 1 << 6 } else { 0 }
                        | if flags & 8 != 0 { 1 << 7 } else { 0 }
                        | if flags & 16 != 0 { 1 << 11 } else { 0 },
                    deprecate_ttak: n(3) != 0,
                };
                let observed =
                    Crypto::observe(status, n(6) != 0, false, n(4) != 0, n(5) != 0, n(7) != 0);
                let result = fields[8].parse::<i32>().unwrap();
                assert_eq!(observed.is_err(), result != 0, "{line}");
                if let Ok(c) = observed {
                    let flags = u32::from(c.decrypted)
                        | (u32::from(c.mic_stripped) << 1)
                        | (u32::from(c.tkip_mic_error) << 2)
                        | (u32::from(c.icv_stripped) << 3)
                        | (u32::from(c.tkip_mic_stripped) << 4);
                    assert_eq!(flags, n(9), "{line}");
                    assert_eq!(u32::from(c.iv_bytes), n(10), "{line}");
                }
                crypto_cases += 1;
            } else {
                let fc = [0x208u16, 0x288, 0x308, 0x388][n(2) as usize];
                let crypt = [0, 4, 8][n(3) as usize];
                let pad = n(4) as usize * 2;
                let tail = n(5) as usize * 2;
                let body = [0, 8, 200][n(6) as usize];
                let scene = n(7) as usize;
                let header = frame::header_len(fc);
                let length = header + crypt + pad + tail + body;
                let mut raw: Vec<_> = (0..length).map(|i| (i * 29 + scene) as u8).collect();
                raw[..2].copy_from_slice(&fc.to_le_bytes());
                let copied = copy_bytes(&raw, header, crypt, pad, tail).unwrap();
                assert_eq!(n(8), 0);
                assert_eq!(copied.len(), n(9) as usize);
                let hex: alloc::string::String =
                    copied.iter().map(|b| alloc::format!("{b:02x}")).collect();
                assert_eq!(hex, fields[10], "{line}");
                copies += 1;
            }
        }
        assert_eq!((crypto_cases, copies), (8192, 2304));
    }
}
