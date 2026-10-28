// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Bounded ordinary raw-802.11 receive descriptors. These are observations,
//! not association/key-generation, authenticated integrity or replay receipts.
use super::identity::Chip;
use crate::{
    bytes::get_le32,
    net::wifi::{Bandwidth, Encoding, RxRate},
};
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    TooLarge,
    WrongPacketType,
    UnsupportedBandIndex,
    UnsupportedTranslation,
    InvalidGroupLayout,
    AmsduError,
    MaximumLengthError,
    InvalidHeaderLength,
    UnsupportedFragment,
    /// A P-RXV rate `mt7925_mac_fill_rx_rate` refuses; Linux drops the frame.
    InvalidRate,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek RX descriptor: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Retained raw hardware security observations. Even `decrypted` plus no ICV
/// error does not establish a current installed key or authenticated integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Security {
    pub mode: u8,
    pub key_index: u8,
    pub cipher_mismatch: bool,
    pub cipher_length_mismatch: bool,
    pub icv_error: bool,
    pub tkip_mic_error: bool,
    pub security_done: bool,
    pub decrypted: bool,
    pub iv_stripped: bool,
    pub mic_stripped: bool,
    /// Source status.iv order: most significant PN byte first. Only supplied
    /// when the actual decrypted cipher uses PN and group 1 is present.
    pub packet_number_be: Option<[u8; 6]>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Band {
    Ghz2,
    Ghz5,
    Ghz6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel {
    pub encoded: u8,
    pub band: Band,
    /// Source encoding decoded without its u8 wrap. Regulatory/channel policy
    /// must validate this actual observed channel before admitting a packet.
    pub number: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Amsdu {
    pub raw_format: u8,
    pub first: bool,
    pub last: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signal {
    /// Raw RCPI is retained even when source dBm conversion is nonnegative.
    pub rcpi: [u8; 4],
    pub dbm: [i8; 4],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groups {
    pub four: Option<Range<usize>>,
    pub one: Option<Range<usize>>,
    pub two: Option<Range<usize>>,
    pub three: Option<Range<usize>>,
    pub five: Option<Range<usize>>,
}

pub struct Decoded<'a> {
    pub chip: Chip,
    pub raw: &'a [u8],
    pub base: [u32; 8],
    pub base_words: u8,
    pub declared_length: u16,
    pub groups: Groups,
    pub wcid: u16,
    pub unicast_to_me: bool,
    pub channel: Channel,
    pub security: Security,
    pub fcs_error: bool,
    pub only_monitor: bool,
    pub timestamp_low: Option<u32>,
    /// Raw NON_AMPDU observation; source aggregate details additionally require
    /// the actual group-2 timestamp. No reorder/aggregate identifier is invented.
    pub ampdu: bool,
    pub fragment: bool,
    pub amsdu: Option<Amsdu>,
    pub signal: Option<Signal>,
    /// Full source group-3/5 bytes remain available through groups/raw; these
    /// first raw P-RXV words fit the canonical compact rate envelope.
    pub rxv: Option<[u32; 4]>,
    /// The MT7925 P-RXV rate. MT7921/MT7922 vectors are left undecoded: their
    /// layout is `mt76_connac2_mac_fill_rx_rate`'s, which is not implemented.
    pub rate: Option<RxRate>,
    pub header_gap: usize,
    /// Actual ordinary MPDU bytes after RXD groups and hardware header offset;
    /// A-MSDU still contains the device's two-byte pad after its MAC header.
    pub payload: &'a [u8],
}
fn word(bytes: &[u8], at: usize) -> Result<u32, Error> {
    get_le32(bytes, at).ok_or(Error::Truncated)
}
fn group(at: &mut usize, bytes: usize, total: usize) -> Result<Range<usize>, Error> {
    let end = at
        .checked_add(bytes)
        .filter(|&end| end < total)
        .ok_or(Error::Truncated)?;
    let range = *at..end;
    *at = end;
    Ok(range)
}

/// Decode only the source ordinary raw-802.11 profile. Header translation
/// requires an actual reverse codec and is explicitly refused. Bounds are
/// checked before every optional group read, including malformed combinations.
/// Caller retains actual completed DMA/drop/association provenance separately.
pub fn decode(chip: Chip, bytes: &[u8]) -> Result<Decoded<'_>, Error> {
    if bytes.len() > 16 * 1024 {
        return Err(Error::TooLarge);
    }
    let connac3 = chip == Chip::Mt7925;
    let base_words = if connac3 { 8 } else { 6 };
    let mut base = [0; 8];
    for (i, value) in base.iter_mut().enumerate().take(base_words) {
        *value = word(bytes, i * 4)?;
    }
    let [r0, r1, r2, r3, r4, ..] = base;
    let kind = (r0 >> 27) & 31;
    let normal_mcu = kind == 7 && (r0 >> 16) & 15 == 1;
    let normal_sw = connac3 && ((r0 >> 16) & 0x380f) == 0x3801;
    if kind != 2 && !normal_mcu && !normal_sw {
        return Err(Error::WrongPacketType);
    }
    if !connac3 && r1 & (1 << 28) != 0 {
        return Err(Error::UnsupportedBandIndex);
    }
    if r2 & (1 << 23) != 0 {
        return Err(Error::AmsduError);
    }
    if r2 & (1 << 24) != 0 {
        return Err(Error::MaximumLengthError);
    }
    if r2 & (1 << if connac3 { 7 } else { 13 }) != 0 {
        return Err(Error::UnsupportedTranslation);
    }
    let group_bits = (r1 >> if connac3 { 16 } else { 11 }) & 31;
    if group_bits & 16 != 0 && group_bits & 4 == 0 {
        return Err(Error::InvalidGroupLayout);
    }
    let mut at = base_words * 4;
    let four = if group_bits & 8 != 0 {
        Some(group(&mut at, 16, bytes.len())?)
    } else {
        None
    };
    let one = if group_bits & 1 != 0 {
        Some(group(&mut at, 16, bytes.len())?)
    } else {
        None
    };
    let two = if group_bits & 2 != 0 {
        Some(group(&mut at, if connac3 { 16 } else { 8 }, bytes.len())?)
    } else {
        None
    };
    let three = if group_bits & 4 != 0 {
        Some(group(&mut at, if connac3 { 16 } else { 8 }, bytes.len())?)
    } else {
        None
    };
    let five = if group_bits & 16 != 0 {
        Some(group(&mut at, if connac3 { 96 } else { 72 }, bytes.len())?)
    } else {
        None
    };
    let padding = if connac3 {
        (r2 >> 13) & 7
    } else {
        (r2 >> 14) & 3
    } as usize
        * 2;
    let header_gap = at
        .checked_add(padding)
        .filter(|&gap| gap < bytes.len())
        .ok_or(Error::Truncated)?;
    let mode = if connac3 {
        (r2 >> 16) & 31
    } else {
        (r1 >> 16) & 31
    } as u8;
    let mismatch = r1 & (1 << 23) != 0;
    let length_mismatch = r1 & (1 << 24) != 0;
    let decrypted = mode != 0 && !mismatch && !length_mismatch;
    let pn_cipher = matches!(mode, 2 | 3 | 4 | 9 | 10 | 11 | 12);
    let packet_number_be = if decrypted && pn_cipher {
        one.as_ref()
            .map(|range| core::array::from_fn(|i| bytes[range.start + 5 - i]))
    } else {
        None
    };
    let security = Security {
        mode,
        key_index: ((r1 >> 21) & 3) as u8,
        cipher_mismatch: mismatch,
        cipher_length_mismatch: length_mismatch,
        icv_error: r1 & (1 << 25) != 0,
        tkip_mic_error: r1 & (1 << 26) != 0,
        security_done: r1 & (1 << 31) != 0,
        decrypted,
        iv_stripped: decrypted,
        mic_stripped: decrypted,
        packet_number_be,
    };
    let timestamp_low = two
        .as_ref()
        .map(|range| word(bytes, range.start))
        .transpose()?;
    let rxv = three
        .as_ref()
        .map(|range| {
            let mut values = [0; 4];
            for (i, value) in values
                .iter_mut()
                .enumerate()
                .take(if connac3 { 4 } else { 2 })
            {
                *value = word(bytes, range.start + i * 4)?;
            }
            Ok(values)
        })
        .transpose()?;
    let signal = three
        .as_ref()
        .map(|range| {
            let at = if connac3 {
                range.start + 12
            } else {
                five.as_ref().map_or(range.start + 4, |r| r.start + 24)
            };
            let raw = word(bytes, at)?;
            let rcpi = raw.to_le_bytes();
            // Exact source unsigned FIELD_GET/subtract/divide then s8 narrowing:
            // odd negative values round down, so signed (rcpi-220)/2 is incorrect.
            let dbm = rcpi.map(|value| (i16::from(value / 2) - 110) as i8);
            Ok(Signal { rcpi, dbm })
        })
        .transpose()?;
    let encoded = ((r3 >> 8) & 255) as u8;
    let channel = if encoded > 180 {
        Channel {
            encoded,
            band: Band::Ghz6,
            number: u16::from(encoded - 181) * 4 + 1,
        }
    } else if encoded > 14 {
        Channel {
            encoded,
            band: Band::Ghz5,
            number: u16::from(encoded),
        }
    } else {
        Channel {
            encoded,
            band: Band::Ghz2,
            number: u16::from(encoded),
        }
    };
    let rate = match rxv {
        Some(words) if connac3 => Some(rate(&words, channel.band)?),
        _ => None,
    };
    let amsdu = match (r4 & 3) as u8 {
        0 => None,
        raw_format => Some(Amsdu {
            raw_format,
            first: raw_format == 3,
            last: raw_format == 1,
        }),
    };
    Ok(Decoded {
        chip,
        raw: bytes,
        base,
        base_words: base_words as u8,
        declared_length: r0 as u16,
        groups: Groups {
            four,
            one,
            two,
            three,
            five,
        },
        wcid: (r1 & if connac3 { 0xfff } else { 0x3ff }) as u16,
        unicast_to_me: (r3 >> 16) & 3 == 1,
        channel,
        security,
        fcs_error: if connac3 {
            r3 & (1 << 24) != 0
        } else {
            r1 & (1 << 27) != 0
        },
        only_monitor: security.icv_error,
        timestamp_low,
        ampdu: r2 & (1 << 30) == 0,
        fragment: r2 & (1 << 27) != 0,
        amsdu,
        signal,
        rxv,
        rate,
        header_gap,
        payload: &bytes[header_gap..],
    })
}

/// `mt76_rates` hardware values, CCK then OFDM, as `mt76_get_rate` searches
/// them. The 5 and 6 GHz bands hold only the OFDM ones.
const LEGACY_RATES: [u8; 12] = [0, 1, 2, 3, 11, 15, 10, 14, 9, 13, 8, 12];

/// Linux `mt76_get_rate`: the band's bitrate index, or 0 when none matches.
fn legacy_index(band: Band, index: u8, cck: bool) -> u8 {
    let (rates, start, index) = match (band, cck) {
        // Bit 2 selects the short preamble.
        (Band::Ghz2, true) => (&LEGACY_RATES[..], 0, index & !4),
        (Band::Ghz2, false) => (&LEGACY_RATES[..], 4, index),
        (_, true) => return 0,
        (_, false) => (&LEGACY_RATES[4..], 0, index),
    };
    rates
        .iter()
        .skip(start)
        .position(|&rate| rate == index)
        .map_or(0, |at| (start + at) as u8)
}

/// `legacy_index` for a band as the shared radio status names it.
pub(crate) fn legacy_rate_index(band: crate::net::wifi::Band, index: u8, cck: bool) -> u8 {
    use crate::net::wifi::Band as Radio;
    let band = match band {
        Radio::Ghz2 => Band::Ghz2,
        Radio::Ghz5 => Band::Ghz5,
        Radio::Ghz6 => Band::Ghz6,
    };
    legacy_index(band, index, cck)
}

/// Linux `mt7925_mac_fill_rx_rate` over P-RXV words 0 and 2.
fn rate(rxv: &[u32; 4], band: Band) -> Result<RxRate, Error> {
    let (v0, v2) = (rxv[0], rxv[2]);
    let index = (v0 & 0x7f) as u8;
    let nss = ((v0 >> 7) & 15) as u8 + 1;
    let gi = ((v2 >> 3) & 3) as u8;
    let mode = ((v2 >> 11) & 15) as u8;
    let mut rate = RxRate {
        index,
        stbc: ((v2 >> 9) & 3) as u8,
        ..RxRate::default()
    };
    match mode {
        // CCK and OFDM.
        0 | 1 => rate.index = legacy_index(band, index, mode == 0),
        // HT and HT greenfield.
        2 | 3 if index <= 31 => rate.encoding = Encoding::Ht,
        4 if index <= 11 => {
            rate.encoding = Encoding::Vht;
            rate.nss = nss;
        }
        // HE SU, extended-range SU, trigger-based and MU.
        8..=11 => {
            rate.encoding = Encoding::He;
            rate.nss = nss;
            rate.index = index & 15;
            rate.gi = if gi <= 2 { gi } else { 0 };
            rate.he_dcm = v2 & (1 << 5) != 0;
        }
        // EHT SU, trigger-based and MU.
        13..=15 => {
            rate.encoding = Encoding::Eht;
            rate.nss = nss;
            rate.index = index & 15;
            rate.gi = if gi <= 2 { gi } else { 0 };
        }
        _ => return Err(Error::InvalidRate),
    }
    rate.bandwidth = match v2 & 7 {
        0 => Bandwidth::Mhz20,
        // Linux tests the mode against HE_EXT_SU bitwise, and the raw rate
        // field's ER_SU_106T bit.
        1 if mode & 9 != 0 && index & (1 << 5) != 0 => Bandwidth::HeRu106,
        1 => Bandwidth::Mhz40,
        2 => Bandwidth::Mhz80,
        3 => Bandwidth::Mhz160,
        // The vector reports 320 MHz in two positions.
        4 | 5 => Bandwidth::Mhz320,
        _ => return Err(Error::InvalidRate),
    };
    rate.short_gi = mode < 8 && gi != 0;
    Ok(rate)
}
impl Decoded<'_> {
    /// `header_bytes` must come from the shared actual 802.11 header parser
    /// over this payload, not RXD's translated-header hint. It is independently
    /// bounded here before removing exactly the source A-MSDU two-byte pad.
    /// This does not reorder A-MSDU/AMPDU, reinsert fragment crypto headers,
    /// authenticate security metadata or associate it with an installed key.
    pub fn normalize(&self, header_bytes: usize) -> Result<Vec<u8>, Error> {
        if self.fragment {
            return Err(Error::UnsupportedFragment);
        }
        if !(10..=62).contains(&header_bytes)
            || !header_bytes.is_multiple_of(2)
            || header_bytes > self.payload.len()
        {
            return Err(Error::InvalidHeaderLength);
        }
        if self.amsdu.is_none() {
            return Ok(self.payload.to_vec());
        }
        if header_bytes
            .checked_add(2)
            .is_none_or(|n| n > self.payload.len())
        {
            return Err(Error::Truncated);
        }
        let mut normalized = Vec::with_capacity(self.payload.len() - 2);
        normalized.extend_from_slice(&self.payload[..header_bytes]);
        normalized.extend_from_slice(&self.payload[header_bytes + 2..]);
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn packet(chip: Chip, groups: u32, mode: u8, format: u8, offset: u8) -> Vec<u8> {
        let c3 = chip == Chip::Mt7925;
        let base = if c3 { 32 } else { 24 };
        let sizes = [
            (8, 16),
            (1, 16),
            (2, if c3 { 16 } else { 8 }),
            (4, if c3 { 16 } else { 8 }),
            (16, if c3 { 96 } else { 72 }),
        ];
        let gap = base
            + sizes
                .iter()
                .filter(|(bit, _)| groups & bit != 0)
                .map(|(_, bytes)| bytes)
                .sum::<usize>()
            + usize::from(offset) * 2;
        let mut bytes = vec![0; gap + 24 + 40 + if format != 0 { 2 } else { 0 }];
        let len = bytes.len() as u32;
        put(&mut bytes, 0, (2 << 27) | len);
        put(
            &mut bytes,
            4,
            7 | (groups << if c3 { 16 } else { 11 })
                | (2 << 21)
                | if c3 { 0 } else { u32::from(mode) << 16 },
        );
        put(
            &mut bytes,
            8,
            if c3 {
                u32::from(mode) << 16 | u32::from(offset) << 13
            } else {
                u32::from(offset) << 14
            },
        );
        put(&mut bytes, 12, (36 << 8) | (1 << 16));
        put(&mut bytes, 16, u32::from(format));
        let mut at = base;
        for (bit, size) in sizes {
            if groups & bit == 0 {
                continue;
            }
            for i in 0..size {
                bytes[at + i] = (bit * 9 + i as u32) as u8;
            }
            if bit == 4 && c3 {
                // A 1 Mb/s CCK P-RXV rate.
                put(&mut bytes, at, 0);
                put(&mut bytes, at + 8, 0);
            }
            at += size;
        }
        for i in 0..24 {
            bytes[gap + i] = (i * 7) as u8;
        }
        bytes[gap] = 8;
        bytes[gap + 1] = 0;
        let payload = gap
            + 24
            + if format != 0 {
                bytes[gap + 24] = 0xff;
                bytes[gap + 25] = 0xfe;
                2
            } else {
                0
            };
        for i in 0..40 {
            bytes[payload + i] = i as u8;
        }
        bytes
    }
    #[test]
    fn every_valid_optional_group_combination_retains_boundaries_and_payload_padding() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for groups in 0..32 {
                if groups & 16 != 0 && groups & 4 == 0 {
                    continue;
                }
                for format in 0..4 {
                    for offset in 0..if chip == Chip::Mt7925 { 8 } else { 4 } {
                        let bytes = packet(chip, groups, 4, format, offset);
                        let decoded = decode(chip, &bytes).unwrap();
                        assert_eq!(decoded.raw, bytes);
                        assert_eq!(decoded.wcid, 7);
                        assert!(decoded.unicast_to_me);
                        assert_eq!(decoded.security.key_index, 2);
                        assert!(decoded.security.decrypted);
                        let normalized = decoded.normalize(24).unwrap();
                        assert_eq!(normalized.len(), 64);
                        assert_eq!(&normalized[24..], &(0..40).collect::<Vec<u8>>());
                        assert_eq!(&normalized[..24], &decoded.payload[..24]);
                        assert_eq!(decoded.amsdu.is_some(), format != 0);
                        if let Some(one) = &decoded.groups.one {
                            assert_eq!(
                                decoded.security.packet_number_be.unwrap(),
                                core::array::from_fn::<_, 6, _>(|i| bytes[one.start + 5 - i])
                            );
                        } else {
                            assert!(decoded.security.packet_number_be.is_none());
                        }
                        assert_eq!(decoded.timestamp_low.is_some(), groups & 2 != 0);
                        assert_eq!(decoded.rxv.is_some(), groups & 4 != 0);
                        if let Some(signal) = decoded.signal {
                            for i in 0..4 {
                                assert_eq!(
                                    signal.dbm[i],
                                    (i16::from(signal.rcpi[i] / 2) - 110) as i8
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn p_rxv_rates_decode_like_mt7925_mac_fill_rx_rate() {
        // (mode, raw rate, NSTS, frame mode, GI, band) and the result.
        let rate = |mode: u32, index: u32, nsts: u32, bw: u32, gi: u32, band| {
            let v2 = mode << 11 | 1 << 9 | gi << 3 | bw;
            super::rate(&[index | nsts << 7, 0, v2, 0], band)
        };
        let legacy = |index| RxRate {
            index,
            stbc: 1,
            ..RxRate::default()
        };
        // Long- and short-preamble 2 Mb/s CCK; CCK outside 2.4 GHz.
        assert_eq!(rate(0, 1, 0, 0, 0, Band::Ghz2), Ok(legacy(1)));
        assert_eq!(rate(0, 5, 0, 0, 0, Band::Ghz2), Ok(legacy(1)));
        assert_eq!(rate(0, 1, 0, 0, 0, Band::Ghz5), Ok(legacy(0)));
        // 6 and 54 Mb/s OFDM by band.
        assert_eq!(rate(1, 11, 0, 0, 0, Band::Ghz2), Ok(legacy(4)));
        assert_eq!(rate(1, 12, 0, 0, 0, Band::Ghz6), Ok(legacy(7)));
        let ht = rate(2, 15, 1, 1, 1, Band::Ghz5).unwrap();
        assert_eq!(
            (ht.encoding, ht.index, ht.nss, ht.bandwidth, ht.short_gi),
            (Encoding::Ht, 15, 0, Bandwidth::Mhz40, true)
        );
        assert_eq!(rate(3, 32, 0, 0, 0, Band::Ghz5), Err(Error::InvalidRate));
        let vht = rate(4, 9, 1, 2, 0, Band::Ghz5).unwrap();
        assert_eq!(
            (vht.encoding, vht.nss, vht.bandwidth),
            (Encoding::Vht, 2, Bandwidth::Mhz80)
        );
        assert_eq!(rate(4, 12, 0, 0, 0, Band::Ghz5), Err(Error::InvalidRate));
        // Extended-range SU on a 106-tone RU with a 3.2 us GI.
        let he = rate(9, 1 << 5 | 3, 0, 1, 2, Band::Ghz5).unwrap();
        assert_eq!(
            (he.encoding, he.index, he.bandwidth, he.gi, he.short_gi),
            (Encoding::He, 3, Bandwidth::HeRu106, 2, false)
        );
        assert_eq!(rate(8, 7, 0, 3, 3, Band::Ghz6).unwrap().gi, 0);
        let eht = rate(15, 13, 3, 5, 1, Band::Ghz6).unwrap();
        assert_eq!(
            (eht.encoding, eht.index, eht.nss, eht.bandwidth, eht.gi),
            (Encoding::Eht, 13, 4, Bandwidth::Mhz320, 1)
        );
        assert_eq!(rate(5, 0, 0, 0, 0, Band::Ghz5), Err(Error::InvalidRate));
        assert_eq!(rate(1, 11, 0, 6, 0, Band::Ghz5), Err(Error::InvalidRate));
        // A frame whose vector Linux refuses is dropped.
        let mut bytes = packet(Chip::Mt7925, 4, 4, 0, 0);
        put(&mut bytes, 32, 7);
        put(&mut bytes, 32 + 8, 5 << 11);
        assert_eq!(decode(Chip::Mt7925, &bytes).err(), Some(Error::InvalidRate));
        put(&mut bytes, 32 + 8, 4 << 11 | 2);
        let decoded = decode(Chip::Mt7925, &bytes).unwrap();
        assert_eq!(decoded.rate.unwrap().bandwidth, Bandwidth::Mhz80);
        assert_eq!(
            decode(Chip::Mt7921, &packet(Chip::Mt7921, 4, 4, 0, 0))
                .unwrap()
                .rate,
            None
        );
    }
    #[test]
    fn every_short_group_and_padding_boundary_refuses_before_reading() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let bytes = packet(chip, 31, 4, 0, if chip == Chip::Mt7925 { 7 } else { 3 });
            let gap = decode(chip, &bytes).unwrap().header_gap;
            for n in 0..=gap {
                assert!(decode(chip, &bytes[..n]).is_err(), "{chip:?} at {n}");
            }
            assert!(matches!(
                decode(chip, &vec![0; 16385]),
                Err(Error::TooLarge)
            ));
            assert!(matches!(
                decode(chip, &packet(chip, 16, 4, 0, 0)),
                Err(Error::InvalidGroupLayout)
            ));
        }
    }
    #[test]
    fn security_flags_never_synthesize_integrity_key_or_replay_success() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for mode in 0..32 {
                for flags in 0u32..32 {
                    let mut bytes = packet(chip, 1, mode, 0, 0);
                    let r1 = word(&bytes, 4).unwrap() | ((flags & 15) << 23) | ((flags >> 4) << 31);
                    put(&mut bytes, 4, r1);
                    let decoded = decode(chip, &bytes).unwrap();
                    let decrypted = mode != 0 && flags & 3 == 0;
                    assert_eq!(decoded.security.decrypted, decrypted);
                    assert_eq!(decoded.security.iv_stripped, decrypted);
                    assert_eq!(decoded.security.icv_error, flags & 4 != 0);
                    assert_eq!(decoded.only_monitor, flags & 4 != 0);
                    assert_eq!(decoded.security.tkip_mic_error, flags & 8 != 0);
                    assert_eq!(decoded.security.security_done, flags & 16 != 0);
                    assert_eq!(
                        decoded.security.packet_number_be.is_some(),
                        decrypted && matches!(mode, 2 | 3 | 4 | 9 | 10 | 11 | 12)
                    );
                }
            }
        }
    }
    #[test]
    fn translated_fragment_and_error_profiles_remain_explicit_and_fcs_is_retained() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for (flag, error) in [
                (23, Error::AmsduError),
                (24, Error::MaximumLengthError),
                (
                    if chip == Chip::Mt7925 { 7 } else { 13 },
                    Error::UnsupportedTranslation,
                ),
            ] {
                let mut bytes = packet(chip, 0, 0, 0, 0);
                let r2 = word(&bytes, 8).unwrap() | (1 << flag);
                put(&mut bytes, 8, r2);
                assert!(matches!(decode(chip, &bytes), Err(e) if e == error));
            }
            let mut bytes = packet(chip, 0, 0, 0, 0);
            let r2 = word(&bytes, 8).unwrap() | (1 << 27);
            put(&mut bytes, 8, r2);
            assert_eq!(
                decode(chip, &bytes).unwrap().normalize(24),
                Err(Error::UnsupportedFragment)
            );
            let mut bytes = packet(chip, 0, 0, 0, 0);
            let at = if chip == Chip::Mt7925 { 12 } else { 4 };
            let word =
                word(&bytes, at).unwrap() | (1 << if chip == Chip::Mt7925 { 24 } else { 27 });
            put(&mut bytes, at, word);
            assert!(decode(chip, &bytes).unwrap().fcs_error);
        }
    }
    #[test]
    fn packet_classification_and_channel_encoding_follow_actual_chip_layout_without_wrapping() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for kind in 0..32u32 {
                for flag in [0, 1, 2] {
                    let mut bytes = packet(chip, 0, 0, 0, 0);
                    put(&mut bytes, 0, kind << 27 | flag << 16);
                    let sw = chip == Chip::Mt7925 && (((kind << 11) | flag) & 0x380f) == 0x3801;
                    assert_eq!(
                        decode(chip, &bytes).is_ok(),
                        kind == 2 || (kind == 7 && flag == 1) || sw
                    );
                }
            }
            for (encoded, band, number) in [
                (0, Band::Ghz2, 0),
                (14, Band::Ghz2, 14),
                (36, Band::Ghz5, 36),
                (180, Band::Ghz5, 180),
                (181, Band::Ghz6, 1),
                (239, Band::Ghz6, 233),
                (255, Band::Ghz6, 297),
            ] {
                let mut bytes = packet(chip, 0, 0, 0, 0);
                put(&mut bytes, 12, u32::from(encoded) << 8);
                assert_eq!(
                    decode(chip, &bytes).unwrap().channel,
                    Channel {
                        encoded,
                        band,
                        number
                    }
                );
            }
        }
    }

    #[test]
    #[ignore = "requires freshly built unchanged full Linux RX helper oracle"]
    fn unchanged_full_receive_helpers_match_flags_pn_groups_rcpi_and_normalized_bytes() {
        extern crate std;
        let oracle = std::path::PathBuf::from(
            std::env::var_os("STELA_MT792X_RX_ORACLE").expect("STELA_MT792X_RX_ORACLE"),
        );
        let run = oracle.join(alloc::format!("run-{}", std::process::id()));
        std::fs::create_dir(&run).unwrap();
        for (chip, name, executable) in [
            (Chip::Mt7921, "7921", "rx7921"),
            (Chip::Mt7922, "7922", "rx7921"),
            (Chip::Mt7925, "7925", "rx7925"),
        ] {
            let mut input = Vec::new();
            let mut expected = Vec::new();
            let mut cases = 0;
            for groups in 0..32 {
                if groups & 16 != 0 && groups & 4 == 0 {
                    continue;
                }
                for n in 0..128u32 {
                    let mode = (n % 13) as u8;
                    let format = (n % 4) as u8;
                    let offset = (n % if chip == Chip::Mt7925 { 8 } else { 4 }) as u8;
                    let mut bytes = packet(chip, groups, mode, format, offset);
                    let wcid = n % 20;
                    let r1 = word(&bytes, 4).unwrap()
                        & !(if chip == Chip::Mt7925 { 0xfff } else { 0x3ff });
                    put(&mut bytes, 4, r1 | wcid | (((n / 4) & 15) << 23));
                    let at = if chip == Chip::Mt7925 { 12 } else { 4 };
                    let fcs = word(&bytes, at).unwrap()
                        | ((n & 1) << if chip == Chip::Mt7925 { 24 } else { 27 });
                    put(&mut bytes, at, fcs);
                    let encoded = [1, 14, 36, 180, 181, 239][n as usize % 6];
                    let r3 = word(&bytes, 12).unwrap() & !0xff00;
                    put(&mut bytes, 12, r3 | (encoded << 8));
                    let decoded = decode(chip, &bytes).unwrap();
                    let mut flags = u32::from(decoded.only_monitor)
                        | (u32::from(decoded.fcs_error) << 1)
                        | (u32::from(decoded.security.tkip_mic_error) << 2);
                    if decoded.security.decrypted {
                        flags |= 8 | 16 | 32 | 64;
                    }
                    if decoded.timestamp_low.is_some() {
                        flags |= 128;
                        if decoded.ampdu {
                            flags |= 256;
                        }
                    }
                    let payload = decoded.normalize(24).unwrap();
                    let amsdu = decoded.amsdu;
                    for value in [
                        flags,
                        (decoded.header_gap + usize::from(amsdu.is_some()) * 2) as u32,
                        decoded.timestamp_low.unwrap_or(0),
                        match decoded.channel.band {
                            Band::Ghz2 => 0,
                            Band::Ghz5 => 1,
                            Band::Ghz6 => 2,
                        },
                        u32::from(decoded.channel.number),
                        wcid,
                        1,
                        u32::from(amsdu.is_some()),
                        u32::from(amsdu.is_some_and(|a| a.first)),
                        u32::from(amsdu.is_some_and(|a| a.last)),
                        payload.len() as u32,
                    ] {
                        expected.extend_from_slice(&value.to_le_bytes());
                    }
                    expected
                        .extend_from_slice(&decoded.security.packet_number_be.unwrap_or([0; 6]));
                    expected.extend_from_slice(
                        &decoded
                            .signal
                            .map(|s| s.dbm.map(|v| v as u8))
                            .unwrap_or([0; 4]),
                    );
                    expected.extend_from_slice(&payload);
                    for value in [bytes.len() as u32, 24] {
                        input.extend_from_slice(&value.to_le_bytes());
                    }
                    input.extend_from_slice(&bytes);
                    cases += 1;
                }
            }
            assert_eq!(cases, 3072);
            let input_path = run.join(alloc::format!("mt{name}-inputs.bin"));
            std::fs::write(&input_path, &input).unwrap();
            let result = std::process::Command::new(oracle.join(executable))
                .arg(input_path)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{name}: {}",
                std::string::String::from_utf8_lossy(&result.stderr)
            );
            std::fs::write(
                run.join(alloc::format!("mt{name}-output.bin")),
                &result.stdout,
            )
            .unwrap();
            assert_eq!(result.stdout.len(), expected.len());
            for (case, (actual, expected)) in result
                .stdout
                .as_chunks::<118>()
                .0
                .iter()
                .zip(expected.as_chunks::<118>().0.iter())
                .enumerate()
            {
                assert_eq!(actual, expected, "chip {name} case {case}");
            }
        }
    }
}
