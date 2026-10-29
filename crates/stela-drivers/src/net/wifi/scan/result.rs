// SPDX-License-Identifier: GPL-2.0-only
// Adapted from Linux net/mac80211/scan.c and net/wireless/scan.c.
// Copyright 2003 Jouni Malinen; 2008 Johannes Berg;
// 2013-2015 Intel Mobile Communications GmbH; 2016-2017 Intel Deutschland GmbH;
// 2018-2026 Intel Corporation. Full source notices in THIRD_PARTY.md.
//! Observed beacon/probe responses, not authenticated or connectable BSS claims.

use super::{Error, Policy, Ticket};
use crate::net::{
    Mac,
    wifi::{Band, Channel, RadioStatus, frame::Mpdu},
};
use alloc::vec::Vec;

const FIXED_LENGTH: usize = 36;
const MAX_ELEMENTS: usize = 2300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Beacon,
    ProbeResponse,
}

#[derive(Clone, Debug)]
pub struct Bss {
    pub ticket: Ticket,
    pub kind: Kind,
    pub bssid: Mac,
    pub transmitter: Mac,
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capabilities: u16,
    /// Corrected operating channel from DS/HT or 6GHz HE Operation IEs when permitted.
    pub channel: Channel,
    /// Receive radio/vector facts; may be a neighboring channel.
    pub observed: RadioStatus,
    /// None when unavailable or operating channel differs from observed RX.
    pub signal_dbm: Option<i8>,
    /// None means absent. Some(empty) is the hidden/empty SSID element.
    pub ssid: Option<Vec<u8>>,
    /// Complete received TLVs, including unknown/advanced ones. Retention does
    /// not declare the native association/driver capable of those modes.
    pub elements: Vec<u8>,
}

pub(super) fn elements(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut output = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 {
            return Err(Error::Invalid("truncated scan IE header"));
        }
        let length = usize::from(bytes[1]);
        let data = bytes
            .get(2..2 + length)
            .ok_or(Error::Invalid("truncated scan IE data"))?;
        output.push((bytes[0], data));
        bytes = &bytes[2 + length..];
    }
    Ok(output)
}

fn advertised_channel(parsed: &[(u8, &[u8])], band: Band) -> Option<u16> {
    if band == Band::Ghz6 {
        // cfg80211 ignores DS/HT on this band and uses the first HE Operation
        // extension only after its complete optional-field size is validated.
        const VHT_INFORMATION: u32 = 0x0000_4000;
        const COHOSTED_BSSID: u32 = 0x0000_8000;
        const SIX_GHZ_INFORMATION: u32 = 0x0002_0000;
        let data = parsed
            .iter()
            .find_map(|(id, data)| (*id == 255 && data.first() == Some(&36)).then_some(*data))?;
        let parameters = u32::from_le_bytes(data.get(1..5)?.try_into().unwrap());
        let optional = 7
            + 3 * usize::from(parameters & VHT_INFORMATION != 0)
            + usize::from(parameters & COHOSTED_BSSID != 0);
        if parameters & SIX_GHZ_INFORMATION == 0 || data.len() < optional + 5 {
            return None;
        }
        return Some(u16::from(data[optional]));
    }
    let first = |id| {
        parsed
            .iter()
            .find(|element| element.0 == id)
            .map(|element| element.1)
    };
    first(3)
        .filter(|data| data.len() == 1)
        .map(|data| u16::from(data[0]))
        .or_else(|| {
            first(61)
                .filter(|data| data.len() >= 22)
                .map(|data| u16::from(data[0]))
        })
}

pub(super) fn parse(
    ticket: Ticket,
    frame: &Mpdu,
    local: Mac,
    policy: &mut impl Policy,
) -> Result<Bss, Error> {
    let header = frame.header();
    if frame.fcs_error || frame.monitor_only {
        return Err(Error::Integrity);
    }
    if frame.aggregation != crate::net::wifi::Aggregation::default()
        || header.protected()
        || header.fragmented()
        || header.length != 24
        || header.control & 0x0300 != 0
    {
        return Err(Error::Unsupported(
            "protected/fragmented/nonstandard scan management",
        ));
    }
    let kind = match header.control & 0x00fc {
        0x80 => Kind::Beacon,
        0x50 => Kind::ProbeResponse,
        _ => return Err(Error::Unsupported("non-beacon/probe response")),
    };
    match kind {
        Kind::Beacon if header.receiver != Mac::BROADCAST => return Err(Error::WrongPeer),
        Kind::ProbeResponse
            if header.receiver != local
                && !(frame.radio.band == Band::Ghz6 && header.receiver == Mac::BROADCAST) =>
        {
            // mac80211 accepts unsolicited broadcast probe responses on 6GHz;
            // other bands still need the separately unimplemented OCE flag.
            return Err(Error::WrongPeer);
        }
        _ => (),
    }
    let observed = Channel {
        band: frame.radio.band,
        number: frame.radio.channel,
        frequency_mhz: frame.radio.frequency_mhz,
    };
    if policy.lookup_channel(observed.band, observed.number) != Some(observed)
        || !policy.allow_receive(observed)
    {
        return Err(Error::Regulatory);
    }
    let bytes = frame.bytes();
    if bytes.len() < FIXED_LENGTH || bytes.len() - FIXED_LENGTH > MAX_ELEMENTS {
        return Err(Error::Invalid("scan fixed fields/IE length"));
    }
    let bssid = Mac(bytes[16..22].try_into().unwrap());
    let transmitter = header.transmitter.ok_or(Error::WrongPeer)?;
    if bssid.is_multicast()
        || bssid.0 == [0; 6]
        || transmitter.is_multicast()
        || transmitter.0 == [0; 6]
    {
        return Err(Error::WrongPeer);
    }
    let ies = &bytes[FIXED_LENGTH..];
    let mut ssid = None;
    let parsed = elements(ies)?;
    for &(id, data) in &parsed {
        if id == 0 {
            if ssid.is_some() || data.len() > 32 {
                return Err(Error::Invalid("scan SSID"));
            }
            ssid = Some(data.to_vec());
        }
    }
    // cfg80211_get_ies_channel_number prefers the first DS element if its
    // length is exactly one, then the first complete 22-byte HT operation.
    let advertised = advertised_channel(&parsed, observed.band);
    let channel = if let Some(number) = advertised {
        match policy.lookup_channel(observed.band, number) {
            Some(channel)
                if channel.band == observed.band
                    && channel.number == number
                    && policy.allow_receive(channel) =>
            {
                channel
            }
            Some(_) => return Err(Error::Regulatory),
            None if matches!(observed.band, Band::Ghz2 | Band::Ghz6) => {
                return Err(Error::Regulatory);
            }
            // Linux ignores unknown advertised channels on 5GHz only.
            None => observed,
        }
    } else {
        observed
    };
    Ok(Bss {
        ticket,
        kind,
        bssid,
        transmitter,
        timestamp: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        beacon_interval: u16::from_le_bytes(bytes[32..34].try_into().unwrap()),
        capabilities: u16::from_le_bytes(bytes[34..36].try_into().unwrap()),
        channel,
        observed: frame.radio.clone(),
        signal_dbm: if channel == observed {
            frame.radio.signal_dbm
        } else {
            None
        },
        ssid,
        elements: ies.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sha2::{Digest, Sha256};

    #[test]
    fn channel_element_precedence_matches_full_unchanged_linux_oracle() {
        let mut hash = Sha256::new();
        for band in [Band::Ghz2, Band::Ghz5] {
            for variant in 0..8 {
                for value in 0..=u8::MAX {
                    let mut ies = Vec::new();
                    let mut add = |id, count: usize, first| {
                        ies.extend_from_slice(&[id, count as u8]);
                        let mut data = vec![0; count];
                        if let Some(byte) = data.first_mut() {
                            *byte = first;
                        }
                        ies.extend_from_slice(&data);
                    };
                    if variant == 0 || variant == 6 {
                        add(3, 1, value);
                    }
                    if variant == 1 {
                        add(3, 0, 0);
                    }
                    if variant == 2 || variant == 3 {
                        add(3, 2, value);
                    }
                    if variant == 3 {
                        add(3, 1, value);
                    }
                    if variant < 6 {
                        add(
                            61,
                            match variant {
                                2 => 21,
                                5 => 23,
                                _ => 22,
                            },
                            if variant == 0 || variant == 3 {
                                value ^ 0x5a
                            } else {
                                value
                            },
                        );
                    }
                    let channel = advertised_channel(&elements(&ies).unwrap(), band)
                        .map_or(-1, |value| value as i16);
                    hash.update(channel.to_le_bytes());
                }
            }
        }
        // tests/reference/wifi_scan_channel_oracle.py: unchanged complete
        // cfg80211_get_ies_channel_number/find-element helpers and iteration,
        // 4096 DS/HT element combinations under ASan/UBSan, 2.4/5GHz only.
        assert_eq!(
            <[u8; 32]>::from(hash.finalize()),
            [
                0x83, 0x04, 0x03, 0x37, 0x73, 0xf7, 0xc4, 0x19, 0x42, 0xd7, 0x93, 0x7e, 0x7e, 0x53,
                0x16, 0x6a, 0xa1, 0x7c, 0x47, 0x89, 0x48, 0xc0, 0xf9, 0x4d, 0x6c, 0xbc, 0xca, 0x46,
                0x42, 0x55, 0xa3, 0xd9,
            ]
        );
    }

    fn he_case(flags: u32, variant: usize, primary: u8) -> Vec<u8> {
        let parameters = (u32::from(flags & 1 != 0) * 0x4000)
            | (u32::from(flags & 2 != 0) * 0x8000)
            | (u32::from(flags & 4 != 0) * 0x20000);
        let mut data = vec![36];
        data.extend_from_slice(&parameters.to_le_bytes());
        data.extend_from_slice(&[0; 2]);
        if flags & 1 != 0 {
            data.extend_from_slice(&[0; 3]);
        }
        if flags & 2 != 0 {
            data.push(0);
        }
        if flags & 4 != 0 {
            data.extend_from_slice(&[primary, 0, 0, 0, 0]);
        }
        if variant == 1 {
            data.pop();
        }
        if variant == 2 {
            data.push(0xa5);
        }
        let mut ies = Vec::new();
        if matches!(variant, 3 | 5) {
            let length = if variant == 3 { 5 } else { 6 };
            ies.extend_from_slice(&[255, length as u8]);
            ies.extend_from_slice(&data[..length]);
        }
        if variant == 4 {
            ies.extend_from_slice(&[3, 1, primary ^ 0x5a, 61, 22, primary ^ 0x33]);
            ies.extend_from_slice(&[0; 21]);
        }
        if variant == 6 {
            data[1..5].copy_from_slice(&(parameters & !0x20000).to_le_bytes());
        }
        if variant == 7 {
            ies.extend_from_slice(&[255, 1, 35]);
        }
        ies.extend_from_slice(&[255, data.len() as u8]);
        ies.extend_from_slice(&data);
        ies
    }

    #[test]
    fn unchanged_six_ghz_channel_selector_checks_all_optional_lengths_and_precedence() {
        let mut hash = Sha256::new();
        for flags in 0..8 {
            for variant in 0..8 {
                for primary in 0..=255 {
                    let bytes = he_case(flags, variant, primary);
                    let parsed = elements(&bytes).unwrap();
                    let actual = advertised_channel(&parsed, Band::Ghz6).unwrap_or(u16::MAX);
                    hash.update(actual.to_le_bytes());
                }
            }
        }
        // Fresh unchanged full cfg80211 selector + HE size/offset helpers,
        // 16,384 cases under ASan/UBSan; receipt under .stela/oracle/scan6-channel.
        assert_eq!(
            <[u8; 32]>::from(hash.finalize()),
            [
                0xca, 0x76, 0xe9, 0x00, 0x4c, 0xb0, 0x91, 0x77, 0xf3, 0x33, 0xae, 0x08, 0xb8, 0x0a,
                0x5d, 0x6c, 0x0f, 0x05, 0x41, 0xdd, 0x18, 0xea, 0xd9, 0x4a, 0xf1, 0x21, 0xac, 0xf9,
                0x8a, 0x12, 0x54, 0x3f
            ]
        );
    }
}
