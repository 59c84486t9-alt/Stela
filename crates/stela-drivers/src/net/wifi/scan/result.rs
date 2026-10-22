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
    /// Corrected operating channel from DS/HT IEs when resolvable/permitted.
    pub channel: Channel,
    /// Actual receive radio/vector facts; may be a neighboring channel.
    pub observed: RadioStatus,
    /// None when unavailable or operating channel differs from observed RX.
    pub signal_dbm: Option<i8>,
    /// None means absent. Some(empty) is the actual hidden/empty SSID element.
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

fn advertised_channel(parsed: &[(u8, &[u8])]) -> Option<u16> {
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
        Kind::ProbeResponse if header.receiver != local => return Err(Error::WrongPeer),
        _ => (),
    }
    if frame.radio.band == Band::Ghz6 {
        return Err(Error::Unsupported("6GHz/RNR scan result"));
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
    let advertised = advertised_channel(&parsed);
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
            None if observed.band == Band::Ghz2 => return Err(Error::Regulatory),
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
        for _band in [Band::Ghz2, Band::Ghz5] {
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
                    let channel = advertised_channel(&elements(&ies).unwrap())
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
}
