// SPDX-License-Identifier: GPL-2.0-only
// Linux-derived header layout: Copyright (c) 2001-2003 Jouni Malinen,
// SSH Communications Security Corp; 2005 Devicescape Software, Inc.;
// 2006 Michael Wu; 2013-2014 Intel Mobile Communications GmbH;
// 2016-2017 Intel Deutschland GmbH; 2018-2026 Intel Corporation.
// Header length: Copyright 2007-2009 Johannes Berg;
// 2013-2014 Intel Mobile Communications GmbH; 2017 Intel Deutschland GmbH;
// 2018-2023, 2025-2026 Intel Corporation. See THIRD_PARTY.md.
//! Bounded normalized MPDUs and the pinned Linux header-length rules.

use super::{Aggregation, RadioStatus, security::SecurityStatus};
use crate::net::Mac;
use alloc::vec::Vec;

/// Largest declared VHT MPDU; vendor padding and FCS are not included.
pub const MAX_MPDU: usize = 11_454;
const TYPE: u16 = 0x000c;
const DATA: u16 = 0x0008;
const CONTROL: u16 = 0x0004;
const EXTENSION: u16 = 0x000c;
const QOS: u16 = 0x0080;
pub(crate) const TO_DS: u16 = 0x0100;
pub(crate) const FROM_DS: u16 = 0x0200;
const MORE_FRAGMENTS: u16 = 0x0400;
pub(crate) const PROTECTED: u16 = 0x4000;
const ORDER: u16 = 0x8000;
/// Frame Control type and subtype bits, and the complete values compared.
pub(crate) const TYPE_SUBTYPE: u16 = 0x00fc;
pub(crate) const BLOCK_ACK_REQUEST: u16 = 0x0084;
pub(crate) const DISASSOCIATION: u16 = 0x00a0;
pub(crate) const DEAUTHENTICATION: u16 = 0x00c0;
pub(crate) const ACTION: u16 = 0x00d0;
/// Sequence Control's 12-bit sequence number.
pub(crate) const SEQUENCE_MASK: u16 = 0x0fff;
/// Largest Block Ack windows (Linux `IEEE80211_MAX_AMPDU_BUF_{EHT,HE,HT}`).
pub(crate) const MAX_AMPDU_BUF_EHT: u16 = 1024;
pub(crate) const MAX_AMPDU_BUF_HE: u16 = 256;
pub(crate) const MAX_AMPDU_BUF_HT: u16 = 64;
/// QoS TIDs a station tracks sequence numbers for (Linux `IEEE80211_NUM_TIDS`).
pub(crate) const QOS_TIDS: usize = 16;

/// The sequence number after `sequence`, modulo 4096.
pub(crate) const fn next_sequence(sequence: u16) -> u16 {
    sequence.wrapping_add(1) & SEQUENCE_MASK
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    TooLong,
    ProtocolVersion,
    Unsupported(&'static str),
}

/// Equivalent to Linux `ieee80211_hdrlen`, including control/extension types.
/// This computes wire length; it does not authorize a frame type for delivery.
pub const fn header_len(fc: u16) -> usize {
    match fc & TYPE {
        EXTENSION => 4,
        DATA => {
            let mut length = if fc & (TO_DS | FROM_DS) == TO_DS | FROM_DS {
                30
            } else {
                24
            };
            if fc & QOS != 0 {
                length += 2;
                if fc & ORDER != 0 {
                    length += 4;
                }
            }
            length
        }
        CONTROL => {
            if fc & 0x00e0 == 0x00c0 {
                10
            } else {
                16
            }
        }
        _ => {
            if fc & ORDER != 0 {
                28
            } else {
                24
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub control: u16,
    pub length: usize,
    pub receiver: Mac,
    pub transmitter: Option<Mac>,
    pub sequence: Option<u16>,
    pub fragment: Option<u8>,
    pub tid: Option<u8>,
    pub amsdu: bool,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let fc = u16::from_le_bytes(bytes.get(..2).ok_or(Error::Truncated)?.try_into().unwrap());
        if fc & 3 != 0 {
            return Err(Error::ProtocolVersion);
        }
        let length = header_len(fc);
        if bytes.len() < length {
            return Err(Error::Truncated);
        }
        if fc & TYPE == EXTENSION {
            return Err(Error::Unsupported("extension frame"));
        }
        let mac = |offset| Mac(bytes[offset..offset + 6].try_into().unwrap());
        let sequence = if fc & TYPE == CONTROL {
            None
        } else {
            Some(u16::from_le_bytes(bytes[22..24].try_into().unwrap()))
        };
        let qos = if fc & TYPE == DATA && fc & QOS != 0 {
            let offset = if fc & (TO_DS | FROM_DS) == TO_DS | FROM_DS {
                30
            } else {
                24
            };
            Some(u16::from_le_bytes(
                bytes[offset..offset + 2].try_into().unwrap(),
            ))
        } else {
            None
        };
        Ok(Self {
            control: fc,
            length,
            receiver: mac(4),
            transmitter: (length >= 16).then(|| mac(10)),
            sequence: sequence.map(|value| value >> 4),
            fragment: sequence.map(|value| (value & 15) as u8),
            tid: qos.map(|value| (value & 15) as u8),
            amsdu: qos.is_some_and(|value| value & 0x80 != 0),
        })
    }

    pub const fn protected(&self) -> bool {
        self.control & PROTECTED != 0
    }

    pub const fn fragmented(&self) -> bool {
        self.control & MORE_FRAGMENTS != 0 || matches!(self.fragment, Some(1..=15))
    }

    pub const fn data_present(&self) -> bool {
        self.control & TYPE == DATA && self.control & 0x0040 == 0
    }
}

/// Whole MPDU without FCS or transport padding. Metadata retains vendor facts;
/// construction validates framing, not security or station membership.
#[derive(Clone, Debug)]
pub struct Mpdu {
    bytes: Vec<u8>,
    header: Header,
    pub radio: RadioStatus,
    pub security: SecurityStatus,
    pub aggregation: Aggregation,
    pub fcs_error: bool,
    pub monitor_only: bool,
    pub raw_status: [u32; 4],
}

impl Mpdu {
    pub fn new(
        bytes: Vec<u8>,
        radio: RadioStatus,
        security: SecurityStatus,
    ) -> Result<Self, Error> {
        if bytes.len() > MAX_MPDU {
            return Err(Error::TooLong);
        }
        let header = Header::parse(&bytes)?;
        Ok(Self {
            bytes,
            header,
            radio,
            security,
            aggregation: Aggregation::default(),
            fcs_error: false,
            monitor_only: false,
            raw_status: [0; 4],
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn header_lengths_and_truncations() {
        for fc in (0..=u16::MAX).filter(|fc| fc & 3 == 0 && fc & TYPE != EXTENSION) {
            let len = header_len(fc);
            let mut bytes = vec![0; len];
            bytes[..2].copy_from_slice(&fc.to_le_bytes());
            assert!(Header::parse(&bytes).is_ok(), "{fc:x}");
            for n in 0..len {
                assert_eq!(Header::parse(&bytes[..n]), Err(Error::Truncated));
            }
        }
    }

    #[test]
    fn qos_order_four_address_sequence() {
        let mut bytes = [0; 36];
        bytes[..2].copy_from_slice(&0x8388_u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&0xabcd_u16.to_le_bytes());
        bytes[30] = 0x8f;
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.length, 36);
        assert_eq!(header.sequence, Some(0xabc));
        assert_eq!(header.fragment, Some(13));
        assert_eq!(header.tid, Some(15));
        assert!(header.amsdu && header.fragmented());
    }

    #[test]
    fn unchanged_linux_header_and_pn_oracle_all_control_words() {
        use crate::net::wifi::security::PacketNumber;
        use sha2::{Digest, Sha256};
        // Reproduce with tests/reference/wifi_mac_oracle.py. The digest binds
        // 65,536 unchanged-C header-length + CCMP PN-layout results, ASan/UBSan.
        let mut digest = Sha256::new();
        for i in 0..=u16::MAX {
            digest.update((header_len(i) as u16).to_le_bytes());
            let h = [
                i as u8,
                (i >> 8) as u8,
                0,
                0x20 | ((i >> 14) as u8) << 6,
                i.wrapping_mul(3) as u8,
                (i >> 3) as u8,
                i.wrapping_mul(7) as u8,
                (i >> 5) as u8,
            ];
            let (pn, key) = PacketNumber::from_header(&h).unwrap();
            assert_eq!(key, (i >> 14) as u8);
            digest.update(&pn.value().to_be_bytes()[2..]);
        }
        assert_eq!(
            digest.finalize().as_slice(),
            &[
                0x71, 0xcb, 0xee, 0x7e, 0x83, 0x03, 0xe0, 0x35, 0xcc, 0x30, 0x7a, 0xd6, 0xb3, 0x06,
                0x1a, 0x1e, 0x63, 0xe7, 0x50, 0xe4, 0xee, 0x88, 0x6a, 0x86, 0xde, 0x65, 0x27, 0xe3,
                0xfa, 0xac, 0x2b, 0xcc
            ]
        );
    }

    #[test]
    fn protocol_and_extension_are_explicit() {
        assert_eq!(Header::parse(&[1; 24]), Err(Error::ProtocolVersion));
        assert_eq!(
            Header::parse(&[12, 0, 0, 0]),
            Err(Error::Unsupported("extension frame"))
        );
    }
}
