// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! The 48-byte packet descriptor ahead of every RTL8822C frame, from pinned
//! rtw88 `tx.c` and `tx.h`.

/// `RTW_RATEID_B_20M` and `RTW_RATEID_G`, for what goes at a basic rate.
pub const RATE_ID_B: u8 = 8;
pub const RATE_ID_G: u8 = 7;
/// `DESC_RATE1M` and `DESC_RATE6M`.
pub const RATE_1M: u8 = 0;
pub const RATE_6M: u8 = 4;
/// `TX_DESC_QSEL_MGMT` and `TX_DESC_QSEL_HIGH`; data selects its TID.
pub const QSEL_MANAGEMENT: u8 = 0x12;
pub const QSEL_HIGH: u8 = 0x11;
/// `rtw_tx_pkt_info_update_sec`'s type for a CCMP frame's hardware key.
pub const SECURITY_CCMP: u8 = 3;
/// And for TKIP and WEP.
pub const SECURITY_RC4: u8 = 1;

/// `struct rtw_tx_pkt_info`, as far as a station uses it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Packet {
    pub size: u16,
    pub multicast: bool,
    pub mac_id: u8,
    pub queue: u8,
    pub rate_id: u8,
    pub security: u8,
    /// Whether the frame may join an A-MPDU, with the peer's limits.
    pub aggregate: Option<Aggregate>,
    /// The frame's report number, which firmware names in its TX report.
    pub report: Option<u8>,
    pub fixed_rate: bool,
    pub rts: bool,
    /// `nav_use_hdr`: the frame's own duration field holds its AID.
    pub navigation_from_header: bool,
    /// `bt_null`: firmware sends this to tell the AP it left for Bluetooth.
    pub bluetooth_null: bool,
    pub rate: u8,
    pub width: u8,
    pub ldpc: bool,
    pub stbc: u8,
    /// Let the device number the frame: management and null frames.
    pub device_sequence: bool,
    /// The sequence number of a frame the host numbers.
    pub sequence: u16,
}

/// `get_tx_ampdu_factor` and `get_tx_ampdu_density`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aggregate {
    pub factor: u8,
    pub density: u8,
}

impl Aggregate {
    /// From the peer's HT A-MPDU parameters.
    pub fn from_ht(parameters: u8) -> Self {
        Self {
            factor: (4 << (parameters & 3)) - 1,
            density: (parameters >> 2) & 7,
        }
    }
}

impl Packet {
    /// `rtw_tx_fill_tx_desc`, with rtw8822c's checksum over the descriptor.
    pub fn encode(&self) -> [u8; 48] {
        let (factor, density) = self.aggregate.map_or((0, 0), |a| (a.factor, a.density));
        let bit = |value: bool, at: u32| u32::from(value) << at;
        let mut words = [0u32; 12];
        words[0] = u32::from(self.size)
            | (48 << 16)
            | bit(self.multicast, 24)
            | (1 << 26)
            | bit(self.device_sequence, 31);
        words[1] = u32::from(self.mac_id)
            | (u32::from(self.queue & 0x1f) << 8)
            | (u32::from(self.rate_id & 0x1f) << 16)
            | (u32::from(self.security & 3) << 22)
            | bit(self.queue == QSEL_HIGH, 29);
        words[2] = bit(self.aggregate.is_some(), 12)
            | bit(self.report.is_some(), 19)
            | (u32::from(density & 7) << 20)
            | bit(self.bluetooth_null, 23);
        words[3] = bit(self.fixed_rate, 8)
            | bit(self.fixed_rate, 10)
            | bit(self.rts, 12)
            | bit(self.navigation_from_header, 15)
            | (u32::from(factor & 0x1f) << 17);
        words[4] = u32::from(self.rate & 0x7f);
        words[5] =
            (u32::from(self.width & 3) << 5) | bit(self.ldpc, 7) | (u32::from(self.stbc & 3) << 8);
        if self.rts {
            // DESC_RATE24M.
            words[4] |= 8 << 24;
            words[5] |= 1 << 12;
        }
        words[6] = u32::from(self.report.unwrap_or(0));
        words[8] = bit(self.device_sequence, 15);
        words[9] = u32::from(self.sequence & 0xfff) << 12;
        let mut bytes = [0; 48];
        for (out, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *out = word.to_le_bytes();
        }
        // fill_txdesc_checksum_common over its 24 halfwords.
        let checksum = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .fold(0u16, |sum, &half| sum ^ u16::from_le_bytes(half));
        bytes[28..30].copy_from_slice(&checksum.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8; 48], index: usize) -> u32 {
        u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
    }

    #[test]
    fn a_management_frame_goes_at_a_fixed_rate_and_the_device_numbers_it() {
        let bytes = Packet {
            size: 300,
            queue: QSEL_MANAGEMENT,
            rate_id: RATE_ID_G,
            rate: RATE_6M,
            fixed_rate: true,
            device_sequence: true,
            report: Some(0x14),
            ..Packet::default()
        }
        .encode();
        assert_eq!(word(&bytes, 0), 300 | (48 << 16) | (1 << 26) | (1 << 31));
        assert_eq!(word(&bytes, 1), (0x12 << 8) | (7 << 16));
        assert_eq!(word(&bytes, 2), 1 << 19);
        assert_eq!(word(&bytes, 3), (1 << 8) | (1 << 10));
        assert_eq!(word(&bytes, 4), 4);
        assert_eq!(word(&bytes, 6), 0x14);
        assert_eq!(word(&bytes, 8), 1 << 15);
    }

    #[test]
    fn a_data_frame_carries_its_aggregate_and_key_type() {
        let bytes = Packet {
            size: 1500,
            mac_id: 1,
            queue: 5,
            rate_id: 9,
            security: SECURITY_CCMP,
            aggregate: Some(Aggregate::from_ht(0x17)),
            rate: 0x53,
            width: 2,
            ldpc: true,
            sequence: 0xabc,
            ..Packet::default()
        }
        .encode();
        assert_eq!(word(&bytes, 1), 1 | (5 << 8) | (9 << 16) | (3 << 22));
        assert_eq!(word(&bytes, 2), (1 << 12) | (5 << 20));
        assert_eq!(word(&bytes, 3), 31 << 17);
        assert_eq!(word(&bytes, 5), (2 << 5) | (1 << 7));
        assert_eq!(word(&bytes, 9), 0xabc << 12);
    }

    #[test]
    fn the_checksum_cancels_the_descriptor() {
        let bytes = Packet {
            size: 77,
            mac_id: 3,
            ..Packet::default()
        }
        .encode();
        let checksum = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .fold(0u16, |sum, &half| sum ^ u16::from_le_bytes(half));
        assert_eq!(checksum, 0);
    }
}
