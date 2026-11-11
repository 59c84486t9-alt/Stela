// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! The frames firmware sends for a station by itself, as `rtw_build_rsvd_page`
//! lays them out: a dummy where a beacon would go, then a PS-Poll, a QoS null
//! and a null, and what a power gate would lose, each on its own page behind
//! its descriptor.
use super::descriptor::{Packet, QSEL_MANAGEMENT, RATE_1M, RATE_6M, RATE_ID_B, RATE_ID_G};
use crate::{Mac, wifi::Band};
use alloc::{vec, vec::Vec};

/// `TX_PAGE_SIZE`.
const PAGE: usize = 128;
/// `tx_pkt_desc_sz`.
const DESCRIPTOR: usize = 48;
/// `rsvd_drv_pg_num`.
const MAX_PAGES: usize = 16;
/// What page 0 is: one byte, behind the descriptor the queue writes.
const DUMMY: usize = 1;

/// `MAX_PG_CAM_BACKUP_NUM`.
const SAVED_KEYS: usize = 8;

/// A station's frames, ready for what a power gate needs beside them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Templates {
    frames: [Vec<u8>; 3],
    band: Band,
}

/// The pages for firmware, and where each part's page is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pages {
    pub data: Vec<u8>,
    pub ps_poll: u8,
    pub qos_null: u8,
    pub null: u8,
    pub predistortion: u8,
    pub info: u8,
}

/// `rtw_tx_rsvd_page_pkt_info_update` of `frame`.
fn descriptor(band: Band, frame: &[u8]) -> Packet {
    let (rate_id, rate) = if band == Band::Ghz2 {
        (RATE_ID_B, RATE_1M)
    } else {
        (RATE_ID_G, RATE_6M)
    };
    let control = frame[0];
    Packet {
        size: frame.len() as u16,
        queue: QSEL_MANAGEMENT,
        rate_id,
        rate,
        fixed_rate: true,
        navigation_from_header: control == PS_POLL,
        device_sequence: control != PS_POLL,
        bluetooth_null: control == QOS_NULL,
        ..Packet::default()
    }
}

/// `IEEE80211_STYPE_PSPOLL` and `IEEE80211_STYPE_QOS_NULLFUNC`.
const PS_POLL: u8 = 0xa4;
const QOS_NULL: u8 = 0xc8;

/// `ieee80211_pspoll_get`.
fn ps_poll(local: Mac, bssid: Mac, aid: u16) -> Vec<u8> {
    let mut frame = vec![PS_POLL, 0];
    frame.extend((aid | 0xc000).to_le_bytes());
    frame.extend(bssid.0);
    frame.extend(local.0);
    frame
}

/// `ieee80211_nullfunc_get`.
fn null(local: Mac, bssid: Mac, qos: bool) -> Vec<u8> {
    let mut frame = vec![if qos { QOS_NULL } else { 0x48 }, 1, 0, 0];
    frame.extend(bssid.0);
    frame.extend(local.0);
    frame.extend(bssid.0);
    frame.extend([0, 0]);
    if qos {
        frame.extend(7u16.to_le_bytes());
    }
    frame
}

/// The frames of an association of `local` to `bssid` as `aid`, over WMM or
/// not, on `band`.
pub fn build(local: Mac, bssid: Mac, aid: u16, wmm: bool, band: Band) -> Templates {
    Templates {
        frames: [
            ps_poll(local, bssid, aid),
            null(local, bssid, wmm),
            null(local, bssid, false),
        ],
        band,
    }
}

/// `rtw_lps_pg_info_get`: `struct rtw_lps_pg_info_hdr` of the key entries set
/// in `keys`, for the one station on MAC ID 0.
pub fn power_gate_info(keys: u32) -> [u8; 8 + SAVED_KEYS] {
    let mut info = [0; 8 + SAVED_KEYS];
    let entries = (0..32u8).filter(|entry| keys >> entry & 1 != 0);
    let mut count = 0;
    for (slot, entry) in info[8..].iter_mut().zip(entries) {
        *slot = entry;
        count += 1;
    }
    info[4] = count;
    info[5] = MAX_PAGES as u8;
    info
}

impl Templates {
    /// `rtw_build_rsvd_page` of the frames, then the `predistortion` and `info`
    /// a power gate restores from.
    pub fn pages(&self, predistortion: &[u8], info: &[u8]) -> Pages {
        let [poll, qos, plain] = &self.frames;
        let parts: [&[u8]; 5] = [poll, qos, plain, predistortion, info];
        let mut packets: [Vec<u8>; 5] = Default::default();
        let mut locations = [0u8; 5];
        let mut page = (DUMMY + DESCRIPTOR).div_ceil(PAGE);
        for ((packet, location), part) in packets.iter_mut().zip(&mut locations).zip(parts) {
            packet.extend(descriptor(self.band, part).encode());
            packet.extend(part);
            *location = page as u8;
            page += packet.len().div_ceil(PAGE);
        }
        debug_assert!(page <= MAX_PAGES);
        // The queue's own descriptor takes the head of page 0, and the rest of
        // the pages follow what is left of it.
        let margin = PAGE - DESCRIPTOR;
        let mut data = vec![0; (page - 1) * PAGE + margin];
        for (packet, location) in packets.iter().zip(locations) {
            let at = margin + PAGE * (usize::from(location) - 1);
            data[at..at + packet.len()].copy_from_slice(packet);
        }
        let [ps_poll, qos_null, null, predistortion, info] = locations;
        Pages {
            data,
            ps_poll,
            qos_null,
            null,
            predistortion,
            info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: Mac = Mac([2, 0, 0, 0, 0, 1]);
    const AP: Mac = Mac([2, 0, 0, 0, 0, 2]);

    #[test]
    fn each_frame_has_a_page_past_the_dummy() {
        let built = build(LOCAL, AP, 5, true, Band::Ghz2).pages(&[3; 169], &[9; 16]);
        assert_eq!(
            (built.ps_poll, built.qos_null, built.null),
            (1, 2, 3),
            "PS-Poll, QoS null and null, as rtw_add_rsvd_page_sta orders them"
        );
        assert_eq!(
            (built.predistortion, built.info),
            (4, 6),
            "what a power gate loses comes last, and predistortion takes two"
        );
        assert_eq!(built.data.len(), 6 * PAGE + 80);
        let at = |page: usize| 80 + PAGE * (page - 1) + DESCRIPTOR;
        assert_eq!(built.data[at(4)..at(4) + 169], [3; 169]);
        assert_eq!(built.data[at(6)..at(6) + 16], [9; 16]);
        let poll = &built.data[at(1)..at(1) + 16];
        assert_eq!(poll[..4], [0xa4, 0, 5, 0xc0]);
        assert_eq!(poll[4..10], AP.0);
        assert_eq!(poll[10..16], LOCAL.0);
        let qos = &built.data[at(2)..at(2) + 26];
        assert_eq!(qos[..2], [0xc8, 1]);
        assert_eq!(qos[24..26], [7, 0]);
        assert_eq!(built.data[at(3)..at(3) + 2], [0x48, 1]);
    }

    #[test]
    fn a_peer_without_wmm_gets_a_plain_null_for_the_qos_one() {
        let built = build(LOCAL, AP, 1, false, Band::Ghz5).pages(&[0; 169], &[0; 16]);
        let at = 80 + PAGE + DESCRIPTOR;
        assert_eq!(built.data[at..at + 2], [0x48, 1]);
    }

    #[test]
    fn a_power_gate_keeps_the_first_eight_keys() {
        let info = power_gate_info(0b1011);
        assert_eq!(info[4], 3);
        assert_eq!(info[5], 16, "rsvd_drv_pg_num");
        assert_eq!(info[8..12], [0, 1, 3, 0]);
        let info = power_gate_info(u32::MAX);
        assert_eq!(info[4], 8);
        assert_eq!(info[8..], [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn descriptors_say_who_numbers_the_frame() {
        let poll = descriptor(Band::Ghz2, &ps_poll(LOCAL, AP, 1));
        assert!(poll.navigation_from_header && !poll.device_sequence);
        let qos = descriptor(Band::Ghz5, &null(LOCAL, AP, true));
        assert!(qos.bluetooth_null && qos.device_sequence);
        assert_eq!(qos.rate, RATE_6M);
    }
}
