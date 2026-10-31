// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! A station's HE capabilities, `iwl_iftype_cap` as `iwl_nvm_fixup_sband_iftd`
//! fixes it up for a band and device. Only what `IEEE80211_HE_PHY_CAP0` says
//! the width set holds goes on the air, as `ieee80211_put_he_cap` writes it.
use crate::wifi::{Band, intel::firmware::Family, station::phy::McsMaps};
use alloc::vec::Vec;

const EXTENSION: u8 = 255;
const HE_CAPABILITIES: u8 = 35;
const HE_6GHZ_CAPABILITIES: u8 = 59;
/// PPET16 at 0 and PPET8 at 7, for two streams.
const THRESHOLDS: [u8; 4] = [0x61, 0x1c, 0xc7, 0x71];
/// Every MCS of one stream, or of two.
const ONE_STREAM: u16 = 0xfffe;
const TWO_STREAMS: u16 = 0xfffa;
const NO_STREAMS: u16 = 0xffff;

/// The device's maps for 80, 160 and 80+80 MHz.
pub(super) fn maps(two_streams: bool) -> [McsMaps; 3] {
    let map = if two_streams { TWO_STREAMS } else { ONE_STREAM };
    [
        McsMaps { rx: map, tx: map },
        McsMaps { rx: map, tx: map },
        McsMaps {
            rx: NO_STREAMS,
            tx: NO_STREAMS,
        },
    ]
}

/// The HE 6 GHz Band Capabilities `iwl_init_he_6ghz_capa` derives from a
/// station's HT and VHT ones, with spatial multiplexing power save off as
/// `ieee80211_put_he_6ghz_cap` writes it.
pub(super) fn six_ghz_capability(tx: u32, rx: u32) -> [u8; 5] {
    let capability: u16 = 5 // 4 us A-MPDU spacing
        | 7 << 3 // 1 MB A-MPDUs
        | 2 << 6 // 11454-byte MPDUs
        | 3 << 9 // SMPS off
        | u16::from(rx == 1) << 12
        | u16::from(tx == 1) << 13;
    let [low, high] = capability.to_le_bytes();
    [EXTENSION, 3, HE_6GHZ_CAPABILITIES, low, high]
}

/// The element for `band`. `two_streams` is both directions having both
/// antennas; `wide` is 160 MHz being usable.
pub(super) fn capability(band: Band, family: Family, two_streams: bool, wide: bool) -> Vec<u8> {
    // HTC-HE; 16 us trigger padding and eight receive TIDs; 32-bit bitmaps;
    // OM control and control frames to the multiple BSSID set; A-MSDU in
    // A-MPDU; eight transmit TIDs, 2x996 uplink, dynamic SMPS and trigger
    // frames in HT and VHT PPDUs.
    let mut mac = [0x01, 0x78, 0x20, 0x82, 0xc0, 0xab];
    // Punctured receive, class A, LDPC; NDP LTF and RX STBC; DCM BPSK;
    // beamformee of eight; trigger feedback and PPE thresholds; boost and 4x LTF;
    // ER SU, and 20 and 80 MHz within wider PPDUs; SIG-B full bandwidth, and the
    // reserved nominal padding; M-1 RU LTF.
    let mut phy = [0, 0x3f, 0x0a, 0x09, 0xfd, 0, 0x8c, 0x06, 0x0f, 0xfc, 0x01];
    if band == Band::Ghz2 {
        mac[3] |= 3 << 3;
        phy[0] |= 0x02;
    } else {
        mac[3] |= 1 << 3;
        phy[0] |= 0x04 | if wide { 0x08 } else { 0 };
    }
    if two_streams {
        phy[2] |= 0x04;
        phy[5] |= 0x09;
        phy[7] |= 0x10;
    } else {
        phy[7] |= 0x08;
    }
    match family {
        // The HR radio has no 1024-QAM below a 242-tone RU.
        Family::Ax200 => phy[9] &= !0x0c,
        Family::Ax210 => phy[2] |= 0x40,
    }
    let [narrow, broad, _] = maps(two_streams);
    let mut element = Vec::new();
    element.extend_from_slice(&[EXTENSION, 0, HE_CAPABILITIES]);
    element.extend_from_slice(&mac);
    element.extend_from_slice(&phy);
    let mut supported = alloc::vec![narrow];
    if phy[0] & 0x08 != 0 {
        supported.push(broad);
    }
    for map in supported {
        element.extend_from_slice(&map.rx.to_le_bytes());
        element.extend_from_slice(&map.tx.to_le_bytes());
    }
    element.extend_from_slice(&THRESHOLDS);
    element[1] = (element.len() - 2) as u8;
    element
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::station::phy::{Capabilities, Role};

    fn parsed(band: Band, family: Family, two_streams: bool, wide: bool) -> Capabilities {
        let mut elements = if band == Band::Ghz2 {
            alloc::vec![1, 1, 0x82]
        } else {
            alloc::vec![1, 1, 0x8c]
        };
        elements.extend(capability(band, family, two_streams, wide));
        Capabilities::parse(band, Role::Station, &elements).unwrap()
    }

    #[test]
    fn six_ghz_names_he_and_its_own_band_capabilities_alone() {
        let elements = super::super::capability_elements(Band::Ghz6, Family::Ax210, (3, 3), true);
        let capabilities = Capabilities::parse(Band::Ghz6, Role::Station, &elements).unwrap();
        assert_eq!(capabilities.he_6ghz(), Some(0x6bd));
        assert!(capabilities.ht().is_none() && capabilities.vht().is_none());
        assert_eq!(six_ghz_capability(1, 1)[3..], 0x36bdu16.to_le_bytes());
    }

    #[test]
    fn the_band_sets_its_widths_and_its_ampdu_extension() {
        let low = capability(Band::Ghz2, Family::Ax210, true, true);
        assert_eq!(low[3..9], [0x01, 0x78, 0x20, 0x9a, 0xc0, 0xab]);
        assert_eq!(low[9], 0x02);
        assert_eq!(low.len(), 3 + 17 + 4 + 4, "2.4 GHz names no 160 MHz map");
        let high = capability(Band::Ghz5, Family::Ax210, true, true);
        assert_eq!(high[6], 0x8a);
        assert_eq!(high[9], 0x0c);
        assert_eq!(high.len(), 3 + 17 + 8 + 4);
        let narrow = capability(Band::Ghz5, Family::Ax210, true, false);
        assert_eq!(narrow[9], 0x04);
        assert_eq!(narrow.len(), 3 + 17 + 4 + 4);
    }

    #[test]
    fn a_single_chain_names_one_stream() {
        let single = capability(Band::Ghz5, Family::Ax210, false, true);
        assert_eq!(single[9 + 2] & 0x04, 0);
        assert_eq!(single[9 + 5], 0);
        assert_eq!(single[9 + 7], 0x0e);
        assert_eq!(single[20..24], [0xfe, 0xff, 0xfe, 0xff]);
    }

    #[test]
    fn the_radio_decides_small_rus_and_full_mu_mimo() {
        let hr = capability(Band::Ghz5, Family::Ax200, true, true);
        assert_eq!(hr[9 + 9], 0xf0);
        assert_eq!(hr[9 + 2] & 0x40, 0);
        let gf = capability(Band::Ghz5, Family::Ax210, true, true);
        assert_eq!(gf[9 + 9], 0xfc);
        assert_ne!(gf[9 + 2] & 0x40, 0);
    }

    #[test]
    fn the_element_parses_to_the_maps_it_was_built_from() {
        for (two_streams, wide) in [(true, true), (true, false), (false, true)] {
            let he = parsed(Band::Ghz5, Family::Ax210, two_streams, wide);
            let he = he.he().unwrap();
            let [narrow, broad, _] = maps(two_streams);
            assert_eq!(he.mcs_80, narrow);
            assert_eq!(he.mcs_160, wide.then_some(broad));
            assert_eq!(he.mcs_80p80, None);
            assert_eq!(he.ppe.as_slice(), THRESHOLDS);
        }
        assert!(parsed(Band::Ghz2, Family::Ax200, true, true).he().is_some());
    }
}
