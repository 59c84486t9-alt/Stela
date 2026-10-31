// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! A station's EHT capabilities, `iwl_iftype_cap` as `iwl_nvm_fixup_sband_iftd`
//! fixes it up for a band and device, narrowed as `ieee80211_put_eht_cap`
//! writes it to the widths the country leaves.
use crate::wifi::{Band, intel::identity::EhtLimits, station::phy::Width};
use alloc::vec::Vec;

const EXTENSION: u8 = 255;
const EHT_CAPABILITIES: u8 = 108;

/// The element for `band`. `two_streams` is both directions having both
/// antennas; `widest` is the widest channel this device has on the band.
pub(super) fn capability(
    band: Band,
    limits: EhtLimits,
    two_streams: bool,
    widest: Width,
) -> Vec<u8> {
    let (wide, widest_320) = (widest != Width::Mhz80, widest == Width::Mhz320);
    // OM control.
    let mut mac = [0x02, 0];
    // 242-tone RUs above 20 MHz, four-LTF NDPs, SU beamformee of four streams;
    // triggered SU feedback; four LTFs at 0.8 us; 16 us padding, transmit and
    // receive below 242 tones, extra LTFs; 1024- and 4096-QAM in wider OFDMA.
    let mut phy = [0xcc, 0x1f, 0, 0x20, 0x08, 0x66, 0, 0, 0x03];
    if band == Band::Ghz2 {
        // 11454-byte MPDUs, which 2.4 GHz has no VHT to name.
        mac[0] |= 2 << 6;
    }
    if widest_320 {
        phy[0] |= 0x02;
        phy[1] |= 0xe0;
    }
    if two_streams {
        // One sounding dimension at each width, and feedback of two.
        phy[2] |= if widest_320 { 0x49 } else { 0x09 };
        phy[4] |= 0x10;
    }
    if !wide {
        phy[1] &= !0x1c;
        phy[2] &= !0x38;
    }
    if limits.reduced {
        phy[8] &= !0x02;
    }
    let streams = if two_streams { 0x22 } else { 0x11 };
    let top = if limits.reduced { 0 } else { streams };
    let fast_320 = !limits.urm && !(limits.slow_bus && two_streams);
    let high_320 = if fast_320 { streams } else { 0 };
    let mut element = alloc::vec![EXTENSION, 0, EHT_CAPABILITIES];
    element.extend_from_slice(&mac);
    element.extend_from_slice(&phy);
    element.extend_from_slice(&[streams, streams, top]);
    if wide && band != Band::Ghz2 {
        element.extend_from_slice(&[streams, streams, top]);
    }
    if widest_320 {
        element.extend_from_slice(&[streams, high_320, high_320]);
    }
    element[1] = (element.len() - 2) as u8;
    element
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::{
        intel::{
            association::{self as commands, RateShape},
            firmware::Family,
            identity::Rf,
        },
        station::phy::{Capabilities, Mode, Negotiated, Role},
    };

    fn device(eht: EhtLimits) -> super::super::Device {
        super::super::Device {
            family: Family::Bz,
            radio: Rf::Fm,
            chains: (3, 3),
            eht: Some(eht),
        }
    }

    fn negotiated(limits: EhtLimits, width: Width) -> Negotiated {
        let band = Band::Ghz6;
        let own = |limits| super::super::probe_elements(band, device(limits), Width::Mhz320);
        let mut station = own(limits);
        station.extend([221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0]);
        let mut ap = own(EhtLimits::default());
        ap.extend([221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x80, 0]);
        for category in 0..4 {
            ap.extend([category << 5 | 3, 0xa4, 0, 0]);
        }
        let parsed = |role, elements: &[u8]| Capabilities::parse(band, role, elements).unwrap();
        let station = parsed(Role::Station, &station);
        Negotiated::between(&station, &parsed(Role::AccessPoint, &ap), Mode::Eht, width).unwrap()
    }

    fn rates(negotiated: &Negotiated, authorized: bool) -> (Vec<u8>, RateShape) {
        let shape = RateShape::of(6).unwrap();
        let rates = commands::rate_config(negotiated, Band::Ghz6, 3, shape, authorized, 0).unwrap();
        (rates, shape)
    }

    fn class(rates: &[u8], shape: RateShape, nss: usize, width: usize) -> u32 {
        let at = shape.head + 8 + (nss * shape.classes + width) * shape.rate_bytes;
        u32::from_le_bytes(rates[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn each_band_names_what_linux_names() {
        let limits = EhtLimits::default();
        let low = capability(Band::Ghz2, limits, true, Width::Mhz80);
        assert_eq!(low[3..5], [0x82, 0]);
        assert_eq!(low[5..14], [0xcc, 0x03, 0x01, 0x20, 0x18, 0x66, 0, 0, 0x03]);
        assert_eq!(low[14..], [0x22; 3]);
        let middle = capability(Band::Ghz5, limits, true, Width::Mhz160);
        assert_eq!(middle[3..5], [0x02, 0]);
        assert_eq!(middle[5..8], [0xcc, 0x1f, 0x09]);
        assert_eq!(middle[14..], [0x22; 6]);
        let high = capability(Band::Ghz6, limits, true, Width::Mhz320);
        assert_eq!(high[5..8], [0xce, 0xff, 0x49]);
        assert_eq!(high[14..], [0x22; 9]);
        assert_eq!(high[1] as usize, high.len() - 2);
    }

    #[test]
    fn one_chain_names_one_stream_without_sounding() {
        let single = capability(Band::Ghz6, EhtLimits::default(), false, Width::Mhz320);
        assert_eq!(single[7], 0);
        assert_eq!(single[9], 0x08);
        assert_eq!(single[14..], [0x11; 9]);
    }

    #[test]
    fn the_device_limits_narrow_320_mhz_and_the_top_rates() {
        let widest = Width::Mhz320;
        let urm = EhtLimits {
            urm: true,
            ..EhtLimits::default()
        };
        assert_eq!(
            capability(Band::Ghz6, urm, false, widest)[20..],
            [0x11, 0, 0]
        );
        let slow = EhtLimits {
            slow_bus: true,
            ..EhtLimits::default()
        };
        assert_eq!(
            capability(Band::Ghz6, slow, true, widest)[20..],
            [0x22, 0, 0]
        );
        assert_eq!(
            capability(Band::Ghz6, slow, false, widest)[20..],
            [0x11; 3],
            "one stream fits the link"
        );
        let reduced = EhtLimits {
            reduced: true,
            ..EhtLimits::default()
        };
        assert!(!reduced.reaches_320());
        let element = capability(Band::Ghz6, reduced, true, Width::Mhz160);
        assert_eq!(element[13], 0x01, "no 4096-QAM in wider OFDMA");
        assert_eq!(element[14..], [0x22, 0x22, 0, 0x22, 0x22, 0]);
        assert!(
            !EhtLimits {
                stops_at_160: true,
                ..EhtLimits::default()
            }
            .reaches_320()
        );
    }

    #[test]
    fn a_narrower_channel_drops_its_widths_and_their_maps() {
        let eighty = capability(Band::Ghz5, EhtLimits::default(), true, Width::Mhz80);
        assert_eq!(eighty[6], 0x03);
        assert_eq!(eighty[7], 0x01);
        assert_eq!(eighty[14..], [0x22; 3]);
    }

    #[test]
    fn firmware_takes_every_rate_the_width_reaches() {
        let negotiated = negotiated(EhtLimits::default(), Width::Mhz320);
        assert_eq!(commands::ampdu_exponent(&negotiated), 9, "4 MB");
        let (config, shape) = rates(&negotiated, true);
        assert_eq!(config[shape.head], 4);
        assert_eq!(config[shape.head + 1], 4);
        assert_eq!(config[shape.head + 4] & 0x40, 0x40, "extra LTFs");
        for nss in 0..2 {
            for width in 0..3 {
                assert_eq!(class(&config, shape, nss, width), 0x3fff);
            }
        }
    }

    #[test]
    fn until_the_port_opens_firmware_stays_in_the_lowest_class() {
        let negotiated = negotiated(EhtLimits::default(), Width::Mhz320);
        let (config, shape) = rates(&negotiated, false);
        assert_eq!(config[shape.head], 0);
        assert_eq!(class(&config, shape, 0, 0), 0x3fff);
        assert_eq!(class(&config, shape, 0, 1), 0);
        assert_eq!(class(&config, shape, 1, 2), 0);
    }

    #[test]
    fn a_limited_device_keeps_its_rates_below_the_limit() {
        let slow = EhtLimits {
            slow_bus: true,
            ..EhtLimits::default()
        };
        let negotiated = negotiated(slow, Width::Mhz320);
        let (config, shape) = rates(&negotiated, true);
        assert_eq!(class(&config, shape, 0, 1), 0x3fff);
        assert_eq!(class(&config, shape, 0, 2), 0x3ff);
        assert_eq!(class(&config, shape, 1, 2), 0x3ff);
    }

    #[test]
    fn six_ghz_with_eht_takes_a_longer_he_aggregate() {
        let elements =
            |eht| super::super::he::capability(Band::Ghz6, Family::Bz, Rf::Fm, true, true, eht);
        assert_eq!(elements(true)[6] >> 3 & 3, 2);
        assert_eq!(elements(false)[6] >> 3 & 3, 1);
    }

    #[test]
    fn its_elements_parse_as_a_station_and_fit_a_probe() {
        let bands = [
            (Band::Ghz2, Width::Mhz80),
            (Band::Ghz5, Width::Mhz160),
            (Band::Ghz6, Width::Mhz320),
        ];
        let mut bytes = 0;
        for (band, widest) in bands {
            let elements = super::super::probe_elements(band, device(EhtLimits::default()), widest);
            let parsed = Capabilities::parse(band, Role::Station, &elements).unwrap();
            assert!(parsed.eht().is_some());
            bytes += elements.len();
        }
        assert!(bytes < 400);
    }
}
