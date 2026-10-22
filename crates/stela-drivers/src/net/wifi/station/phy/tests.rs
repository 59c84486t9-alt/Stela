use super::*;
use alloc::{vec, vec::Vec};

fn ie(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    out.extend_from_slice(&[id, data.len() as u8]);
    out.extend_from_slice(data);
}
fn extension(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    let mut extended = vec![id];
    extended.extend_from_slice(data);
    ie(out, 255, &extended);
}
fn ht() -> [u8; 26] {
    let mut data = [0; 26];
    data[..2].copy_from_slice(&0x19e3_u16.to_le_bytes());
    data[2] = 3 | (4 << 2);
    data[3..5].fill(0xff);
    data[7] = 1;
    data[15] = 1;
    data
}
fn vht() -> [u8; 12] {
    let mut data = [0; 12];
    data[..4].copy_from_slice(&(1_u32 | 4 | 0x60 | 0x180 | (3 << 23)).to_le_bytes());
    data[4..6].copy_from_slice(&0xfffa_u16.to_le_bytes());
    data[8..10].copy_from_slice(&0xfffa_u16.to_le_bytes());
    data
}
fn he(width_bits: u8) -> Vec<u8> {
    let mut data = vec![0; 17];
    data[6] = width_bits;
    for _ in 0..1 + usize::from(width_bits & 8 != 0) + usize::from(width_bits & 16 != 0) {
        data.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff]);
    }
    data
}
fn eht(width_bits: u8, role: Role, width320: bool) -> Vec<u8> {
    let mut data = vec![0; 11];
    data[0] = 1 << 6; // Actual 2.4GHz max-MPDU selection; ignored elsewhere.
    data[2] = if width320 { 2 } else { 0 };
    if width_bits & 2 != 0 {
        data.extend_from_slice(&[0x22, 0x22, 0x11]);
    } else {
        for present in [width_bits & 4 != 0, width_bits & 8 != 0, width320] {
            if present {
                data.extend_from_slice(&[0x22, 0x22, 0x11]);
            }
        }
        if data.len() == 11 {
            data.extend_from_slice(if role == Role::Station {
                &[0x22, 0x22, 0x22, 0x11]
            } else {
                &[0x22, 0x22, 0x11]
            });
        }
    }
    data
}
fn wmm(role: Role) -> Vec<u8> {
    if role == Role::Station {
        return vec![0, 0x50, 0xf2, 2, 0, 1, 0x6f];
    }
    vec![
        0, 0x50, 0xf2, 2, 1, 1, 0x89, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94, 0, 0x62,
        0x32, 47, 0,
    ]
}
fn modern_ies(band: Band, role: Role, width_bits: u8, width320: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if band == Band::Ghz2 {
        ie(&mut out, 1, &[0x82, 0x84, 11, 22, 0x8c, 0x98, 0xb0, 108]);
        ie(&mut out, 50, &[18, 36, 72, 96]);
    } else if band != Band::Ghz6 {
        ie(&mut out, 1, &[0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
    }
    if band != Band::Ghz6 {
        ie(&mut out, 45, &ht());
        if band == Band::Ghz5 {
            ie(&mut out, 191, &vht());
        }
    }
    extension(&mut out, 35, &he(width_bits));
    extension(&mut out, 108, &eht(width_bits, role, width320));
    if band == Band::Ghz6 {
        extension(&mut out, 59, &0x004a_u16.to_le_bytes());
    }
    ie(&mut out, 221, &wmm(role));
    out
}
fn pair(band: Band, width_bits: u8, width320: bool) -> (Capabilities, Capabilities) {
    (
        Capabilities::parse(
            band,
            Role::Station,
            &modern_ies(band, Role::Station, width_bits, width320),
        )
        .unwrap(),
        Capabilities::parse(
            band,
            Role::AccessPoint,
            &modern_ies(band, Role::AccessPoint, width_bits, width320),
        )
        .unwrap(),
    )
}

#[test]
fn source_rate_indices_basic_rates_and_membership_are_distinct() {
    let (local, peer) = pair(Band::Ghz2, 2, false);
    assert_eq!(local.rates().supported, 0xfff);
    assert_eq!(peer.rates().basic, 0x153);
    let (local, peer) = pair(Band::Ghz5, 12, false);
    assert_eq!(local.rates().supported, 0xff);
    assert_eq!(peer.rates().basic, 0x15);
    let mut ies = modern_ies(Band::Ghz5, Role::AccessPoint, 12, false);
    // Required HT/VHT/HE/EHT selectors occupy none of the eight rate bits.
    ie(&mut ies, 50, &[0xff, 0xfe, 0xfa, 0xf9]);
    let peer = Capabilities::parse(Band::Ghz5, Role::AccessPoint, &ies).unwrap();
    assert_eq!(peer.rates().selectors, 15);
    assert_eq!(peer.rates().supported, 0xff);
    assert!(Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).is_ok());
    let mut rates = LegacyRates::default();
    assert!(rates.add(Band::Ghz5, &[0x82]).is_err()); // CCK cannot become an OFDM bit.
    rates.add(Band::Ghz5, &[0xfb]).unwrap(); // SAE H2E is retained separately.
    assert_eq!((rates.supported, rates.selectors), (0, 16));
    assert!(Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40).is_err());
    assert!(rates.add(Band::Ghz5, &[0xf8]).is_err()); // UHR remains unsupported.
}

#[test]
fn real_selected_family_width_nss_aggregation_and_edca_reach_typed_output() {
    let (local, peer) = pair(Band::Ghz5, 12, false);
    for (mode, width) in [
        (Mode::Ht, Width::Mhz40),
        (Mode::Vht, Width::Mhz160),
        (Mode::He, Width::Mhz160),
        (Mode::Eht, Width::Mhz160),
    ] {
        let n = Negotiated::between(&local, &peer, mode, width).unwrap();
        assert_eq!((n.rx_nss, n.tx_nss), (2, 2));
        assert_eq!(n.legacy.basic, 0x15);
        assert_eq!(n.peer_mpdu_spacing, 4);
        assert!(!n.legacy20_compatible());
        let wmm = n.wmm.as_ref().unwrap();
        assert_eq!(wmm.parameter_set_count, 9);
        assert_eq!((wmm.uapsd_queues, wmm.max_service_period), (15, 3));
        assert_eq!(wmm.access_categories[2].txop_32us, 94);
        assert_eq!(wmm.access_categories[3].txop_32us, 47);
        assert_eq!(n.peer(), &peer);
    }
    let (local, peer) = pair(Band::Ghz6, 12, true);
    let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz320).unwrap();
    assert_eq!((n.rx_nss, n.tx_nss, n.max_tx_amsdu), (2, 2, 7991));
    assert_eq!(n.legacy.supported, 0);
    assert_eq!(n.peer_ampdu_base_exponent, 1);
    assert_eq!(n.peer_mpdu_spacing, 2);
}

#[test]
fn no_width_rate_nss_or_wmm_fallback_when_required_effects_absent() {
    let (local, peer) = pair(Band::Ghz5, 4, false);
    for (mode, width) in [
        (Mode::He, Width::Mhz160),
        (Mode::Eht, Width::Mhz160),
        (Mode::Eht, Width::Mhz320),
        (Mode::Eht, Width::Mhz80P80),
    ] {
        assert!(Negotiated::between(&local, &peer, mode, width).is_err());
    }
    let mut bad = peer.clone();
    bad.he.as_mut().unwrap().mcs_80 = McsMaps {
        rx: 0xffff,
        tx: 0xffff,
    };
    assert!(matches!(
        Negotiated::between(&local, &bad, Mode::He, Width::Mhz80),
        Err(Error::Incompatible(_))
    ));
    bad = peer.clone();
    bad.wmm = None;
    assert!(matches!(
        Negotiated::between(&local, &bad, Mode::He, Width::Mhz80),
        Err(Error::Missing(_))
    ));
    bad = peer.clone();
    bad.rates.basic |= 1 << 10;
    assert!(matches!(
        Negotiated::between(&local, &bad, Mode::He, Width::Mhz80),
        Err(Error::Incompatible(_))
    ));
    bad = peer.clone();
    bad.eht.as_mut().unwrap().mcs.bw80 = Some([0; 3]);
    assert!(matches!(
        Negotiated::between(&local, &bad, Mode::Eht, Width::Mhz80),
        Err(Error::Incompatible(_))
    ));
}

#[test]
fn asymmetric_directional_maps_do_not_transpose_or_invent_streams() {
    let (mut local, mut peer) = pair(Band::Ghz5, 12, false);
    local.he.as_mut().unwrap().mcs_160 = Some(McsMaps {
        rx: 0xfffa,
        tx: 0xfffc,
    });
    peer.he.as_mut().unwrap().mcs_160 = Some(McsMaps {
        rx: 0xfffa,
        tx: 0xfffe,
    });
    let n = Negotiated::between(&local, &peer, Mode::He, Width::Mhz160).unwrap();
    let map = n.he.unwrap().mcs_160.unwrap();
    assert_eq!(
        map,
        McsMaps {
            rx: 0xfffc,
            tx: 0xfffe
        }
    );
    assert_eq!((n.tx_nss, n.rx_nss), (1, 1));
    local.eht.as_mut().unwrap().mcs.bw160 = Some([0x21, 0x21, 0]);
    peer.eht.as_mut().unwrap().mcs.bw160 = Some([0x12, 0x12, 0]);
    let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
    assert_eq!(n.eht.unwrap().ranges, [0x12, 0x12, 0x12, 0]);
    assert_eq!((n.tx_nss, n.rx_nss), (2, 1));
}

#[test]
fn ht_asymmetric_stbc_stream_limits_and_mcs32_width_have_actual_effect() {
    let (mut local, mut peer) = pair(Band::Ghz5, 12, false);
    local.ht.as_mut().unwrap().capability &= !0x380;
    local.ht.as_mut().unwrap().tx_params = 3; // Explicit one TX stream.
    let n = Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40).unwrap();
    let h = n.ht.as_ref().unwrap();
    assert_eq!(h.capability & 0x380, 0);
    assert_eq!(h.peer_rx_mcs[1], 0);
    assert_eq!((n.tx_nss, n.rx_nss), (1, 2));
    assert_eq!(n.peer().ht().unwrap().capability & 0x380, 0x180);
    for cap in [&mut local, &mut peer] {
        cap.ht.as_mut().unwrap().rx_mcs.fill(0);
        cap.ht.as_mut().unwrap().rx_mcs[4] = 1;
    }
    assert!(Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz20).is_err());
    assert_eq!(
        Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40)
            .unwrap()
            .tx_nss,
        1
    );
    local.ht.as_mut().unwrap().tx_params = 0;
    assert!(Negotiated::between(&local, &peer, Mode::Ht, Width::Mhz40).is_err());
}

#[test]
fn selected_vht_width_matches_final_source_intersection_without_limiting_he_eht() {
    for (own_width, peer_width, expected_160) in
        [(4, 8, false), (8, 4, true), (4, 4, true), (8, 8, true)]
    {
        let (mut local, mut peer) = pair(Band::Ghz5, 12, false);
        local.vht.as_mut().unwrap().capability =
            (local.vht().unwrap().capability & !0xc) | own_width;
        peer.vht.as_mut().unwrap().capability =
            (peer.vht().unwrap().capability & !0xc) | peer_width;
        assert_eq!(
            Negotiated::between(&local, &peer, Mode::Vht, Width::Mhz160).is_ok(),
            expected_160
        );
        assert_eq!(
            Negotiated::between(&local, &peer, Mode::Vht, Width::Mhz80P80).is_ok(),
            own_width == 8 && peer_width == 8
        );
        assert!(Negotiated::between(&local, &peer, Mode::Vht, Width::Mhz80).is_ok());
        // A lower-family VHT restriction cannot disable actual HE/EHT160.
        assert!(Negotiated::between(&local, &peer, Mode::He, Width::Mhz160).is_ok());
        assert!(Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).is_ok());
    }
}

#[test]
fn base_af_scalar_never_claims_he_eht_extensions_while_raw_effects_are_preserved() {
    let (local, mut peer) = pair(Band::Ghz5, 12, false);
    let before = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
    peer.he.as_mut().unwrap().mac[3] |= 0x18;
    peer.eht.as_mut().unwrap().mac[1] |= 1;
    let after = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
    assert_eq!(
        after.peer_ampdu_base_exponent,
        before.peer_ampdu_base_exponent
    );
    assert_eq!(after.peer_ampdu_base_exponent, 3);
    assert_eq!(after.peer().he().unwrap().mac[3] & 0x18, 0x18);
    assert_eq!(after.he.as_ref().unwrap().mac[3] & 0x18, 0x18);
    assert_eq!(after.peer().eht().unwrap().mac[1] & 1, 1);
}

#[test]
fn capability_sizing_and_duplicates_never_accept_partial_fields() {
    for band in [Band::Ghz2, Band::Ghz5, Band::Ghz6] {
        let bits = if band == Band::Ghz2 { 2 } else { 12 };
        let bytes = modern_ies(band, Role::AccessPoint, bits, band == Band::Ghz6);
        for end in 1..bytes.len() {
            // A truncation inside an IE must refuse; complete earlier IE sets
            // may be valid observations and do not imply modern negotiation.
            let prefix = &bytes[..end];
            let mut pos = 0;
            while pos + 2 <= prefix.len() && pos + 2 + usize::from(prefix[pos + 1]) <= prefix.len()
            {
                pos += 2 + usize::from(prefix[pos + 1]);
            }
            if pos != prefix.len() {
                assert!(Capabilities::parse(band, Role::AccessPoint, prefix).is_err());
            }
        }
        let mut duplicate = bytes;
        extension(&mut duplicate, 35, &he(bits));
        assert!(matches!(
            Capabilities::parse(band, Role::AccessPoint, &duplicate),
            Err(Error::Invalid(_))
        ));
    }
    for length in 0..26 {
        assert!(caps::Ht::parse(&ht()[..length]).is_err());
    }
    for length in 0..12 {
        assert!(caps::Vht::parse(&vht()[..length]).is_err());
    }
}

#[test]
fn deferred_eht_layout_uses_actual_he_and_role_not_ie_order() {
    let h = he(0);
    let e_sta = eht(0, Role::Station, false);
    let e_ap = eht(0, Role::AccessPoint, false);
    let mut bytes = vec![1, 1, 12];
    extension(&mut bytes, 108, &e_sta);
    extension(&mut bytes, 35, &h);
    let parsed = Capabilities::parse(Band::Ghz5, Role::Station, &bytes).unwrap();
    assert!(parsed.eht().unwrap().mcs.only_20.is_some());
    assert!(parsed.eht().unwrap().mcs.bw80.is_none());
    assert!(caps::Eht::parse(&e_sta, parsed.he().unwrap(), Role::AccessPoint).is_err());
    assert!(caps::Eht::parse(&e_ap, parsed.he().unwrap(), Role::Station).is_err());
    assert!(Capabilities::parse(Band::Ghz6, Role::Station, &bytes).is_err());
}

#[test]
fn ppe_presence_length_and_nss_are_checked_before_any_slice_use() {
    for header in 0..=255_u8 {
        let mut bytes = he(12);
        bytes[12] |= 0x80;
        let size = caps::he_ppe_len(header);
        bytes.resize(bytes.len() + size, 0);
        let offset = bytes.len() - size;
        bytes[offset] = header;
        assert_eq!(caps::He::parse(&bytes).unwrap().ppe.len(), size);
        assert!(caps::He::parse(&bytes[..bytes.len() - 1]).is_err());
    }
    for header in 0..512_u16 {
        let h = caps::He::parse(&he(12)).unwrap();
        let mut bytes = eht(12, Role::AccessPoint, false);
        bytes[7] |= 8;
        let size = caps::eht_ppe_len(header);
        let offset = bytes.len();
        bytes.resize(offset + size, 0);
        bytes[offset..offset + 2].copy_from_slice(&header.to_le_bytes());
        if header & 15 < 8 {
            assert_eq!(
                caps::Eht::parse(&bytes, &h, Role::AccessPoint)
                    .unwrap()
                    .ppe
                    .len(),
                size
            );
            assert!(caps::Eht::parse(&bytes[..bytes.len() - 1], &h, Role::AccessPoint).is_err());
        } else {
            assert!(caps::Eht::parse(&bytes, &h, Role::AccessPoint).is_err());
        }
    }
}

#[test]
fn malformed_wmm_no_defaults_duplicate_aci_and_mlo_are_explicit() {
    let mut bytes = wmm(Role::AccessPoint);
    bytes[12] = bytes[8];
    assert!(Wmm::parse(&bytes, Role::AccessPoint).is_err());
    bytes = wmm(Role::AccessPoint);
    bytes[9] = 0x23;
    assert!(Wmm::parse(&bytes, Role::AccessPoint).is_err());
    bytes = modern_ies(Band::Ghz5, Role::Station, 12, false);
    extension(&mut bytes, 107, &[]);
    assert!(matches!(
        Capabilities::parse(Band::Ghz5, Role::Station, &bytes),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn unchanged_linux_directional_mcs_and_sizing_helpers_match_complete_oracle() {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for nss in 0..8 {
        for own_rx in 0..4 {
            for own_tx in 0..4 {
                for peer_rx in 0..4 {
                    for peer_tx in 0..4 {
                        let shift = nss * 2;
                        let mask = !(3_u16 << shift);
                        let own = McsMaps {
                            rx: mask | own_rx << shift,
                            tx: mask | own_tx << shift,
                        };
                        let peer = McsMaps {
                            rx: mask | peer_rx << shift,
                            tx: mask | peer_tx << shift,
                        };
                        let result = McsMaps::intersect(own, peer);
                        hash.update(result.rx.to_le_bytes());
                        hash.update(result.tx.to_le_bytes());
                    }
                }
            }
        }
    }
    for enabled in [false, true] {
        for header in 0..=255_u8 {
            hash.update([if enabled {
                caps::he_ppe_len(header) as u8
            } else {
                0
            }]);
        }
    }
    for enabled in [false, true] {
        for header in 0..512_u16 {
            hash.update([if enabled {
                caps::eht_ppe_len(header) as u8
            } else {
                0
            }]);
        }
    }
    for phy0 in 0..=255_u8 {
        let h = caps::He::parse(&he(phy0)).unwrap();
        for width320 in [false, true] {
            for role in [Role::Station, Role::AccessPoint] {
                let mut accepted = None;
                for count in [3, 4, 6, 9] {
                    let mut bytes = vec![0; 11 + count];
                    bytes[2] = if width320 { 2 } else { 0 };
                    if caps::Eht::parse(&bytes, &h, role).is_ok() {
                        assert!(accepted.replace(count).is_none());
                    }
                }
                hash.update([accepted.unwrap() as u8]);
            }
        }
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "b65d15db624c62db45cb60b3c2d1b426a1cbb7e496e0af8d76b1a6c88c37e26c"
    );
}

#[test]
fn full_eht_maps_keep_each_width_direction_and_source_union_distinct() {
    let (mut local, mut peer) = pair(Band::Ghz6, 12, true);
    let own = [0x12, 0x34, 0x56, 0x23, 0x45, 0x67, 0x34, 0x56, 0x78];
    let ap = [0x87, 0x65, 0x43, 0x76, 0x54, 0x32, 0x65, 0x43, 0x21];
    for (cap, raw, role) in [
        (&mut local, own, Role::Station),
        (&mut peer, ap, Role::AccessPoint),
    ] {
        let mut bytes = eht(12, role, true);
        bytes[11..20].copy_from_slice(&raw);
        cap.eht = Some(Eht::parse(&bytes, cap.he().unwrap(), role).unwrap());
    }
    let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz160).unwrap();
    let map = n.eht.unwrap();
    assert_eq!(map.peer_source_mcs_union.bytes(), &ap);
    assert_eq!(map.peer_source_mcs_union.wire_len(), 9);
    assert_eq!(map.common.bw20, Some([0x21, 0x21, 0x43, 0x43]));
    assert_eq!(map.common.bw80, map.common.bw20);
    assert_eq!(map.common.bw160, Some([0x32, 0x32, 0x54, 0x32]));
    assert_eq!(map.common.bw320, Some([0x43, 0x43, 0x43, 0x21]));
    assert_eq!(map.ranges, map.common.bw160.unwrap());
    assert_ne!(&map.ranges[..3], &map.peer_source_mcs_union.bytes()[..3]);
}

#[test]
fn twenty_only_sta_four_groups_do_not_shift_the_ap_three_group_source_overlay() {
    let (mut local, mut peer) = pair(Band::Ghz5, 0, false);
    let mut own = eht(0, Role::Station, false);
    own[11..].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    local.eht = Some(Eht::parse(&own, local.he().unwrap(), Role::Station).unwrap());
    let mut ap = eht(0, Role::AccessPoint, false);
    ap[11..].copy_from_slice(&[0x87, 0x65, 0x43]);
    peer.eht = Some(Eht::parse(&ap, peer.he().unwrap(), Role::AccessPoint).unwrap());
    let n = Negotiated::between(&local, &peer, Mode::Eht, Width::Mhz20).unwrap();
    let map = n.eht.unwrap();
    assert_eq!(map.ranges, [0x21, 0x43, 0x65, 0x43]);
    assert_eq!(map.common.bw20, Some(map.ranges));
    assert_eq!(map.common.bw80, None);
    assert_eq!(map.common.bw160, None);
    assert_eq!(map.common.bw320, None);
    assert_eq!(
        local.eht().unwrap().source_mcs_union().bytes(),
        &[0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0]
    );
    assert_eq!(local.eht().unwrap().source_mcs_union().wire_len(), 4);
    assert_eq!(
        map.peer_source_mcs_union.bytes(),
        &[0x87, 0x65, 0x43, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(map.peer_source_mcs_union.wire_len(), 3);
}

#[test]
fn complete_unchanged_linux_eht_station_union_oracle() {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut cases = 0;
    for phy0 in 0..=255 {
        for wide320 in [false, true] {
            for role in [Role::Station, Role::AccessPoint] {
                let he = He::parse(&he(phy0)).unwrap();
                let mut bytes = eht(phy0, role, wide320);
                for (i, octet) in bytes[11..].iter_mut().enumerate() {
                    *octet = 0x11 * (1 + i as u8 % 8);
                }
                for available in [false, true] {
                    for extra in [-1_i32, 0, 1] {
                        cases += 1;
                        if !available || extra < 0 {
                            hash.update([0; 10]);
                        } else {
                            let parsed = Eht::parse(&bytes, &he, role).unwrap();
                            hash.update([1]);
                            hash.update(parsed.source_mcs_union().bytes());
                            assert_eq!(parsed.source_mcs_union().wire_len(), bytes.len() - 11);
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 6144);
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "f1aa36b6d5c91454e1be078fdf8a7557367687f48448b669742387785110f5aa"
    );
}
