use super::*;
use crate::net::wifi::scan::result::{Bss, Kind};
use crate::net::wifi::station::phy::{Mode, Width};

fn ie(out: &mut Vec<u8>, id: u8, b: &[u8]) {
    out.extend_from_slice(&[id, b.len() as u8]);
    out.extend_from_slice(b);
}
fn extension(out: &mut Vec<u8>, id: u8, b: &[u8]) {
    let mut v = vec![id];
    v.extend_from_slice(b);
    ie(out, 255, &v);
}
impl crate::net::wifi::scan::Policy for Policy {
    fn allow_receive(&mut self, _: Channel) -> bool {
        self.0
    }
    fn allow_probe(&mut self, _: Channel) -> bool {
        self.0
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        Some(Channel {
            band,
            number,
            frequency_mhz: 5180,
        })
    }
}
fn modern_ies(ap: bool) -> Vec<u8> {
    let mut out = vec![0, 1, b'x', 1, 3, 0x8c, 0x98, 0xb0];
    let mut ht = [0; 26];
    ht[0] = 2;
    ht[2] = 3;
    ht[3] = 0xff;
    ht[15] = 1;
    ie(&mut out, 45, &ht);
    let mut vht = [0; 12];
    vht[..4].copy_from_slice(&4_u32.to_le_bytes());
    vht[4..6].copy_from_slice(&0xfffe_u16.to_le_bytes());
    vht[8..10].copy_from_slice(&0xfffe_u16.to_le_bytes());
    ie(&mut out, 191, &vht);
    let mut he = vec![0; 17];
    he[6] = 12;
    for _ in 0..2 {
        he.extend_from_slice(&[0xfe, 0xff, 0xfe, 0xff]);
    }
    extension(&mut out, 35, &he);
    let mut eht = vec![0; 11];
    eht.extend_from_slice(&[0x11; 6]);
    extension(&mut out, 108, &eht);
    if ap {
        ie(
            &mut out,
            221,
            &[
                0, 0x50, 0xf2, 2, 1, 1, 0x80, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94,
                0, 0x62, 0x32, 47, 0,
            ],
        );
        let mut ht_op = [0; 22];
        ht_op[0] = 36;
        ht_op[1] = 5;
        ht_op[2] = 3;
        ie(&mut out, 61, &ht_op);
        ie(&mut out, 192, &[1, 42, 0, 0xff, 0xff]);
        extension(&mut out, 36, &[3, 0x20, 0, 0x2a, 0xff, 0xff]);
        extension(&mut out, 106, &[1, 0, 0, 0, 0, 2, 42, 0]);
        ie(&mut out, 5, &[0, 3, 0, 0]);
    } else {
        ie(&mut out, 221, &[0, 0x50, 0xf2, 2, 0, 1, 0]);
    }
    out
}
fn modern_join() -> Join {
    let mut j = join(PortPolicy::Open);
    j.request = wire::AssociationRequest::new_modern(
        1,
        10,
        modern_ies(false),
        Band::Ghz5,
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap();
    j
}
fn beacon(j: &Join) -> Bss {
    let scan = crate::net::wifi::scan::Scanner::new(LOCAL)
        .unwrap()
        .begin(
            crate::net::wifi::scan::Request::new(vec![j.channel], vec![], vec![]).unwrap(),
            0,
            100,
            &mut Policy(true),
        )
        .unwrap();
    Bss {
        ticket: scan,
        kind: Kind::Beacon,
        bssid: AP,
        transmitter: AP,
        timestamp: 100,
        beacon_interval: 100,
        capabilities: 1,
        channel: j.channel,
        observed: response(0xb0, &[0; 6]).radio,
        signal_dbm: Some(-45),
        ssid: Some(vec![b'x']),
        elements: modern_ies(true),
    }
}
fn configuration(s: &mut Station, j: Join, bss: Bss) -> Result<Action, Error> {
    let start = s.now;
    let a = s.begin_modern(j, bss, start, &mut Policy(true))?;
    s.submitted(ticket(&a))?;
    let a = s.receive(
        s.association_epoch().unwrap(),
        &response(0xb0, &[0, 0, 2, 0, 0, 0]),
        start + 1,
        &mut Policy(true),
    )?;
    s.submitted(ticket(&a))?;
    let mut body = vec![1, 0, 0, 0, 1, 0xc0];
    body.extend_from_slice(&modern_ies(true));
    s.receive(
        s.association_epoch().unwrap(),
        &response(0x10, &body),
        start + 2,
        &mut Policy(true),
    )
}
#[test]
fn modern_configuration_is_retained_bound_and_invalidated_before_removal() {
    let mut s = Station::new(LOCAL).unwrap();
    let j = modern_join();
    assert!(matches!(
        s.begin(j.clone(), 0, &mut Policy(true)),
        Err(Error::Unsupported(_))
    ));
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    let Action::Configure {
        ticket,
        context: Some(context),
        ..
    } = a
    else {
        panic!("modern context required")
    };
    assert_eq!(context.ticket(), ticket);
    assert_eq!(context.bssid(), AP);
    assert_eq!(context.definition().center1_mhz, 5210);
    assert_eq!(context.definition().width, Width::Mhz80);
    assert_eq!(context.dtim_period(), 3);
    assert_eq!(context.negotiated().mode, Mode::Eht);
    assert_eq!(context.operations().ht.as_ref().unwrap().protection, 3);
    let he = context.operations().he.as_ref().unwrap();
    assert_eq!(
        (he.packet_extension(), he.rts_threshold(), he.color()),
        (3, 512, 42)
    );
    s.validate_association_context(&context).unwrap();
    s.complete_configuration(ticket, Completion::Accepted, 3)
        .unwrap();
    s.validate_association_context(&context).unwrap();
    let removal = s.disconnect().unwrap();
    assert!(s.validate_association_context(&context).is_err());
    assert!(s.association_context().is_none());
    s.complete_removal(super::ticket(&removal), Completion::Accepted)
        .unwrap();
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    let Action::Configure {
        context: Some(next),
        ..
    } = a
    else {
        panic!()
    };
    assert_ne!(next.ticket().epoch(), context.ticket().epoch());
    assert!(s.validate_association_context(&context).is_err());
    s.validate_association_context(&next).unwrap();
}
#[test]
fn modern_uncertainty_retains_configuration_but_never_usable_identity() {
    let mut s = Station::new(LOCAL).unwrap();
    let j = modern_join();
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    let Action::Configure {
        ticket,
        context: Some(context),
        ..
    } = a
    else {
        panic!()
    };
    s.complete_configuration(ticket, Completion::Uncertain, 3)
        .unwrap();
    assert!(s.association_context().is_none());
    assert!(s.validate_association_context(&context).is_err());
    assert!(s.context.is_some());
    assert!(!s.port_open(None, None));
    assert!(matches!(
        s.begin_modern(j.clone(), beacon(&j), 4, &mut Policy(true)),
        Err(Error::Busy)
    ));
}
#[test]
fn selected_beacon_timing_peer_ssid_and_width_are_required_not_defaulted() {
    let j = modern_join();
    for damage in 0..6 {
        let mut b = beacon(&j);
        match damage {
            0 => b.beacon_interval = 0,
            1 => b.kind = Kind::ProbeResponse,
            2 => b.ssid = Some(vec![b'y']),
            3 => b.elements.truncate(b.elements.len() - 6),
            4 => {
                let n = b.elements.len();
                b.elements[n - 3] = 0;
            }
            _ => b.transmitter = LOCAL,
        }
        assert!(
            configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), b).is_err(),
            "damage {damage}"
        );
    }
    let mut j = modern_join();
    j.request = wire::AssociationRequest::new_modern(
        1,
        10,
        modern_ies(false),
        Band::Ghz5,
        Mode::Eht,
        Width::Mhz160,
    )
    .unwrap();
    assert!(configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), beacon(&j)).is_err());
}

fn response_metadata(elements: Vec<u8>) -> wire::AssociationResponse {
    wire::AssociationResponse {
        capabilities: 1,
        status: 0,
        raw_aid: 0xc001,
        aid: 1,
        power_save_allowed: true,
        elements,
    }
}
fn filtered(mut bytes: &[u8], remove: impl Fn(u8, &[u8]) -> bool) -> Vec<u8> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let length = usize::from(bytes[1]);
        let b = &bytes[2..2 + length];
        if !remove(bytes[0], b) {
            out.extend_from_slice(&bytes[..2 + length]);
        }
        bytes = &bytes[2 + length..];
    }
    out
}
#[test]
fn generic_missing_ht_vht_wmm_fallback_retains_actual_beacon_but_not_he_eht() {
    let j = modern_join();
    let b = beacon(&j);
    let elements = filtered(&modern_ies(true), |id, _| {
        matches!(id, 45 | 61 | 191 | 192 | 221)
    });
    let response = response_metadata(elements);
    let context = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response,
    )
    .unwrap();
    assert!(context.negotiated().wmm.is_some());
    assert!(context.operations().ht.is_some());
    assert_eq!(context.response().elements, response.elements);
    for id in [35, 36, 106, 108] {
        let elements = filtered(&modern_ies(true), |other, b| other == 255 && b[0] == id);
        assert!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(elements)
            )
            .is_err()
        );
    }
}
#[test]
fn normal_basic_rules_keep_he_eht_and_real_rates_but_not_strict_only_ht_checks() {
    let j = modern_join();
    let b = beacon(&j);
    for kind in 0..4 {
        let mut bytes = modern_ies(true);
        let mut rest = bytes.as_mut_slice();
        while !rest.is_empty() {
            let length = usize::from(rest[1]);
            let id = rest[0];
            let data = &mut rest[2..2 + length];
            match kind {
                0 if id == 1 => data[1] &= 0x7f,
                1 if id == 61 => data[7] = 1,
                2 if id == 255 && data[0] == 36 => {
                    data[5] = 0xf0;
                    data[6] = 0xff;
                }
                3 if id == 255 && data[0] == 106 => data[2] = 2,
                _ => (),
            }
            rest = &mut rest[2 + length..];
        }
        assert_eq!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(bytes)
            )
            .is_ok(),
            kind == 1,
            "kind{kind}"
        );
    }
}

#[test]
fn final_vht_operation_uses_actual_source_capability_width_not_raw_segments_alone() {
    let mut j = modern_join();
    j.request = wire::AssociationRequest::new_modern(
        1,
        10,
        modern_ies(false),
        Band::Ghz5,
        Mode::He,
        Width::Mhz160,
    )
    .unwrap();
    let mut b = beacon(&j);
    let mut elements = modern_ies(true);
    for bytes in [&mut b.elements, &mut elements] {
        let mut rest = bytes.as_mut_slice();
        while !rest.is_empty() {
            let n = usize::from(rest[1]);
            if rest[0] == 191 {
                rest[2..6].copy_from_slice(&0_u32.to_le_bytes());
            }
            if rest[0] == 192 {
                rest[4] = 50;
            } // raw ccfs1 suggests160, source ignores it for peer width0.
            rest = &mut rest[2 + n..];
        }
    }
    assert!(
        AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2
            },
            &j,
            &b,
            &response_metadata(elements)
        )
        .is_err()
    );
}

#[test]
fn review_eht_basic_mcs_cannot_ignore_advertised_wider_local_map() {
    let mut local = modern_ies(false);
    let mutate = |bytes: &mut Vec<u8>, own: bool| {
        let mut at = 0;
        while at < bytes.len() {
            let len = usize::from(bytes[at + 1]);
            let id = bytes[at];
            let b = &mut bytes[at + 2..at + 2 + len];
            if id == 255 && b[0] == 108 {
                b[12..15].fill(0x22);
                b[15..18].fill(if own { 0x11 } else { 0x22 });
            }
            if id == 255 && b[0] == 106 {
                b[2..6].fill(0x22);
            }
            at += 2 + len;
        }
    };
    mutate(&mut local, true);
    let mut j = modern_join();
    j.request =
        wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, Mode::Eht, Width::Mhz80)
            .unwrap();
    let mut b = beacon(&j);
    mutate(&mut b.elements, false);
    let mut elements = modern_ies(true);
    mutate(&mut elements, false);
    let result = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(elements),
    );
    assert!(
        result.is_err(),
        "local advertised160 map fails actual EHT basic2NSS even when selected80 passes, got {result:?}"
    );
}

#[test]
fn basic_eht_local_rx_tx_orientation_is_not_selected_common_orientation() {
    fn maps(bytes: &mut [u8], cap: u8, basic: u8) {
        let mut at = 0;
        while at < bytes.len() {
            let n = usize::from(bytes[at + 1]);
            let id = bytes[at];
            let b = &mut bytes[at + 2..at + 2 + n];
            if id == 255 && b[0] == 108 {
                b[12..].fill(cap);
            }
            if id == 255 && b[0] == 106 {
                b[2..6].fill(basic);
            }
            at += 2 + n;
        }
    }
    let mut own = modern_ies(false);
    maps(&mut own, 0x12, 0);
    let mut j = modern_join();
    j.request =
        wire::AssociationRequest::new_modern(1, 10, own, Band::Ghz5, Mode::Eht, Width::Mhz80)
            .unwrap();
    for (basic, accepted) in [(0x12, true), (0x21, false)] {
        let mut beacon = beacon(&j);
        maps(&mut beacon.elements, 0x22, basic);
        let mut response = modern_ies(true);
        maps(&mut response, 0x22, basic);
        let result = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &beacon,
            &response_metadata(response),
        );
        assert_eq!(result.is_ok(), accepted, "basic {basic:#x}: {result:?}");
    }
}

#[test]
fn unselected_ap_mlo_never_changes_single_link_context_bssid_or_outgoing_request() {
    let j = modern_join();
    let mut b = beacon(&j);
    let baseline = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(modern_ies(true)),
    )
    .unwrap();
    let mut raw = Vec::new();
    extension(&mut raw, 107, &[0, 0, 7, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    b.elements.extend_from_slice(&raw);
    let mut response = modern_ies(true);
    response.extend_from_slice(&raw);
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response),
    )
    .unwrap();
    assert_eq!(c.intent(), AssociationIntent::SingleLink);
    assert_eq!(c.bssid(), AP);
    assert_eq!(c.definition(), baseline.definition());
    assert_eq!(c.negotiated().eht, baseline.negotiated().eht);
    assert_eq!(c.negotiated().peer().unselected_multi_link_elements(), raw);
    assert!(
        j.request
            .modern()
            .unwrap()
            .capabilities()
            .unselected_multi_link_elements()
            .is_empty()
    );
    assert_eq!(j.request.elements(), modern_ies(false));
    let mut requested = modern_ies(false);
    requested.extend_from_slice(&raw);
    assert!(matches!(
        wire::AssociationRequest::new_modern(1, 10, requested, Band::Ghz5, Mode::Eht, Width::Mhz80),
        Err(wire::Error::Unsupported(_))
    ));
}
#[test]
fn malformed_unselected_ml_body_and_fragment_cannot_replace_single_link_operation() {
    let j = modern_join();
    let mut b = beacon(&j);
    let mut response = modern_ies(true);
    let mut body = vec![0; 254];
    body[..3].copy_from_slice(&[7, 0, 255]);
    let mut raw = Vec::new();
    extension(&mut raw, 107, &body);
    ie(&mut raw, 242, &[61, 2, 149, 3, 192, 3, 3, 155, 171]);
    b.elements.extend_from_slice(&raw);
    response.extend_from_slice(&raw);
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response),
    )
    .unwrap();
    assert_eq!(c.intent(), AssociationIntent::SingleLink);
    assert_eq!(c.bssid(), AP);
    assert_eq!(c.channel().number, 36);
    assert_eq!(c.definition().center1_mhz, 5210);
    assert_eq!(c.negotiated().peer().unselected_multi_link_elements(), raw);
}

#[test]
fn review_source_eht_basic_local_support_does_not_require_peer_common_envelope() {
    let mutate = |bytes: &mut Vec<u8>, own: bool| {
        let mut at = 0;
        while at < bytes.len() {
            let len = usize::from(bytes[at + 1]);
            let id = bytes[at];
            let b = &mut bytes[at + 2..at + 2 + len];
            if id == 255 && b[0] == 108 {
                b[12..18].fill(if own { 0x22 } else { 0x12 });
            }
            if id == 255 && b[0] == 106 {
                b[2..6].fill(0x22);
            }
            at += 2 + len;
        }
    };
    let mut local = modern_ies(false);
    mutate(&mut local, true);
    let mut j = modern_join();
    j.request =
        wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, Mode::Eht, Width::Mhz80)
            .unwrap();
    assert!(
        j.request
            .modern()
            .unwrap()
            .capabilities()
            .meets_eht_basic([0x22; 4])
    );
    let mut b = beacon(&j);
    mutate(&mut b.elements, false);
    let mut elements = modern_ies(true);
    mutate(&mut elements, false);
    let peer = phy::Capabilities::parse(Band::Ghz5, phy::Role::AccessPoint, &elements).unwrap();
    let n = phy::Negotiated::between(
        j.request.modern().unwrap().capabilities(),
        &peer,
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap();
    assert!(n.rx_nss > 0 && n.tx_nss > 0);
    let result = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(elements),
    );
    assert!(
        result.is_ok(),
        "source local requirement passes; usable asymmetric common envelope is not a second Basic predicate: {result:?}"
    );
}

fn edit_elements(mut bytes: &mut [u8], mut edit: impl FnMut(u8, &mut [u8])) {
    while !bytes.is_empty() {
        let n = usize::from(bytes[1]);
        let id = bytes[0];
        edit(id, &mut bytes[2..2 + n]);
        bytes = &mut bytes[2 + n..];
    }
}
#[test]
fn default_ht_vht_basic_claims_remain_raw_without_rejecting_usable_profiles() {
    for (mode, width) in [(Mode::Ht, Width::Mhz40), (Mode::Vht, Width::Mhz80)] {
        for basic in [0, 0x5555_u16, 0xffff] {
            let mut j = modern_join();
            j.request = wire::AssociationRequest::new_modern(
                1,
                10,
                modern_ies(false),
                Band::Ghz5,
                mode,
                width,
            )
            .unwrap();
            let mut b = beacon(&j);
            let mut response = modern_ies(true);
            for bytes in [&mut b.elements, &mut response] {
                edit_elements(bytes, |id, data| {
                    if id == 61 {
                        data[6..16].fill(0xff);
                    }
                    if id == 192 {
                        data[3..5].copy_from_slice(&basic.to_le_bytes());
                    }
                });
            }
            let c = AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2,
                },
                &j,
                &b,
                &response_metadata(response),
            )
            .unwrap();
            assert_eq!(c.negotiated().mode, mode);
            assert_eq!(c.definition().width, width);
            assert!(c.negotiated().rx_nss > 0 && c.negotiated().tx_nss > 0);
            assert_eq!(
                &c.operations().ht.as_ref().unwrap().basic_mcs[..10],
                &[0xff; 10]
            );
            assert_eq!(c.operations().vht.as_ref().unwrap().basic_mcs, basic);
        }
    }
}
#[test]
fn zero_he_basic_compatibility_cannot_invent_streams_or_bypass_peer_one_ss() {
    let j = modern_join();
    let b = beacon(&j);
    let mut response = modern_ies(true);
    edit_elements(&mut response, |id, data| {
        if id == 255 && data[0] == 36 {
            data[5..7].fill(0);
        }
    });
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response.clone()),
    )
    .unwrap();
    assert_eq!((c.negotiated().rx_nss, c.negotiated().tx_nss), (1, 1));
    assert_eq!(c.operations().he.as_ref().unwrap().basic_mcs, 0);
    for start in [18, 20] {
        let mut broken = response.clone();
        edit_elements(&mut broken, |id, data| {
            if id == 255 && data[0] == 35 {
                data[start..start + 2].fill(0xff);
            }
        });
        assert!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(broken)
            )
            .is_err()
        );
    }
}
#[test]
fn full_local_he_source_slots_are_explicit_and_preserve_normal_one_width_semantics() {
    let own = modern_ies(false);
    let local = phy::Capabilities::parse(Band::Ghz5, phy::Role::Station, &own).unwrap();
    let he = local.he().unwrap();
    let m = he.mcs_80;
    let source = [m, he.mcs_160.unwrap(), phy::McsMaps { rx: 0, tx: 0 }];
    assert_eq!(he.mcs_80p80, None);
    assert_eq!(local.local_he_source_maps(), None);
    let mut j = modern_join();
    let mut b = beacon(&j);
    let mut response = modern_ies(true);
    for bytes in [&mut b.elements, &mut response] {
        edit_elements(bytes, |id, data| {
            if id == 255 && data[0] == 35 {
                data[18..22].copy_from_slice(&[0xf0, 0xff, 0xf0, 0xff]);
            }
            if id == 255 && data[0] == 36 {
                data[5..7].copy_from_slice(&0xfff0_u16.to_le_bytes());
            }
        });
    }
    let result = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response.clone()),
    );
    assert!(matches!(
        result,
        Err(Error::Phy(phy::Error::Missing(
            "complete local HE source MCS slots"
        )))
    ));
    let local = local.with_local_he_source_maps(source).unwrap();
    let mut changed = own.clone();
    edit_elements(&mut changed, |id, b| {
        if id == 45 {
            b[0] ^= 1;
        }
    });
    assert!(
        wire::AssociationRequest::new_modern_with_local(
            1,
            10,
            changed,
            local.clone(),
            Mode::Eht,
            Width::Mhz80
        )
        .is_err()
    );
    j.request =
        wire::AssociationRequest::new_modern_with_local(1, 10, own, local, Mode::Eht, Width::Mhz80)
            .unwrap();
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response),
    )
    .unwrap();
    assert_eq!(c.negotiated().local().local_he_source_maps(), Some(&source));
    assert_eq!(c.negotiated().local().he().unwrap().mcs_80p80, None);
    assert_eq!((c.negotiated().rx_nss, c.negotiated().tx_nss), (1, 1));
}

#[test]
fn transmitted_bssid_ignores_opaque_nested_profiles_and_keeps_outer_facts() {
    let j = modern_join();
    let mut bss = beacon(&j);
    let mut nested = vec![1, 0, 25]; // max indicator, opaque subelement
    ie(&mut nested, 83, &[0x11, 0]);
    ie(&mut nested, 0, b"other");
    ie(&mut nested, 85, &[1, 9, 8]);
    ie(&mut nested, 3, &[149]);
    ie(&mut nested, 48, &[1, 0, 0, 0]);
    ie(&mut bss.elements, 71, &nested);
    // An invalid inner subelement still cannot become profile authority.
    ie(&mut bss.elements, 71, &[255, 0, 255]);
    let raw = bss.elements.clone();
    let mut station = Station::new(LOCAL).unwrap();
    let Action::Configure {
        context: Some(c), ..
    } = configuration(&mut station, j.clone(), bss).unwrap()
    else {
        panic!("modern context")
    };
    assert_eq!(c.bssid(), j.bssid);
    assert_eq!(c.beacon().transmitter, j.bssid);
    assert_eq!(c.beacon().ssid, Some(vec![b'x']));
    assert_eq!(c.beacon().capabilities, 1);
    assert_eq!(c.beacon().elements, raw);
    assert_eq!((c.dtim_count(), c.dtim_period()), (0, 3));
    assert_eq!(c.channel(), j.channel);
    assert_eq!(c.definition().center1_mhz, 5210);
    assert_eq!(c.operations().ht.as_ref().unwrap().primary, 36);
}

#[test]
fn transmitted_bssid_retains_outer_bounds_and_refuses_profile_selection() {
    let j = modern_join();
    let mut bss = beacon(&j);
    bss.elements.extend_from_slice(&[71, 5, 1]);
    assert!(configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), bss).is_err());
    let mut bss = beacon(&j);
    ie(&mut bss.elements, 85, &[1, 9, 8]);
    assert!(matches!(
        configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), bss),
        Err(Error::Unsupported(_))
    ));
    let mut bss = beacon(&j);
    bss.transmitter = Mac([4; 6]);
    ie(&mut bss.elements, 71, &[1]);
    assert!(matches!(
        configuration(&mut Station::new(LOCAL).unwrap(), j, bss),
        Err(Error::Unsupported(_))
    ));
}

mod regulatory;
