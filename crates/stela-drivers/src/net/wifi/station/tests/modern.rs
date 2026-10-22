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
fn peer_basic_mcs_requirements_and_response_basic_rates_are_enforced() {
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
        assert!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(bytes)
            )
            .is_err(),
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
