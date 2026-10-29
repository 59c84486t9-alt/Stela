// SPDX-License-Identifier: GPL-2.0-only
//! Authored pure protocol controls; these do not check a native receiver.
use super::*;
use alloc::vec;

// Pinned hid-logitech-dj.c's distinct short/long Application profile, authored
// as a transport peer. This is not an observed physical receiver descriptor.
pub(super) const PROFILE: &[u8] = &[
    0x06, 0, 0xff, 9, 1, 0xa1, 1, 0x85, 0x10, 0x75, 8, 0x95, 6, 0x15, 0, 0x26, 0xff, 0, 9, 1, 0x81,
    0, 9, 1, 0x91, 0, 0xc0, 0x06, 0, 0xff, 9, 2, 0xa1, 1, 0x85, 0x11, 0x75, 8, 0x95, 19, 0x15, 0,
    0x26, 0xff, 0, 9, 2, 0x81, 0, 9, 2, 0x91, 0, 0xc0,
];
fn group() -> Group {
    Group {
        controller: Weak::new(),
        id: SlotId::fixture(1),
        configuration: 1,
        configuration_descriptor: vec![9, 2, 9, 0, 1, 1, 0, 0x80, 0],
        members: vec![Member {
            interface: 2,
            endpoint: Endpoint {
                address: 0x81,
                attributes: 3,
                max_packet: 32,
                interval: 1,
                companion: None,
            },
            descriptor: PROFILE.to_vec(),
            active: true,
        }],
        vendor: 0,
        initialization: Initialization::ArmInput,
        routes: (1..=7).map(Logical::new).collect(),
        pending: None,
        first_error: None,
    }
}
fn listen(g: &mut Group) {
    for _ in 0..2 {
        let out = g.next(0).unwrap();
        g.acknowledge(&out, 0);
    }
    assert_eq!(g.initialization, Initialization::QueryAcknowledged);
}
fn notification(slot: u8, id: u8) -> [u8; 7] {
    [SHORT, slot, CONNECTION, 0x0c, 2, id, 0]
}
fn version(g: &Group, major: u8) -> Vec<u8> {
    let p = g.pending.as_ref().unwrap();
    vec![
        SHORT,
        p.slot,
        ROOT,
        VERSION_FUNCTION | p.software_id,
        major,
        0,
        p.nonce,
    ]
}
fn feature(g: &Group, index: u8) -> Vec<u8> {
    let p = g.pending.as_ref().unwrap();
    let mut b = vec![0; LONG_BYTES];
    b[..5].copy_from_slice(&[LONG, p.slot, ROOT, p.software_id, index]);
    b
}

#[test]
fn separate_primary_applications_and_exact_byte_profiles_are_required() {
    assert!(transport::profile(&Descriptor::parse(PROFILE).unwrap()));
    let mut bad = PROFILE.to_vec();
    bad[31] = 3; // Long Application's Usage changes.
    assert!(!transport::profile(&Descriptor::parse(&bad).unwrap()));
    let mut bad = PROFILE.to_vec();
    bad[39] = 18; // Long report count changes.
    assert!(!transport::profile(&Descriptor::parse(&bad).unwrap()));
    for flags in [4, 0x40] {
        let mut bad = PROFILE.to_vec();
        bad[21] = flags;
        assert!(!transport::profile(&Descriptor::parse(&bad).unwrap()));
    }
    let mut split = vec![
        6, 0, 0xff, 9, 1, 0xa1, 1, 0x85, 0x10, 0x75, 8, 0x95, 3, 0x15, 0, 0x26, 0xff, 0, 9, 1,
        0x81, 0, 0xc0, 9, 1, 0xa1, 1, 9, 1, 0x81, 0, 0x95, 6, 9, 1, 0x91, 0, 0xc0,
    ];
    split.extend_from_slice(&PROFILE[27..]);
    assert!(
        !transport::profile(&Descriptor::parse(&split).unwrap()),
        "equal usage does not merge actual Application identities"
    );
}

#[test]
fn usb_status_ack_does_not_publish_protocol_or_feature_authority() {
    let mut g = group();
    let enable = g.next(0).unwrap();
    assert_eq!(enable.bytes, [SHORT, RECEIVER, 0x80, 0, 0, 9, 0]);
    assert_eq!(g.initialization, Initialization::Enabling);
    assert!(g.snapshot().routes.is_empty());
    g.acknowledge(&enable, 0);
    let query = g.next(1).unwrap();
    assert_eq!(query.bytes, [SHORT, RECEIVER, 0x80, 2, 2, 0, 0]);
    g.acknowledge(&query, 1);
    assert!(g.snapshot().routes.is_empty());
    g.observe(&notification(2, 7), 2);
    let out = g.next(2).unwrap();
    assert_eq!(out.bytes, [SHORT, 2, ROOT, 0x11, 0, 0, 1]);
    let answer = version(&g, 2);
    g.observe(&answer, 3);
    assert!(
        g.routes[1].view.version.is_none(),
        "reply before USB ACK cannot grant authority"
    );
    g.acknowledge(&out, 4);
    g.observe(&answer, 5);
    assert_eq!(
        g.routes[1].view.version,
        Some(Version { major: 2, minor: 0 })
    );
    assert!(g.routes[1].view.feature.is_none());
}

#[test]
fn exact_slot_header_error_form_and_nonce_correlate_before_publication() {
    let mut g = group();
    listen(&mut g);
    g.observe(&notification(1, 1), 0);
    let out = g.next(0).unwrap();
    g.acknowledge(&out, 0);
    let good = version(&g, 2);
    for (at, value) in [(1, 2), (2, 1), (3, 0x12)] {
        let mut wrong = good.clone();
        wrong[at] = value;
        g.observe(&wrong, 1);
        assert!(g.pending.is_some());
    }
    let mut wrong = good.clone();
    wrong[6] = 0x77;
    g.observe(&wrong, 2);
    assert_eq!(g.routes[0].view.error, Some(Error::InvalidNonce));
    assert!(g.pending.is_none());
    g.observe(&notification(1, 2), 3);
    let out = g.next(3).unwrap();
    g.acknowledge(&out, 3);
    assert_eq!(g.pending.as_ref().unwrap().software_id, 2);
    g.observe(&[SHORT, 1, RAP_ERROR, ROOT, 0x11, INVALID_SUBID, 0], 4);
    assert!(
        g.pending.is_some(),
        "old nonce-free1.0 error has consumed softwareID"
    );
    g.observe(&[SHORT, 1, RAP_ERROR, ROOT, 0x12, INVALID_SUBID, 0], 5);
    assert_eq!(
        g.routes[0].view.version,
        Some(Version { major: 1, minor: 0 })
    );
    assert!(
        g.next(6).is_none(),
        "1.0 never receives a FAP feature query"
    );
}

#[test]
fn root_feature_is_observed_metadata_and_duplicate_replies_are_not_reused() {
    let mut g = group();
    listen(&mut g);
    g.observe(&notification(1, 1), 0);
    let out = g.next(0).unwrap();
    g.acknowledge(&out, 0);
    g.observe(&version(&g, 2), 1);
    let out = g.next(1).unwrap();
    assert_eq!(&out.bytes[..6], &[LONG, 1, ROOT, 1, 0x1d, 0x4b]);
    g.acknowledge(&out, 1);
    let short = [
        SHORT,
        1,
        ROOT,
        g.pending.as_ref().unwrap().software_id,
        9,
        0,
        0,
    ];
    g.observe(&short, 2);
    assert!(
        g.pending.is_some(),
        "short positive FAP answer is not accepted"
    );
    let mut wrong_error = vec![0; LONG_BYTES];
    wrong_error[..6].copy_from_slice(&[
        LONG,
        1,
        RAP_ERROR,
        ROOT,
        g.pending.as_ref().unwrap().software_id,
        1,
    ]);
    g.observe(&wrong_error, 2);
    assert!(g.pending.is_some());
    let wrong_error = [
        SHORT,
        1,
        FAP_ERROR,
        ROOT,
        g.pending.as_ref().unwrap().software_id,
        1,
        0,
    ];
    g.observe(&wrong_error, 2);
    assert!(g.pending.is_some());
    let first = feature(&g, 9);
    g.observe(&first, 2);
    assert_eq!(
        g.routes[0].view.feature,
        Some(Feature {
            id: WIRELESS_STATUS,
            index: 9
        })
    );
    g.observe(&first, 3);
    assert!(g.pending.is_none());
    g.observe(&notification(1, 2), 4);
    assert!(g.routes[0].view.feature.is_none());
    let out = g.next(4).unwrap();
    g.acknowledge(&out, 4);
    g.observe(&version(&g, 2), 5);
    let out = g.next(5).unwrap();
    g.acknowledge(&out, 5);
    assert_eq!(g.pending.as_ref().unwrap().software_id, 2);
    g.observe(&first, 6);
    assert!(
        g.pending.is_some(),
        "successful old signature is also retired"
    );
    let absent = feature(&g, 0);
    g.observe(&absent, 7);
    assert_eq!(
        g.routes[0].view.feature,
        Some(Feature {
            id: WIRELESS_STATUS,
            index: 0
        })
    );
}

#[test]
fn duplicate_notifications_and_unknown_families_never_mint_extra_routes_or_queries() {
    let mut g = group();
    listen(&mut g);
    for bytes in [
        [SHORT, 0, CONNECTION, 0x0c, 2, 0, 0],
        [SHORT, 8, CONNECTION, 0x0c, 2, 0, 0],
        [SHORT, 1, CONNECTION, 0x55, 2, 0, 0],
        [SHORT, 1, CONNECTION, 0x0c, 9, 0, 0],
    ] {
        g.observe(&bytes, 0);
    }
    assert!(g.snapshot().routes.is_empty());
    g.observe(&notification(1, 1), 0);
    let out = g.next(0).unwrap();
    g.acknowledge(&out, 0);
    let epoch = g.routes[0].view.epoch;
    g.observe(&notification(1, 1), 1);
    assert_eq!(g.routes[0].view.epoch, epoch);
    assert_eq!(g.routes[0].view.version_signatures_used, 1);
    g.observe(&version(&g, 2), 2);
    g.observe(&notification(1, 1), 3);
    assert_eq!(g.routes[0].view.epoch, epoch);
    let mut change = notification(1, 1);
    change[4] |= 0x40;
    g.observe(&change, 4);
    assert_eq!(g.routes[0].view.epoch, epoch + 1);
    assert!(g.routes[0].view.version.is_none());
    let out = g.next(5).unwrap();
    g.acknowledge(&out, 5);
    let old = version(&g, 2);
    let mut unsupported = change;
    unsupported[3] = 0x05;
    g.observe(&unsupported, 6);
    assert!(g.pending.is_none());
    assert!(g.routes[0].view.version.is_none());
    assert_eq!(g.routes[0].view.notification, Some([0x05, 0x42, 1, 0]));
    assert_eq!(g.routes[0].view.error, Some(Error::UnsupportedNotification));
    g.observe(&old, 7);
    assert!(g.next(7).is_none());
    assert!(g.routes[0].view.version.is_none());
}

#[test]
fn deadlines_and_lifecycle_revoke_authority_without_resetting_consumed_signatures() {
    let mut g = group();
    listen(&mut g);
    g.observe(&notification(1, 1), 10);
    let out = g.next(10).unwrap();
    g.acknowledge(&out, 10);
    let old = version(&g, 2);
    g.expire(RESPONSE_US + 10);
    assert_eq!(g.routes[0].view.error, Some(Error::Timeout));
    g.observe(&old, RESPONSE_US + 11);
    assert!(g.routes[0].view.version.is_none());
    g.invalidate(Error::Stopped);
    g.initialization = Initialization::ArmInput;
    listen(&mut g);
    g.observe(&notification(1, 1), RESPONSE_US + 12);
    let out = g.next(RESPONSE_US + 12).unwrap();
    g.acknowledge(&out, RESPONSE_US + 12);
    assert_eq!(g.pending.as_ref().unwrap().software_id, 2);
    g.observe(&old, RESPONSE_US + 13);
    assert!(g.pending.is_some());
}

#[test]
fn all_fifteen_successful_signatures_remain_consumed_until_physical_retirement() {
    let mut g = group();
    listen(&mut g);
    for id in 1..=15 {
        g.observe(&notification(1, id), u64::from(id));
        let out = g.next(u64::from(id)).unwrap();
        g.acknowledge(&out, u64::from(id));
        assert_eq!(g.pending.as_ref().unwrap().software_id, id);
        let reply = version(&g, 2);
        g.observe(&reply, u64::from(id));
        let feature_request = g.next(u64::from(id)).unwrap();
        g.acknowledge(&feature_request, u64::from(id));
        assert_eq!(g.pending.as_ref().unwrap().software_id, id);
        let reply = feature(&g, id);
        g.observe(&reply, u64::from(id));
    }
    g.invalidate(Error::Stopped);
    g.initialization = Initialization::ArmInput;
    listen(&mut g);
    g.observe(&notification(1, 99), 20);
    assert!(g.next(20).is_none());
    assert_eq!(g.routes[0].view.error, Some(Error::SignatureExhausted));
    assert_eq!(g.routes[0].view.version_signatures_used, 15);
    assert_eq!(g.routes[0].view.feature_signatures_used, 15);
    assert!(g.routes[0].view.version.is_none());
}
