// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek EDCA validation fixtures.
use super::*;

#[test]
fn peer_channel_and_receiver_preflight() {
    let (mut driver, model, _, _) = secure_modern();
    let before = commands(&model);
    for field in [4, 10, 16] {
        let mut frame = beacon(&driver, 1, |_| {});
        frame[field] ^= 2;
        assert!(observe(&mut driver, &model, &frame).is_err());
        assert!(!driver.pending_edca());
    }
    struct Channels;
    impl station::RegulatoryPolicy for Channels {
        fn allow_management_tx(&mut self, _: wifi::Channel) -> bool {
            true
        }
        fn allow_data_tx(&mut self, _: wifi::Channel) -> bool {
            true
        }
    }
    impl scan::Policy for Channels {
        fn allow_receive(&mut self, _: wifi::Channel) -> bool {
            true
        }
        fn allow_probe(&mut self, _: wifi::Channel) -> bool {
            true
        }
        fn lookup_channel(&mut self, band: Band, number: u16) -> Option<wifi::Channel> {
            (band == Band::Ghz5 && matches!(number, 36 | 40)).then_some(wifi::Channel {
                band,
                number,
                frequency_mhz: 5000 + number * 5,
            })
        }
    }
    let frame = beacon(&driver, 1, |_| {});
    let mut raw = incoming_bytes(&frame, None, false);
    raw[13] = 40; // Actual RXD3 CH_FREQ, independently accepted by source policy.
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    assert!(matches!(
        driver.poll(NOW, &Source, &mut Channels),
        Err(ClientError::WrongProfile)
    ));
    assert!(!driver.pending_edca());
    let mut corrupt = frame;
    corrupt[1] |= 0x04; // More fragments: no dynamic observation authority.
    assert!(observe(&mut driver, &model, &corrupt).is_err());
    assert_eq!(commands(&model), before);
}

#[test]
fn malformed_wmm_cancels_pending_update() {
    let (mut driver, model, _, _) = secure_modern();
    let before = commands(&model);
    for change in [0, 1, 3, 4, 5] {
        let valid = beacon(&driver, 1, |_| {});
        observe(&mut driver, &model, &valid).unwrap();
        assert!(driver.pending_edca());
        let mut invalid = beacon(&driver, 2, |w| match change {
            0 => w[12] = w[8], // Duplicate ACI.
            1 => w[9] = 0x20,  // Source dynamic CWmin0 invalid.
            3 => w[6] ^= 0x80, // U-APSD renegotiation is separate.
            4 => w[8] = 1,
            _ => {} // Explicit strict parser AIFSN limit.
        });
        if change == 5 {
            invalid.extend_from_slice(&[255, 1, 38]);
        }
        assert!(observe(&mut driver, &model, &invalid).is_err());
        assert!(!driver.pending_edca());
        assert_eq!(commands(&model), before);
        assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 0);
    }
}

#[test]
fn key_installation_invalidates_observation() {
    let (mut driver, model, _) = awaiting();
    let (mut owner, _) = authority(&driver, &model);
    let permit = admit(&mut owner, &driver, AssociationUse::Configure);
    unsafe { driver.configure_modern(&mut owner, permit, 105) }.unwrap();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    unsafe {
        driver.install_key_modern(&mut owner, permit, true, 0, &[0x77; 16], ReplaySeed::ZERO)
    }
    .unwrap();
    let before = commands(&model);
    assert!(matches!(
        update(&mut driver, &mut owner, None),
        Err(ClientError::Station(station::Error::Stale))
    ));
    assert_eq!(commands(&model), before);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 0);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    let frame = beacon(&driver, 2, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    update(&mut driver, &mut owner, None).unwrap();
}
