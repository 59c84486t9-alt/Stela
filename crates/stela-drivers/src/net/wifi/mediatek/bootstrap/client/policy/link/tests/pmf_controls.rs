// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! A PMF association through the sole owning link, driven as wpa_supplicant
//! drives mac80211: join, EAPOL, keys, then the authorized port.
use super::*;
use crate::net::wifi::mediatek::bootstrap::client::modern::tests::pmf_controls::inputs;
use crate::net::wifi::security::PacketNumber;

#[test]
fn a_pmf_association_opens_its_port_after_the_handshake_keys() {
    let (client, model) = setup_modern();
    let (join, bss) = inputs(&client);
    let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
    let mut link = ManagedLink::new(
        client,
        Provider(
            Arc::new(AtomicUsize::new(0)),
            core::sync::atomic::AtomicBool::new(false),
        ),
    )
    .unwrap();
    associate(&mut link, &model, join, bss);
    assert!(link.station().requires_protected_management());
    let epoch = link.station().association_epoch().unwrap();
    // The 4-way handshake's EAPOL needs no key.
    link.send_control(&control(), None).unwrap();
    assert_eq!(finish_tx(&model)[0][1] & 0x40, 0);
    link.service().unwrap();
    assert!(link.authorize_port(epoch).is_err());
    let ptk = link
        .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    link.install_key(false, 2, &[0x44; 16], ReplaySeed::ZERO)
        .unwrap();
    // The port also needs the IGTK.
    assert!(link.authorize_port(epoch).is_err());
    drop(drain_notices(&mut link));
    // SAFETY: modeled queues, notices and old key users are drained, and the
    // model OS's handshake supplied this IGTK.
    unsafe { link.install_management_key(epoch, 4, &[0x55; 16], PacketNumber::new(100).unwrap()) }
        .unwrap();
    assert!(!link.carrier());
    link.authorize_port(epoch).unwrap();
    assert!(link.carrier());
    link.send_control(&control(), Some(ptk)).unwrap();
    link.transmit(&eth(0x800)).unwrap();
    let frames = finish_tx(&model);
    assert_eq!(frames.len(), 2);
    assert!(frames.iter().all(|frame| frame[1] & 0x40 != 0));
    link.service().unwrap();
    incoming(&model, &data(false), Some((1, 0, 1)), false);
    link.service().unwrap();
    assert_eq!(
        &link.receive().unwrap().unwrap()[12..14],
        &0x800u16.to_be_bytes()
    );
    // An authenticated SA Query response reaches the OS that registered it.
    link.register_action(&[8, 1]).unwrap();
    incoming(
        &model,
        &response(0x40d0, &[8, 1, 3, 4]),
        Some((1, 0, 2)),
        false,
    );
    link.service().unwrap();
    assert!(drain_notices(&mut link).iter().any(|notice| matches!(
        &notice.event,
        LinkEvent::Controller(Event::ProtectedManagement(rx)) if rx.body() == [8, 1, 3, 4]
    )));
    // mac80211 answers the AP's SA Query request and returns an unknown
    // robust action, both protected.
    incoming(
        &model,
        &response(0x40d0, &[8, 0, 5, 6]),
        Some((1, 0, 3)),
        false,
    );
    incoming(
        &model,
        &response(0x40d0, &[126, 1, 2]),
        Some((1, 0, 4)),
        false,
    );
    let mut replies = Vec::new();
    for _ in 0..4 {
        link.service().unwrap();
        replies.extend(finish_tx(&model));
    }
    drop(drain_notices(&mut link));
    for body in [&[8, 1, 5, 6][..], &[0xfe, 1, 2]] {
        assert!(
            replies
                .iter()
                .any(|frame| frame[..2] == [0xd0, 0x40] && &frame[24..] == body)
        );
    }
    // The QoS data frame started its TID's block-ack session with a
    // protected ADDBA request, and the departure is encrypted too, as
    // IEEE80211_STA_MFP_ENABLED leaves it.
    let departed = depart(&mut link, &model);
    assert!(
        replies
            .iter()
            .chain(&departed)
            .any(|frame| frame[..2] == [0xd0, 0x40] && frame[24..26] == [3, 0])
    );
    assert_eq!(departed.last().unwrap()[..2], [0xc0, 0x40]);
    retire(&mut link, &model);
}
