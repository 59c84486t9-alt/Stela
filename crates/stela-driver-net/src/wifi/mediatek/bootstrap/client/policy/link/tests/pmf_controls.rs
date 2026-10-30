// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! A PMF association through the sole owning link, driven as wpa_supplicant
//! drives mac80211: join, EAPOL, keys, then the authorized port.
use super::*;
use crate::wifi::mediatek::bootstrap::client::modern::tests::pmf_controls::{inputs, inputs_akm};
use crate::wifi::security::PacketNumber;

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

#[test]
fn an_sae_exchange_associates_like_ieee80211_mgd_assoc() {
    let (client, model) = setup_modern();
    let (join, bss) = inputs_akm(&client, 8);
    let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
    let mut link = ManagedLink::new(
        client,
        Provider(
            Arc::new(AtomicUsize::new(0)),
            core::sync::atomic::AtomicBool::new(false),
        ),
    )
    .unwrap();
    link.begin_scan(
        scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
        1_000_000,
    )
    .unwrap();
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x11u16.to_le_bytes());
    body.extend_from_slice(&bss.elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(&model, &beacon, None, false);
    link.service().unwrap();
    let handle = link.bss().next().unwrap().0;
    done(&model);
    link.service().unwrap();
    // SAFETY: complete source-model terminal scan and old-user drain.
    unsafe { link.retire_scan_after_drain() }.unwrap();
    // An SAE request cannot authenticate with open system.
    assert!(link.join(handle, join.clone(), profile()).is_err());
    let session = link
        .begin_external_authentication(handle, profile(), None, 2_000_000)
        .unwrap();
    // ieee80211_mgd_assoc refuses while authentication is unfinished.
    assert!(
        link.associate_external(&session, handle, join.clone())
            .is_err()
    );
    for (transaction, data) in [(1, &[19, 0][..]), (2, &[1][..])] {
        link.transmit_external_authentication(
            &session,
            crate::wifi::station::external::Frame {
                transaction,
                status: 0,
                data,
            },
        )
        .unwrap();
        finish_tx(&model);
        link.service().unwrap();
        let mut frame = vec![3, 0, transaction as u8, 0, 0, 0];
        frame.extend_from_slice(data);
        incoming(&model, &response(0xb0, &frame), None, false);
        link.service().unwrap();
    }
    assert!(link.station().external_authenticated());
    drop(drain_notices(&mut link));
    link.associate_external(&session, handle, join).unwrap();
    let request = finish_tx(&model);
    assert_eq!(request[0][..2], [0, 0]);
    link.service().unwrap();
    let mut assoc = vec![0x11, 0, 0, 0, 1, 0xc0];
    assoc.extend_from_slice(&bss.elements);
    incoming(&model, &response(0x10, &assoc), None, false);
    link.service().unwrap();
    assert_eq!(link.phase(), Phase::AwaitingModernAdmission);
    assert!(link.station().external_authentication().is_none());
    link.configure().unwrap();
    let epoch = link.station().association_epoch().unwrap();
    assert_eq!(epoch, session.epoch());
    link.install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    link.install_key(false, 2, &[0x44; 16], ReplaySeed::ZERO)
        .unwrap();
    drop(drain_notices(&mut link));
    // SAFETY: modeled queues, notices and old key users are drained, and the
    // model OS's handshake supplied this IGTK.
    unsafe { link.install_management_key(epoch, 4, &[0x55; 16], PacketNumber::new(100).unwrap()) }
        .unwrap();
    link.authorize_port(epoch).unwrap();
    assert!(link.carrier());
    stop(&mut link, &model);
}

/// An AP MLD's association on its setup link alone, as mac80211 makes one
/// when no other link is requested: SAE and the association run on the
/// link's address, and the BSS and AP records name both MLDs, as
/// `mt7925_mcu_bss_mld_tlv` and `mt7925_mcu_sta_mld_tlv` write them.
#[test]
fn an_ap_mld_association_names_both_mlds_in_its_records() {
    use crate::wifi::station::{
        multi_link::{Affiliation, Mld, Setup},
        wire::multi_link::Basic,
    };
    const AP_MLD: Mac = Mac([2, 9, 9, 9, 9, 9]);
    const SETUP_LINK: Mac = Mac([2, 0xa, 0, 0, 0, 1]);
    let to_link = |subtype, body: &[u8]| {
        let mut frame = response(subtype, body);
        frame[4..10].copy_from_slice(&SETUP_LINK.0);
        frame
    };
    let ap_mld = |link_id| {
        Basic {
            address: AP_MLD,
            link_id,
            mld_capabilities: link_id.map(|_| 0),
            ..Basic::default()
        }
        .encode()
    };
    let affiliation = Affiliation {
        mld: Mld {
            local: LOCAL,
            ap: AP_MLD,
        },
        link_id: 0,
        local: SETUP_LINK,
    };
    let (client, model) = setup_modern();
    let (mut join, bss) = inputs_akm(&client, 8);
    join.request = join
        .request
        .with_multi_link(Setup {
            association: affiliation,
            mld_capabilities: 0,
            eml_capabilities: 0,
            links: Vec::new(),
        })
        .unwrap();
    let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
    let mut link = ManagedLink::new(
        client,
        Provider(
            Arc::new(AtomicUsize::new(0)),
            core::sync::atomic::AtomicBool::new(false),
        ),
    )
    .unwrap();
    link.begin_scan(
        scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
        1_000_000,
    )
    .unwrap();
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x11u16.to_le_bytes());
    body.extend_from_slice(&bss.elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(&model, &beacon, None, false);
    link.service().unwrap();
    let handle = link.bss().next().unwrap().0;
    done(&model);
    link.service().unwrap();
    // SAFETY: complete source-model terminal scan and old-user drain.
    unsafe { link.retire_scan_after_drain() }.unwrap();
    let session = link
        .begin_external_authentication(handle, profile(), Some(affiliation), 2_000_000)
        .unwrap();
    for (transaction, status, data) in [(1, 126, &[19, 0][..]), (2, 0, &[1][..])] {
        link.transmit_external_authentication(
            &session,
            crate::wifi::station::external::Frame {
                transaction,
                status,
                data,
            },
        )
        .unwrap();
        finish_tx(&model);
        link.service().unwrap();
        let mut frame = vec![3, 0, transaction as u8, 0, status as u8, 0];
        frame.extend_from_slice(data);
        frame.extend(ap_mld(None));
        incoming(&model, &to_link(0xb0, &frame), None, false);
        link.service().unwrap();
    }
    assert!(link.station().external_authenticated());
    drop(drain_notices(&mut link));
    link.associate_external(&session, handle, join).unwrap();
    let request = &finish_tx(&model)[0];
    assert_eq!(request[10..16], SETUP_LINK.0);
    link.service().unwrap();
    let mut assoc = vec![0x11, 0, 0, 0, 1, 0xc0];
    assoc.extend_from_slice(&bss.elements);
    assoc.extend(ap_mld(Some(0)));
    incoming(&model, &to_link(0x10, &assoc), None, false);
    link.service().unwrap();
    assert_eq!(link.phase(), Phase::AwaitingModernAdmission);
    let before = model.response.lock().unwrap().client_commands.len();
    link.configure().unwrap();
    let commands = model.response.lock().unwrap().client_commands[before..].to_vec();
    let record = |command: u8, header: usize, tag: u16| {
        commands
            .iter()
            .filter(|packet| packet[34] == command)
            .find_map(|packet| {
                let mut rest = &packet[48 + header..];
                while rest.len() >= 4 {
                    let length = usize::from(u16::from_le_bytes([rest[2], rest[3]]));
                    if rest[..2] == tag.to_le_bytes() {
                        return Some(rest[..length].to_vec());
                    }
                    rest = &rest[length..];
                }
                None
            })
            .unwrap()
    };
    // UNI_BSS_INFO_MLD: link 0 of the group of BSS 0, own MLD 32, the
    // station MLD's address.
    let bss = record(2, 4, 26);
    assert_eq!(
        (bss[4], bss[5], &bss[6..12], bss[13]),
        (0, 32, &LOCAL.0[..], 0)
    );
    // STA_REC_MLD names the AP MLD with the setup link's WCID 1 alone.
    let peer = record(3, 8, 0x20);
    assert_eq!((&peer[4..10], peer[16]), (&AP_MLD.0[..], 1));
    // mt792x_tx: a management frame the station addresses to the AP MLD
    // leaves the setup link from the station's address there.
    let mut action = vec![0xd0, 0, 0, 0];
    for address in [AP_MLD, LOCAL, AP_MLD] {
        action.extend_from_slice(&address.0);
    }
    action.extend_from_slice(&[0, 0, 3, 0]);
    let context = link.station().association_context().unwrap();
    let on_air = Client::<Bar, Q, NativeGuard>::on_setup_link(&action, context);
    assert_eq!(
        (&on_air[4..10], &on_air[10..16], &on_air[16..22]),
        (&AP.0[..], &SETUP_LINK.0[..], &AP.0[..])
    );
    // The PTK is the MLDs', the setup link's GTK its AP's: the port opens
    // with the keys the handshake gives.
    let epoch = link.station().association_epoch().unwrap();
    link.install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    link.install_key(false, 2, &[0x44; 16], ReplaySeed::ZERO)
        .unwrap();
    drop(drain_notices(&mut link));
    // SAFETY: modeled queues, notices and old key users are drained, and the
    // model OS's handshake supplied this IGTK.
    unsafe { link.install_management_key(epoch, 4, &[0x55; 16], PacketNumber::new(100).unwrap()) }
        .unwrap();
    link.authorize_port(epoch).unwrap();
    assert!(link.carrier());
    let sent = depart(&mut link, &model);
    assert!(
        !sent.is_empty()
            && sent
                .iter()
                .all(|frame| frame[4..10] == AP.0 && frame[10..16] == SETUP_LINK.0)
    );
    retire(&mut link, &model);
}
