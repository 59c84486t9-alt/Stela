// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Owning link consumes the same native observation; notices retain raw bytes.
use super::*;

fn beacon(link: &TestLink, count: u8) -> Vec<u8> {
    let mut elements = link
        .state()
        .client
        .client
        .modern_context()
        .unwrap()
        .beacon()
        .elements
        .clone();
    let mut at = 0;
    while at < elements.len() {
        let n = usize::from(elements[at + 1]);
        if elements[at] == 221 && elements[at + 2..at + 6] == [0, 0x50, 0xf2, 2] {
            elements[at + 8] = (elements[at + 8] & 0xf0) | count;
            elements[at + 12..at + 14].copy_from_slice(&100u16.to_le_bytes());
            break;
        }
        at += 2 + n;
    }
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x11u16.to_le_bytes());
    body.extend_from_slice(&elements);
    let mut frame = response(0x80, &body);
    frame[4..10].copy_from_slice(&crate::net::Mac::BROADCAST.0);
    frame
}

#[test]
fn owning_link_consumes_current_wmm_and_preserves_native_notice_and_association() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drain_notices(&mut link);
    let epoch = link.station().association_epoch().unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    let frame = beacon(&link, 1);
    incoming(&model, &frame, None, false);
    link.service().unwrap();
    // The beacon's parameters apply at once, as mt7925_mcu_set_tx sends them.
    let notices = link.queues().notices;
    assert!(!link.pending_edca());
    assert_eq!(link.applied_edca().unwrap().parameter_set_count, 1);
    assert_eq!(link.station().association_epoch(), Some(epoch));
    assert!(link.carrier());
    assert_eq!(link.queues().notices, notices);
    let notice = link.take_notice().unwrap();
    assert_eq!(notice.association, Some(epoch));
    match notice.event {
        LinkEvent::Controller(Event::Raw(raw)) => assert!(raw.bytes.ends_with(&frame)),
        _ => panic!("original native beacon retained through owning notice"),
    }
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 1
    );
    stop(&mut link, &model);
}

#[test]
fn failed_owning_update_reconciles_carrier_and_retained_ethernet_immediately() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drain_notices(&mut link);
    let mut packet = data(false);
    packet[0] |= 0x80;
    packet.splice(24..24, [6, 0]);
    incoming(&model, &packet, Some((1, 0, 1)), false);
    link.service().unwrap();
    assert_eq!(link.queues().data_frames, 1);
    let frame = beacon(&link, 1);
    model.response.lock().unwrap().edca_status = Some(0xbad);
    incoming(&model, &frame, None, false);
    assert!(link.service().is_err());
    assert_eq!(link.phase(), Phase::Quarantined);
    assert_eq!(link.queues().data_frames, 0);
    assert!(!link.carrier());
    assert!(link.pending_edca());
    assert_eq!(link.applied_edca().unwrap().parameter_set_count, 0);
    drop(link);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn a_beacon_narrowing_the_channel_moves_the_firmware_like_ieee80211_config_bw() {
    use crate::net::wifi::station::phy::Width;
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drain_notices(&mut link);
    let context = link.state().client.client.modern_context().unwrap().clone();
    assert_ne!(context.definition().width, Width::Mhz20);
    // HT operation without a secondary channel, VHT operation at 20/40 MHz
    // and EHT operation at 20 MHz on channel 36.
    let mut frame = beacon(&link, 0);
    let mut at = 36;
    while at + 2 < frame.len() {
        let n = usize::from(frame[at + 1]);
        match frame[at] {
            61 => frame[at + 3] &= !7,
            192 => frame[at + 2] = 0,
            255 if frame[at + 2] == 106 => frame[at + 8..at + 10].copy_from_slice(&[0, 36]),
            _ => {}
        }
        at += 2 + n;
    }
    incoming(&model, &frame, None, false);
    link.service().unwrap();
    let command = model
        .response
        .lock()
        .unwrap()
        .client_commands
        .last()
        .unwrap()
        .clone();
    assert_eq!(command[48 + 4..48 + 6], [2, 0]);
    assert_eq!(command[48 + 11], 0);
    let channel = link.state().client.client.state().channel.unwrap();
    assert_eq!(channel.width, Width::Mhz20);
    assert!(link.carrier());
    stop(&mut link, &model);
}

#[test]
fn rssi_monitor_needs_firmware_rssi_events_like_ieee80211_vif_supports_cqm_rssi() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drain_notices(&mut link);
    let before = model.response.lock().unwrap().client_commands.len();
    // This firmware reports chip flags without RSSI_NOTIFY_EVT_EN.
    assert!(matches!(
        link.set_rssi_monitor(Some((-70, 2))),
        Err(LinkControlError::Policy(PolicyError::Client(
            Error::Unsupported
        )))
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(link.carrier());
    stop(&mut link, &model);
}
