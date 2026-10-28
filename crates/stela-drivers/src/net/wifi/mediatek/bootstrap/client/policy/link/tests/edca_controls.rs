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

fn channel_switch_events(link: &mut TestLink) -> Vec<Event> {
    drain_notices(link)
        .into_iter()
        .filter_map(|notice| match notice.event {
            LinkEvent::Controller(
                event @ (Event::ChannelSwitchStarted { .. } | Event::ChannelSwitched(_)),
            ) => Some(event),
            _ => None,
        })
        .collect()
}

#[test]
fn an_announced_channel_switch_moves_the_firmware_like_mt7925_csa_work() {
    use crate::net::wifi::station::phy::Width;
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drop(drain_notices(&mut link));
    let before = link.station().operating_definition().unwrap();
    // An unprotected public ECSA action only quiets the station until a
    // beacon confirms it: class 115, channel 40, mode 1.
    let mut action = response(0xd0, &[4, 4, 1, 115, 40, 3]);
    action[4..10].copy_from_slice(&link.mac().0);
    incoming(&model, &action, None, false);
    link.service().unwrap();
    assert!(link.transmit(&eth(0x800)).is_err());
    assert_eq!(link.station().operating_definition(), Some(before));
    incoming(&model, &beacon(&link, 0), None, false);
    link.service().unwrap();
    assert!(link.transmit(&eth(0x800)).is_ok());
    // The beacon announces a quiet switch to 44 at 80 MHz around 42, now.
    let mut frame = beacon(&link, 0);
    for (id, data) in [
        (37, &[1, 44, 0][..]),
        (62, &[1]),
        (196, &[194, 3, 1, 42, 0]),
    ] {
        frame.extend_from_slice(&[id, data.len() as u8]);
        frame.extend_from_slice(data);
    }
    incoming(&model, &frame, None, false);
    link.service().unwrap();
    let target = link.station().operating_definition().unwrap();
    assert_eq!(target.control.number, 44);
    assert_eq!((target.width, target.center1_mhz), (Width::Mhz80, 5210));
    let commands = model.response.lock().unwrap().client_commands.clone();
    let chctx = commands.last().unwrap();
    assert_eq!(chctx[48 + 4..48 + 6], [2, 0]);
    assert_eq!((chctx[48 + 8], chctx[48 + 9], chctx[48 + 11]), (44, 42, 2));
    assert!(model.response.lock().unwrap().roc_channel.is_none());
    assert!(matches!(
        channel_switch_events(&mut link)[..],
        [Event::ChannelSwitchStarted {
            count: 0,
            block_tx: true,
            ..
        }]
    ));
    // Silence holds until the AP's beacon on the new channel, whose HT
    // operation names 44 below 48.
    assert!(link.transmit(&eth(0x800)).is_err());
    let mut frame = beacon(&link, 0);
    crate::net::wifi::station::tests::edit_elements(&mut frame[36..], |id, data| {
        if id == 61 {
            data[0] = 44;
            data[1] = (data[1] & !3) | 1;
        }
    });
    let mut bytes = incoming_bytes(&frame, None, false);
    bytes[13] = 44;
    device_receive(&model.queues[&0xd4520], &bytes, true, 0);
    link.service().unwrap();
    assert!(matches!(
        channel_switch_events(&mut link)[..],
        [Event::ChannelSwitched(definition)] if definition == target
    ));
    assert!(link.carrier());
    assert!(link.transmit(&eth(0x800)).is_ok());
    stop(&mut link, &model);
}

#[test]
fn a_channel_switch_to_another_band_disconnects_like_mac80211() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drop(drain_notices(&mut link));
    // ECSA to channel 6 in 2.4 GHz operating class 81.
    let mut frame = beacon(&link, 0);
    frame.extend_from_slice(&[60, 4, 0, 81, 6, 3]);
    incoming(&model, &frame, None, false);
    link.service().unwrap();
    assert!(!link.carrier());
    while link.phase() == Phase::Removing {
        finish_tx_on(&model, 36);
        link.service().unwrap();
    }
    assert_eq!(link.phase(), Phase::NeedsDrain);
    // SAFETY: actual model peer/key removal and all old users drained.
    unsafe { link.retire_peer_after_drain() }.unwrap();
    link.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: independent model controller, firmware, DMA and IRQ/work fence.
    unsafe { link.stop_after_quiesce() }.unwrap();
}

#[test]
fn a_new_association_forgets_the_last_aps_channel_and_timing() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drop(drain_notices(&mut link));
    let s = link.state_mut().client.client.state_mut();
    let mut narrowed = s.modern.as_ref().unwrap().context().definition();
    assert!(narrowed.downgrade());
    s.channel = Some(narrowed);
    depart(&mut link, &model);
    // SAFETY: actual model peer/key removal and all old users drained.
    unsafe { link.retire_peer_after_drain() }.unwrap();
    let (join, bss) = modern_inputs(&link.state().client.client);
    associate(&mut link, &model, join, bss);
    let s = link.state().client.client.state();
    assert!(s.channel.is_none() && s.channel_change.is_none() && s.slot_time.is_none());
    stop(&mut link, &model);
}

#[test]
fn power_save_follows_the_authorized_port_like_ieee80211_recalc_ps_vif() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    assert!(!link.state().client.client.power_save());
    secure(&mut link);
    link.service().unwrap();
    let last = || {
        let response = model.response.lock().unwrap();
        response.client_commands.last().unwrap().clone()
    };
    // mt7925_mcu_uni_bss_ps: the PS TLV in dynamic power save.
    let command = last();
    assert_eq!(
        (&command[48 + 4..48 + 6], command[48 + 8]),
        (&[21, 0][..], 2)
    );
    assert!(link.state().client.client.power_save());
    link.set_power_save(false);
    link.service().unwrap();
    let command = last();
    assert_eq!(
        (&command[48 + 4..48 + 6], command[48 + 8]),
        (&[21, 0][..], 0)
    );
    assert!(!link.state().client.client.power_save());
    assert!(link.carrier());
    stop(&mut link, &model);
}

#[test]
fn unclaimed_actions_go_back_to_their_sender_like_ieee80211_rx_h_action_return() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drop(drain_notices(&mut link));
    // A WNM action nothing claims returns with its category's 0x80 bit.
    let frame = response(0xd0, &[10, 26, 1]);
    incoming(&model, &frame, None, false);
    link.service().unwrap();
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0][24..], [0x8a, 26, 1]);
    assert_eq!(
        (&sent[0][4..10], &sent[0][10..16]),
        (&frame[10..16], &frame[4..10])
    );
    // Registered, the OS receives it instead.
    link.register_action(&[10]).unwrap();
    let frame = response(0xd0, &[10, 26, 2]);
    incoming(&model, &frame, None, false);
    assert!(drain_notices(&mut link).iter().any(|notice| matches!(
        &notice.event,
        LinkEvent::Controller(Event::Raw(raw)) if raw.bytes.ends_with(&frame)
    )));
    // A returned frame is never returned again.
    incoming(&model, &response(0xd0, &[0x85, 0]), None, false);
    link.service().unwrap();
    assert!(finish_tx(&model).is_empty());
    // A 5 GHz measurement request is refused, and an SA Query answered.
    incoming(
        &model,
        &response(0xd0, &[0, 0, 7, 38, 3, 9, 0, 1]),
        None,
        false,
    );
    link.service().unwrap();
    assert_eq!(finish_tx(&model)[0][24..], [0, 2, 7, 39, 3, 9, 4, 1]);
    incoming(&model, &response(0xd0, &[8, 0, 0x12, 0x34]), None, false);
    // The first service retires the report's TX-free.
    link.service().unwrap();
    link.service().unwrap();
    assert_eq!(finish_tx(&model)[0][24..], [8, 1, 0x12, 0x34]);
    assert!(link.carrier());
    stop(&mut link, &model);
}

#[test]
fn frames_ask_for_hardware_amsdu_like_wcid_amsdu() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drop(drain_notices(&mut link));
    let context = link.state().client.client.modern_context().unwrap().clone();
    assert_ne!(context.negotiated().max_tx_amsdu, 0);
    // Each frame takes a new TID, as a TID's next frames wait for its
    // block-ack session.
    let hw_amsdu = |link: &mut TestLink, dscp: u8| {
        let mut frame = eth(0x800);
        frame.truncate(14);
        frame.extend_from_slice(&[0x45, dscp << 2]);
        frame.resize(14 + 20, 0);
        link.transmit(&frame).unwrap();
        let word = u32::from_le_bytes(next_txwi(&model)[12..16].try_into().unwrap());
        finish_tx(&model);
        link.service().unwrap();
        word & (1 << 5) != 0
    };
    // The quarter-second peer frame asks for TX status, which never
    // aggregates; the next frame does.
    assert!(!hw_amsdu(&mut link, 0));
    assert!(hw_amsdu(&mut link, 8));
    // mt7925_mcu_uni_tx_ba for an agreement without A-MSDU.
    link.state_mut().client.client.state_mut().amsdu_off = true;
    assert!(!hw_amsdu(&mut link, 32));
    stop(&mut link, &model);
}

#[test]
fn rssi_monitor_without_firmware_rssi_events_watches_beacons_like_mac80211() {
    let (mut link, model, join, bss, _) = setup_link();
    associate(&mut link, &model, join, bss);
    secure(&mut link);
    drain_notices(&mut link);
    let before = model.response.lock().unwrap().client_commands.len();
    // This firmware reports chip flags without RSSI_NOTIFY_EVT_EN: no
    // command, mac80211's beacon tracking instead.
    link.set_rssi_monitor(Some((-70, 2))).unwrap();
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(link.carrier());
    stop(&mut link, &model);
}
