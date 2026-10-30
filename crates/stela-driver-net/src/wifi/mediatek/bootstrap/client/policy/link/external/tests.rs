// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! The OS-facing owner, scan handles, native DMA and bounded notices.
use super::*;
use crate::wifi::mediatek::{
    bootstrap::client::{
        policy::tests::{done, setup_modern, setup_six, six_country},
        six_ghz::tests::{SIX, beacon_elements, six_profile},
        tests::*,
    },
    bootstrap::tests::{Bar, NativeGuard, Q},
    ring::{rx::tests::device_receive, tests::Source},
};
use crate::wifi::station::wire::six_ghz::tests::selected;
use core::sync::atomic::Ordering;
use reg::database::tests::country;

/// A frame the device received on 6 GHz.
fn incoming_six(model: &Model, frame: &[u8]) {
    let mut raw = incoming_bytes(frame, None, false);
    raw[12..16].copy_from_slice(&(181u32 << 8).to_le_bytes());
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
}

/// A link that scanned channel `SIX` and found one BSS with `elements`.
fn six_link(
    flags: u32,
    elements: &[u8],
) -> (ManagedLink<Bar, Q, NativeGuard, Source>, Model, BssHandle) {
    let (client, model) = setup_six(flags);
    let client = ManagedClient::new(client, six_country(), Environment::Indoor).unwrap();
    let mut link = ManagedLink::new(client, Source).unwrap();
    link.begin_scan(
        scan::Request::new(vec![SIX], vec![], vec![]).unwrap(),
        1_000_000,
    )
    .unwrap();
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x11u16.to_le_bytes());
    body.extend_from_slice(elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming_six(&model, &beacon);
    link.service().unwrap();
    let handle = link.bss().next().unwrap().0;
    done(&model);
    link.service().unwrap();
    // SAFETY: terminal source scan and all modeled old users drained.
    unsafe { link.retire_scan_after_drain() }.unwrap();
    while link.take_notice().is_some() {}
    (link, model, handle)
}

#[test]
fn a_six_ghz_sae_exchange_goes_through_the_client_own_board_and_os() {
    let (mut link, model, handle) = six_link(0, &beacon_elements());
    let session = link
        .begin_six_ghz_external_authentication(
            handle,
            Selection::new(selected()).unwrap(),
            six_profile(),
            2_000_000,
        )
        .unwrap();
    assert_eq!(link.phase(), Phase::Joining);
    // The commit goes out on a ROC20 grant through the generic entry point.
    link.transmit_external_authentication(
        &session,
        crate::wifi::station::external::Frame {
            transaction: 1,
            status: 126,
            data: &[19, 0, 0xaa, 0, 0xbb],
        },
    )
    .unwrap();
    assert_eq!(model.response.lock().unwrap().roc_channel, Some(1));
    assert_eq!(
        &finish_tx_on(&model, 1)[0][24..],
        &[3, 0, 1, 0, 126, 0, 19, 0, 0xaa, 0, 0xbb]
    );
    // The AP's commit arrives through the link's guarded service.
    incoming_six(
        &model,
        &response(0xb0, &[3, 0, 1, 0, 126, 0, 0, 0xff, 7, 0]),
    );
    let mut received = None;
    for _ in 0..2 {
        link.service().unwrap();
        while let Some(notice) = link.take_notice() {
            if let LinkEvent::Controller(Event::ExternalAuthentication(rx)) = notice.event {
                received = Some(rx);
            }
        }
    }
    let received = received.unwrap();
    assert!(Arc::ptr_eq(received.session(), &session));
    assert_eq!((received.transaction(), received.status()), (1, 126));
    link.cancel_external_authentication(&session).unwrap();
    assert_eq!(link.phase(), Phase::NeedsDrain);
}

#[test]
fn a_very_low_power_ap_is_refused_where_the_channel_bars_vlp_clients() {
    let mut elements = beacon_elements();
    // The HE operation's 6 GHz information names a VLP AP.
    let he = elements
        .windows(3)
        .position(|w| w == [255, 12, 36])
        .unwrap();
    elements[he + 10] = 2 << 3;
    let (mut link, model, handle) = six_link(reg::channel::NO_6GHZ_VLP_CLIENT, &elements);
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(matches!(
        link.begin_six_ghz_external_authentication(
            handle,
            Selection::new(selected()).unwrap(),
            six_profile(),
            2_000_000,
        ),
        Err(LinkControlError::Policy(PolicyError::Client(
            Error::Regulatory(reg::Error::HardwareDenied)
        )))
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(link.phase(), Phase::Idle);
}

#[test]
fn owning_link_authentication_uses_bss_and_backpressures_native_receive() {
    let (client, model) = setup_modern();
    let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
    let mut link = ManagedLink::new(client, Source).unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(
        link.begin_external_authentication(BssHandle(0), profile(), None, 2_000_000)
            .is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    link.begin_scan(
        scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
        1_000_000,
    )
    .unwrap();
    let mut beacon_body = vec![0; 8];
    beacon_body.extend_from_slice(&100u16.to_le_bytes());
    beacon_body.extend_from_slice(&0x11u16.to_le_bytes());
    beacon_body.extend_from_slice(&[0, 1, b'x', 1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
    let mut beacon = response(0x80, &beacon_body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(&model, &beacon, None, false);
    link.service().unwrap();
    let handle = link.bss().next().unwrap().0;
    done(&model);
    link.service().unwrap();
    // SAFETY: terminal source scan and all modeled old users drained.
    unsafe { link.retire_scan_after_drain() }.unwrap();
    while link.take_notice().is_some() {}
    let mut wrong = profile();
    wrong.peer.0[5] ^= 1;
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(
        link.begin_external_authentication(handle, wrong, None, 2_000_000)
            .is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    let session = link
        .begin_external_authentication(handle, profile(), None, 2_000_000)
        .unwrap();
    assert_eq!(session.ssid(), b"x");
    assert!(!link.carrier());
    let receipt = link
        .transmit_external_authentication(
            &session,
            crate::wifi::station::external::Frame {
                transaction: 1,
                status: 0,
                data: &[19, 0, 0xff],
            },
        )
        .unwrap();
    assert_eq!(
        &finish_tx(&model)[0][24..],
        &[3, 0, 1, 0, 0, 0, 19, 0, 0xff]
    );
    link.service().unwrap();
    let mut saw_release = false;
    while let Some(notice) = link.take_notice() {
        if let LinkEvent::Released(released) = notice.event {
            assert_eq!(released.receipt, receipt);
            assert!(Arc::ptr_eq(
                released.context.authentication_session().unwrap(),
                &session
            ));
            saw_release = true;
        }
    }
    assert!(saw_release);
    // Fill the real notice capacity using completed native RX frames.
    for i in 0..64_u8 {
        incoming(
            &model,
            &response(0xb0, &[3, 0, 1, 0, 76, 0, i]),
            None,
            false,
        );
        link.service().unwrap();
    }
    assert_eq!(link.queues().notices, 64);
    incoming(
        &model,
        &response(0xb0, &[3, 0, 2, 0, 0, 0, 64]),
        None,
        false,
    );
    let before = {
        let queue = model.queues[&0xd4520].lock().unwrap();
        let memory = model.memory.lock().unwrap();
        let offset = usize::from((queue.index + queue.count - 1) % queue.count) * 16;
        let pointer = (memory.mappings[&queue.base].1 + offset) as *const u8;
        // SAFETY: completed model descriptor is still held/mapped.
        let descriptor = unsafe { core::slice::from_raw_parts(pointer, 16) }.to_vec();
        assert_ne!(
            u32::from_le_bytes(descriptor[4..8].try_into().unwrap()) & (1 << 31),
            0
        );
        (queue.head, queue.index, descriptor)
    };
    link.service().unwrap();
    {
        let queue = model.queues[&0xd4520].lock().unwrap();
        assert_eq!((queue.head, queue.index), (before.0, before.1));
        let memory = model.memory.lock().unwrap();
        let offset = usize::from((queue.index + queue.count - 1) % queue.count) * 16;
        let pointer = (memory.mappings[&queue.base].1 + offset) as *const u8;
        assert_eq!(
            // SAFETY: same model descriptor as the snapshot above.
            unsafe { core::slice::from_raw_parts(pointer, 16) },
            before.2
        );
    }
    let notice = link.take_notice().unwrap();
    assert!(
        matches!(notice.event, LinkEvent::Controller(Event::ExternalAuthentication(rx)) if rx.data() == [0] && Arc::ptr_eq(rx.session(), &session))
    );
    link.service().unwrap();
    let mut count = 1;
    while let Some(notice) = link.take_notice() {
        if let LinkEvent::Controller(Event::ExternalAuthentication(rx)) = notice.event {
            assert!(Arc::ptr_eq(rx.session(), &session));
            assert_eq!(rx.data(), &[count]);
            count += 1;
        }
    }
    assert_eq!(count, 65);
    assert!(!link.carrier());
    assert!(link.authorize_port(session.epoch()).is_err());
    link.cancel_external_authentication(&session).unwrap();
    link.service().unwrap();
    assert!(
        matches!(link.take_notice().unwrap().event, LinkEvent::Controller(Event::ExternalAuthenticationEnded { session: ended, failure: None }) if Arc::ptr_eq(&ended, &session))
    );
    // SAFETY: all native model descriptors/notices and independent users drained.
    unsafe { link.retire_peer_after_drain() }.unwrap();
    link.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: model stop/reset establishes whole-controller quiescence.
    unsafe { link.stop_after_quiesce() }.unwrap();
    drop(link);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}
