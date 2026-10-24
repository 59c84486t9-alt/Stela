// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Actual firmware, ROC, DMA-fetch/TX-free and completed-RX peer controls.
use super::*;
use crate::net::wifi::mediatek::bootstrap::client::tests::*;
use crate::net::wifi::mediatek::bootstrap::tests::{Bar, NativeGuard, Q};
use crate::net::wifi::mediatek::ring::tests::Source;
use core::sync::atomic::Ordering;

fn finish(mut client: Client<Bar, Q, NativeGuard>, model: Model, now: u64) {
    if client.station().phase() == station::Phase::ExternalAuthenticating {
        let session = client.station().external_authentication().unwrap().clone();
        client.cancel_external_authentication(&session).unwrap();
    }
    client.poll(now, &Source, &mut Policy(true)).unwrap();
    assert!(client.poll_released().unwrap().is_empty());
    assert_eq!(client.phase(), Phase::NeedsDrain);
    // SAFETY: all actual model descriptors, mailbox/ROC notifications and
    // retained DMA users have been consumed; no independent physical user.
    unsafe { client.retire_peer_after_drain() }.unwrap();
    client.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: actual model stop/reset leaves no DMA, IRQ or external users.
    unsafe { client.stop_after_quiesce() }.unwrap();
    drop(client);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn actual_sae_commit_token_retry_confirm_transport_never_grants_association() {
    let (mut client, model) = setup();
    let session = client
        .begin_external_authentication(
            profile(),
            vec![b'x', 0, 0xff],
            0,
            2_000_000,
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(session.ssid(), &[b'x', 0, 0xff]);
    assert_eq!(
        client.station().phase(),
        station::Phase::ExternalAuthenticating
    );
    assert_eq!(client.phase(), Phase::Joining);
    assert!(!client.station().port_open(None, None));
    assert!(client.station().association_context().is_none());
    assert!(
        client
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .is_err()
    );
    assert!(client.authorize_port(session.epoch()).is_err());
    let first = client
        .transmit_external_authentication(
            &session,
            1,
            126,
            &[19, 0, 0xaa, 0, 0xbb],
            1,
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(model.response.lock().unwrap().roc_channel, Some(36));
    assert_eq!(
        client
            .state()
            .controller
            .state()
            .data_tx
            .as_ref()
            .unwrap()
            .outstanding_tokens(),
        1
    );
    assert!(client.poll_released().unwrap().is_empty());
    let packet = finish_tx(&model);
    assert_eq!(packet.len(), 1);
    assert_eq!(
        &packet[0][24..],
        &[3, 0, 1, 0, 126, 0, 19, 0, 0xaa, 0, 0xbb]
    );
    client.poll(2, &Source, &mut Policy(true)).unwrap();
    let released = client.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].receipt, first);
    assert!(Arc::ptr_eq(
        released[0].context.authentication_session().unwrap(),
        &session
    ));
    assert_eq!(released[0].context.association_epoch(), session.epoch());
    assert!(released[0].context.key().is_none());
    let mut peer = vec![3, 0, 1, 0, 76, 0];
    peer.extend_from_slice(&[0, 0xff, 7, 0]);
    incoming(&model, &response(0xb0, &peer), None, false);
    let events = client.poll(3, &Source, &mut Policy(true)).unwrap();
    let received = events
        .iter()
        .find_map(|event| match event {
            Event::ExternalAuthentication(rx) => Some(rx),
            _ => None,
        })
        .unwrap();
    assert!(Arc::ptr_eq(received.session(), &session));
    assert_eq!(received.transaction(), 1);
    assert_eq!(received.status(), 76);
    assert_eq!(received.data(), &[0, 0xff, 7, 0]);
    // A peer confirm arriving before our confirm remains an OS observation.
    incoming(
        &model,
        &response(0xb0, &[3, 0, 2, 0, 0, 0, 0x55]),
        None,
        false,
    );
    let events = client.poll(4, &Source, &mut Policy(true)).unwrap();
    assert!(events.iter().any(|event| matches!(event, Event::ExternalAuthentication(rx) if rx.transaction() == 2 && rx.status() == 0)));
    assert_eq!(
        client.station().phase(),
        station::Phase::ExternalAuthenticating
    );
    assert!(!client.station().port_open(None, None));
    for (index, (transaction, bytes)) in [
        (1_u16, &[19, 0, 0xff, 7][..]),
        (2_u16, &[0x34, 0x12, 0xaa][..]),
    ]
    .into_iter()
    .enumerate()
    {
        client
            .transmit_external_authentication(
                &session,
                transaction,
                0,
                bytes,
                5 + index as u64 * 2,
                &Source,
                &mut Policy(true),
            )
            .unwrap();
        let sent = finish_tx(&model);
        assert_eq!(&sent[0][24..26], &[3, 0]);
        assert_eq!(&sent[0][26..28], &transaction.to_le_bytes());
        assert_eq!(&sent[0][30..], bytes);
        client
            .poll(6 + index as u64 * 2, &Source, &mut Policy(true))
            .unwrap();
        assert_eq!(client.poll_released().unwrap().len(), 1);
    }
    drop(released);
    finish(client, model, 9);
}

#[test]
fn cancellation_retains_real_pending_dma_and_late_rx_until_explicit_peer_drain() {
    let (mut client, model) = setup();
    let session = client
        .begin_external_authentication(profile(), vec![b'x'], 0, 2_000_000, &mut Policy(true))
        .unwrap();
    let receipt = client
        .transmit_external_authentication(
            &session,
            1,
            0,
            &[19, 0, 1],
            1,
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    let commands = model.response.lock().unwrap().client_commands.len();
    client.cancel_external_authentication(&session).unwrap();
    assert_eq!(client.phase(), Phase::Removing);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert!(matches!(
        client.transmit_external_authentication(
            &session,
            2,
            0,
            &[1],
            2,
            &Source,
            &mut Policy(true)
        ),
        Err(Error::Station(station::Error::Stale))
    ));
    assert!(client.poll_released().unwrap().is_empty());
    // Real device fetch, consumption and TX-free are independent from cancel.
    assert_eq!(finish_tx(&model).len(), 1);
    incoming(&model, &response(0xb0, &[3, 0, 2, 0, 0, 0, 9]), None, false);
    let events = client.poll(3, &Source, &mut Policy(true)).unwrap();
    assert!(events.iter().any(|event| matches!(event, Event::ExternalAuthenticationEnded { session: ended, failure: None } if Arc::ptr_eq(ended, &session))));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::ExternalAuthentication(_)))
    );
    let released = client.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].receipt, receipt);
    assert!(Arc::ptr_eq(
        released[0].context.authentication_session().unwrap(),
        &session
    ));
    assert_eq!(client.phase(), Phase::NeedsDrain);
    assert!(matches!(
        client.begin_external_authentication(
            profile(),
            vec![b'x'],
            4,
            2_000_000,
            &mut Policy(true)
        ),
        Err(Error::Busy)
    ));
    drop(released);
    // SAFETY: this model consumed all old RX/TX/ROC and has no delayed users.
    unsafe { client.retire_peer_after_drain() }.unwrap();
    let next = client
        .begin_external_authentication(profile(), vec![b'x'], 4, 2_000_000, &mut Policy(true))
        .unwrap();
    assert!(!Arc::ptr_eq(&session, &next));
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(matches!(
        client.cancel_external_authentication(&session),
        Err(Error::Station(station::Error::Stale))
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    finish(client, model, 5);
}

#[test]
fn stale_foreign_and_invalid_os_commands_are_refused_before_actual_roc_or_dma() {
    let (mut client, model) = setup();
    let (mut other, other_model) = setup();
    let session = client
        .begin_external_authentication(profile(), vec![b'x'], 100, 2_000_000, &mut Policy(true))
        .unwrap();
    let foreign = other
        .begin_external_authentication(profile(), vec![b'x'], 100, 2_000_000, &mut Policy(true))
        .unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    let queue_head = model.queues[&0xd4300].lock().unwrap().head;
    for transaction in [0, 3, u16::MAX] {
        assert!(matches!(
            client.transmit_external_authentication(
                &session,
                transaction,
                0,
                &[1],
                100,
                &Source,
                &mut Policy(true)
            ),
            Err(Error::Station(station::Error::Wire(_)))
        ));
    }
    assert!(matches!(
        client.transmit_external_authentication(
            &session,
            1,
            0,
            &vec![0; wifi::frame::MAX_MPDU],
            100,
            &Source,
            &mut Policy(true)
        ),
        Err(Error::Station(station::Error::Wire(_)))
    ));
    assert!(matches!(
        client.transmit_external_authentication(
            &foreign,
            1,
            0,
            &[1],
            100,
            &Source,
            &mut Policy(true)
        ),
        Err(Error::Station(station::Error::Stale))
    ));
    assert!(matches!(
        client.transmit_external_authentication(
            &session,
            1,
            0,
            &[1],
            99,
            &Source,
            &mut Policy(true)
        ),
        Err(Error::Station(station::Error::ClockRegressed))
    ));
    assert!(matches!(
        client.transmit_external_authentication(
            &session,
            1,
            0,
            &[1],
            100,
            &Source,
            &mut Policy(false)
        ),
        Err(Error::Station(station::Error::Regulatory))
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, queue_head);
    assert_eq!(client.state().roc_token, 0);
    assert_eq!(
        client
            .state()
            .controller
            .state()
            .data_tx
            .as_ref()
            .unwrap()
            .outstanding_tokens(),
        0
    );
    finish(client, model, 101);
    finish(other, other_model, 101);
}

#[test]
fn frontend_and_actual_native_deadlines_cancel_without_retransmission_or_authority() {
    for native_timeout in [false, true] {
        let (mut client, model) = setup();
        let session = client
            .begin_external_authentication(
                profile(),
                vec![b'x'],
                0,
                if native_timeout { 10_000 } else { 2_000_000 },
                &mut Policy(true),
            )
            .unwrap();
        if native_timeout {
            // Advance only by the real controller TSC, with a bounded10ms
            // budget. Repeated frontend time cannot extend physical lifetime.
            let deadline = client.state().authentication_deadline.unwrap();
            while client.state().controller.state().control.clock.now_us() < deadline {
                core::hint::spin_loop();
            }
        }
        let now = if native_timeout {
            0
        } else {
            session.deadline()
        };
        let events = client.poll(now, &Source, &mut Policy(true)).unwrap();
        assert!(events.iter().any(|event| matches!(event, Event::ExternalAuthenticationEnded { session: ended, failure: Some(station::Failure::Timeout) } if Arc::ptr_eq(ended, &session))));
        assert_eq!(client.phase(), Phase::NeedsDrain);
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
        assert_eq!(client.state().roc_token, 0);
        assert!(!client.station().port_open(None, None));
        assert!(matches!(
            client.transmit_external_authentication(
                &session,
                1,
                0,
                &[1],
                now,
                &Source,
                &mut Policy(true)
            ),
            Err(Error::Station(station::Error::Stale))
        ));
        finish(client, model, now);
    }
}

#[test]
fn actual_rx_rejects_wrong_peer_channel_algorithm_transaction_and_short_fixed_fields() {
    let (mut client, model) = setup();
    let session = client
        .begin_external_authentication(profile(), vec![b'x'], 0, 2_000_000, &mut Policy(true))
        .unwrap();
    let mut oversized = vec![0; 2305];
    oversized[..6].copy_from_slice(&[3, 0, 1, 0, 0, 0]);
    for body in [
        oversized,
        vec![3, 0, 1, 0, 0],
        vec![0, 0, 2, 0, 0, 0],
        vec![3, 0, 3, 0, 0, 0],
    ] {
        let raw = incoming_bytes(&response(0xb0, &body), None, false);
        // Preserve the oversized authentication body, using the real native
        // multi-descriptor path instead of overfilling one 2-KiB DMA buffer.
        crate::net::wifi::mediatek::ring::rx::tests::device_receive_frame(
            &model.queues[&0xd4520],
            &raw,
            0,
        );
        assert!(matches!(
            client.poll(1, &Source, &mut Policy(true)),
            Err(Error::Station(station::Error::Wire(_)))
        ));
    }
    for (r1, r3) in [
        (0, (36u32 << 8) | (1 << 16) | (1 << 24)),
        (1 << 25, (36u32 << 8) | (1 << 16)),
    ] {
        let mut raw = incoming_bytes(&response(0xb0, &[3, 0, 1, 0, 0, 0]), None, false);
        raw[4..8].copy_from_slice(&u32::to_le_bytes(r1));
        raw[12..16].copy_from_slice(&u32::to_le_bytes(r3));
        crate::net::wifi::mediatek::ring::rx::tests::device_receive(
            &model.queues[&0xd4520],
            &raw,
            true,
            0,
        );
        assert!(matches!(
            client.poll(1, &Source, &mut Policy(true)),
            Err(Error::Station(station::Error::Wire(
                station::wire::Error::Integrity
            )))
        ));
    }
    let mut protected = response(0xb0, &[3, 0, 1, 0, 0, 0]);
    protected[1] |= 0x40;
    incoming(&model, &protected, Some((1, 0, 1)), false);
    assert!(matches!(
        client.poll(1, &Source, &mut Policy(true)),
        Err(Error::WrongPhase)
    ));
    let mut frame = response(0xb0, &[3, 0, 1, 0, 0xff, 0xff, 0]);
    frame[10] ^= 2;
    incoming(&model, &frame, None, false);
    assert!(matches!(
        client.poll(2, &Source, &mut Policy(true)),
        Err(Error::Station(station::Error::Wire(
            station::wire::Error::WrongPeer
        )))
    ));
    let mut raw = incoming_bytes(&response(0xb0, &[3, 0, 1, 0, 0, 0]), None, false);
    raw[12..16].copy_from_slice(&((40u32 << 8) | (1 << 16)).to_le_bytes());
    crate::net::wifi::mediatek::ring::rx::tests::device_receive(
        &model.queues[&0xd4520],
        &raw,
        true,
        0,
    );
    assert!(client.poll(3, &Source, &mut Policy(true)).is_err());
    incoming(
        &model,
        &response(0xb0, &[3, 0, 1, 0, 0xff, 0xff, 0]),
        None,
        false,
    );
    let events = client.poll(4, &Source, &mut Policy(true)).unwrap();
    assert!(events.iter().any(|event| matches!(event, Event::ExternalAuthentication(rx) if rx.status() == u16::MAX && rx.data() == [0] && Arc::ptr_eq(rx.session(), &session))));
    assert_eq!(
        client.station().phase(),
        station::Phase::ExternalAuthenticating
    );
    finish(client, model, 5);
}

#[test]
fn actual_exchange_deadline_during_dma_preparation_refuses_producer_publication() {
    use crate::bus::dma::memory::{CacheAttribute, MemoryError, PageGeometry, PinnedPages};
    struct DelayedSource {
        clock: crate::Clock,
        deadline: u64,
    }
    impl PageSource for DelayedSource {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            Source.page_geometry()
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            // Actual retained controller TSC advances while preparing unpublished
            // RAM. No synthetic firmware grant or deadline replacement occurs.
            while self.clock.now_us() < self.deadline {
                core::hint::spin_loop();
            }
            Source.allocate(bytes, alignment, attribute)
        }
    }
    let (mut client, model) = setup();
    let session = client
        .begin_external_authentication(profile(), vec![b'x'], 0, 500_000, &mut Policy(true))
        .unwrap();
    let source = DelayedSource {
        clock: client.state().controller.state().control.clock,
        deadline: client.state().authentication_deadline.unwrap(),
    };
    assert!(source.clock.now_us() < source.deadline);
    let before = model.memory.lock().unwrap().mappings.len();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(matches!(
        client.transmit_external_authentication(
            &session,
            1,
            0,
            &[19, 0, 1],
            1,
            &source,
            &mut Policy(true)
        ),
        Err(Error::GrantTimeout)
    ));
    // The real ROC grant remains live; it is the distinct retained exchange
    // deadline which prevented producer publication after DMA preparation.
    assert!(source.clock.now_us() < client.state().roc_deadline.unwrap());
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert_eq!(model.memory.lock().unwrap().mappings.len(), before);
    assert_eq!(
        client
            .state()
            .controller
            .state()
            .data_tx
            .as_ref()
            .unwrap()
            .outstanding_tokens(),
        0
    );
    assert_eq!(client.phase(), Phase::Quarantined);
    assert!(Arc::ptr_eq(
        client.station().external_authentication().unwrap(),
        &session
    ));
    drop(client);
    // Uncertain owner Drop deliberately retains its actual controller/ROC and
    // resources; a refused packet cannot authorize an invented reset/drain.
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn actual_peer_firmware_refusal_quarantines_original_exchange_and_resources() {
    let (mut client, model) = setup();
    // Existing firmware peer model returns its actual nonzero unified status.
    // BSS may have succeeded and the peer command may have affected hardware;
    // no local rejection grants rollback or resets the owned namespace.
    model.response.lock().unwrap().status = 0xc000_0001;
    assert!(matches!(
        client.begin_external_authentication(
            profile(),
            vec![b'x'],
            0,
            2_000_000,
            &mut Policy(true)
        ),
        Err(Error::Firmware(0xc000_0001))
    ));
    assert_eq!(client.phase(), Phase::Quarantined);
    {
        let firmware = model.response.lock().unwrap();
        assert!(firmware.device_execution);
        assert_eq!(firmware.bss_status, 0);
        assert!(firmware.peers.contains_key(&profile().wcid));
        let command = firmware.client_commands.last().unwrap();
        assert_eq!(u16::from_le_bytes(command[34..36].try_into().unwrap()), 3);
    }
    assert_eq!(
        client.replies().last().unwrap().command,
        Command::StationRecord
    );
    assert_eq!(client.replies().last().unwrap().status, 0xc000_0001);
    let session = client.station().external_authentication().unwrap().clone();
    assert_eq!(
        client.station().phase(),
        station::Phase::ExternalAuthenticating
    );
    assert!(client.state().format_generation.is_none());
    assert!(!client.station().port_open(None, None));
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(matches!(
        client.transmit_external_authentication(
            &session,
            1,
            0,
            &[19, 0],
            1,
            &Source,
            &mut Policy(true)
        ),
        Err(Error::WrongPhase)
    ));
    assert!(matches!(
        client.begin_external_authentication(
            profile(),
            vec![b'x'],
            1,
            2_000_000,
            &mut Policy(true)
        ),
        Err(Error::Busy)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    drop(client);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}
