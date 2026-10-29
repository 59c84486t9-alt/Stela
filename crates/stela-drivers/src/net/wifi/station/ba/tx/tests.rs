use crate::net::wifi::Band;
use crate::net::wifi::station::ba::{
    Action as BaAction, Error as BaError,
    tx::{Action as TxAction, Agreement, Session},
};
use crate::net::wifi::station::phy::{Mode, Width};
use crate::net::wifi::station::{ba::tests::*, tests::*, *};

fn station(maximum: u16) -> Station {
    let mut s = associated(1024, true);
    s.configure_tx_block_ack(maximum).unwrap();
    s
}
fn prepare(s: &mut Station, tid: u8, timeout: u16) -> (Ticket, Arc<Session>) {
    let TxAction::Prepare { ticket, session } =
        s.begin_tx_block_ack(tid, timeout, s.now + 1).unwrap()
    else {
        panic!("real prepare expected")
    };
    s.validate_tx_block_ack_prepare(ticket, &session).unwrap();
    (ticket, session)
}
fn transmit(action: TxAction) -> (Ticket, Arc<Session>, Vec<u8>) {
    let TxAction::Transmit {
        ticket,
        session,
        bytes,
    } = action
    else {
        panic!("wire expected")
    };
    (ticket, session, bytes)
}
fn programming(action: TxAction, enabled: bool) -> (Ticket, Arc<Session>, Option<Agreement>) {
    let TxAction::Program {
        ticket,
        session,
        agreement,
    } = action
    else {
        panic!("real program expected")
    };
    assert_eq!(agreement.is_some(), enabled);
    (ticket, session, agreement)
}
fn request_sent(s: &mut Station, tid: u8) -> Arc<Session> {
    let (ticket, session) = prepare(s, tid, 0);
    // SAFETY: pure model supplies exact synchronized next sequence and readiness.
    let (wire, same, bytes) = transmit(
        unsafe {
            s.complete_tx_block_ack_prepare(ticket, Completion::Accepted, Some(4095), s.now + 1)
        }
        .unwrap(),
    );
    assert!(Arc::ptr_eq(&session, &same));
    s.validate_tx_block_ack_transmit(wire, &session, &bytes)
        .unwrap();
    assert_eq!(&bytes[31..33], &0xfff0u16.to_le_bytes());
    assert!(matches!(
        // SAFETY: modeled exact frame admitted/queued, without air-ACK claim.
        unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }.unwrap(),
        TxAction::None
    ));
    session
}
fn peer_response(
    session: &Session,
    dialog: u8,
    status: u16,
    window: u16,
    timeout: u16,
    amsdu: bool,
) -> Mpdu {
    let parameters = u16::from(amsdu) | 2 | u16::from(session.tid()) << 2 | (window & 1023) << 6;
    let mut body = vec![3, 1, dialog];
    body.extend_from_slice(&status.to_le_bytes());
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&timeout.to_le_bytes());
    if window >= 1024 {
        body.extend_from_slice(&[159, 1, 1 | ((window >> 10) as u8) << 5]);
    }
    response(0xd0, &body)
}
fn receive_tx(s: &mut Station, frame: &Mpdu) -> TxAction {
    let BaAction::Tx(action) = receive(s, frame).unwrap() else {
        panic!("canonical TX ingress")
    };
    action
}
fn operational(s: &mut Station, tid: u8, timeout: u16) -> Arc<Session> {
    let session = request_sent(s, tid);
    let frame = peer_response(&session, session.dialog(), 0, 1024, timeout, true);
    let (ticket, same, agreement) = programming(receive_tx(s, &frame), true);
    assert!(Arc::ptr_eq(&session, &same));
    s.validate_tx_block_ack_program(ticket, &session, agreement)
        .unwrap();
    // SAFETY: model represents exact successful native operational programming.
    let TxAction::Operational {
        session: active, ..
    } = unsafe { s.complete_tx_block_ack_program(ticket, Completion::Accepted) }.unwrap()
    else {
        panic!("native ACK required")
    };
    assert!(Arc::ptr_eq(&active, &session));
    s.validate_tx_block_ack(&session).unwrap();
    session
}

#[test]
fn sequence_peer_response_and_native_ack_are_all_required_before_aggregate_tx() {
    let mut s = station(512);
    let (prepare, session) = prepare(&mut s, 3, 19);
    assert!(s.active_tx_block_ack(3).is_none());
    // SAFETY: modeled synchronized TID/next sequence.
    let (wire, _, bytes) = transmit(
        unsafe {
            s.complete_tx_block_ack_prepare(prepare, Completion::Accepted, Some(321), s.now + 1)
        }
        .unwrap(),
    );
    assert_eq!(
        &bytes[24..],
        &[3, 0, session.dialog(), 15, 128, 19, 0, 16, 20, 159, 1, 1]
    );
    let frame = peer_response(&session, session.dialog(), 0, 1024, 9, true);
    assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
    let mut changed = bytes.clone();
    changed[31] ^= 1;
    assert!(
        s.validate_tx_block_ack_transmit(wire, &session, &changed)
            .is_err()
    );
    s.validate_tx_block_ack_transmit(wire, &session, &bytes)
        .unwrap();
    // SAFETY: exact wire publication completed; a real matching early peer
    // response is held until this acknowledgement, then programs firmware.
    let (program, _, agreement) = programming(
        unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }.unwrap(),
        true,
    );
    let wrong = peer_response(&session, session.dialog().wrapping_add(1), 0, 512, 0, true);
    assert!(matches!(receive_tx(&mut s, &wrong), TxAction::None));
    assert_eq!(agreement.unwrap().window(), 512);
    assert_eq!(agreement.unwrap().timeout_tu(), 9);
    assert!(s.validate_tx_block_ack(&session).is_err());
    assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
    s.validate_tx_block_ack_program(program, &session, agreement)
        .unwrap();
    assert!(matches!(
        // SAFETY: matching firmware install ACK modeled.
        unsafe { s.complete_tx_block_ack_program(program, Completion::Accepted) }.unwrap(),
        TxAction::Operational { .. }
    ));
    assert_eq!(
        s.validate_tx_block_ack(&session).unwrap(),
        agreement.unwrap()
    );
    // SAFETY: old matching ticket is now stale and cannot activate again.
    assert!(unsafe { s.complete_tx_block_ack_program(program, Completion::Accepted) }.is_err());
}

#[test]
fn tid_block_preserves_software_cursor_until_synchronized_prepare_snapshot() {
    let mut s = station(1024);
    let context = Arc::clone(s.context.as_ref().unwrap());
    for sequence in 0..17 {
        assert_eq!(s.allocate_qos_sequence(&context, 3), Ok(sequence));
    }
    let (prepare, session) = prepare(&mut s, 3, 0);
    assert!(s.tx_block_ack_blocks_data(3));
    assert_eq!(s.allocate_qos_sequence(&context, 3), Err(Error::Busy));
    assert_eq!(s.next_qos_sequence(&context, 3), Ok(17));
    assert_eq!(s.allocate_qos_sequence(&context, 4), Ok(0));
    // SAFETY: fixture models the native synchronization of old TID users
    // before reading this real canonical cursor; independent TIDs keep working.
    let snapshot = s.next_qos_sequence(&context, 3).unwrap();
    let (wire, _, bytes) = transmit(
        // SAFETY: the ticket is this station's own outstanding completion, reported once.
        unsafe {
            s.complete_tx_block_ack_prepare(
                prepare,
                Completion::Accepted,
                Some(snapshot),
                s.now + 1,
            )
        }
        .unwrap(),
    );
    assert_eq!(
        u16::from_le_bytes(bytes[31..33].try_into().unwrap()) >> 4,
        17
    );
    // SAFETY: request publication then peer response modeled.
    unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }.unwrap();
    let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
    let (program, _, _) = programming(receive_tx(&mut s, &frame), true);
    assert_eq!(s.allocate_qos_sequence(&context, 3), Err(Error::Busy));
    // SAFETY: exact successful firmware operation permits the queued TID again.
    unsafe { s.complete_tx_block_ack_program(program, Completion::Accepted) }.unwrap();
    assert!(!s.tx_block_ack_blocks_data(3));
    assert_eq!(s.allocate_qos_sequence(&context, 3), Ok(17));
    s.stop_tx_block_ack(3, false).unwrap();
    assert!(s.tx_block_ack_blocks_data(3));
    assert_eq!(s.allocate_qos_sequence(&context, 3), Err(Error::Busy));
    assert_eq!(s.next_qos_sequence(&context, 3), Ok(18));
}

#[test]
fn early_peer_reply_cannot_bypass_cancelled_rejected_or_uncertain_real_request_publication() {
    for result in [
        Completion::Accepted,
        Completion::RejectedAndIdle,
        Completion::Uncertain,
    ] {
        let mut s = station(1024);
        let (prepare_ticket, session) = prepare(&mut s, 3, 0);
        // SAFETY: synchronized software TID counter and kept queue.
        let (wire, _, _) = transmit(
            unsafe {
                s.complete_tx_block_ack_prepare(
                    prepare_ticket,
                    Completion::Accepted,
                    Some(8),
                    s.now + 1,
                )
            }
            .unwrap(),
        );
        let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
        assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
        if result == Completion::Accepted {
            let delba = response(0xd0, &[3, 2, 0, 0x30, 37, 0]);
            assert!(matches!(receive_tx(&mut s, &delba), TxAction::None));
        }
        // SAFETY: matching real publication outcome, including uncertain state.
        let action = unsafe { s.complete_tx_block_ack_transmit(wire, result, s.now + 1) }.unwrap();
        if result == Completion::Uncertain {
            assert!(matches!(action, TxAction::None));
        } else {
            programming(action, false);
        }
        assert!(s.validate_tx_block_ack(&session).is_err());
    }
}

#[test]
fn decline_and_zero_buffer_stop_without_sending_delba_or_enabling_aggregation() {
    for (status, window) in [(37, 64), (0, 0)] {
        let mut s = station(1024);
        let session = request_sent(&mut s, 3);
        let frame = peer_response(&session, session.dialog(), status, window, 0, true);
        let (ticket, _, agreement) = programming(receive_tx(&mut s, &frame), false);
        s.validate_tx_block_ack_program(ticket, &session, agreement)
            .unwrap();
        assert!(matches!(
            // SAFETY: completed disable/retirement before legacy queue release.
            unsafe { s.complete_tx_block_ack_program(ticket, Completion::Accepted) }.unwrap(),
            TxAction::ResumeLegacy { .. }
        ));
        assert!(s.active_tx_block_ack(3).is_none());
    }
}

#[test]
fn ba_window_requests_follow_ht_and_he_limits() {
    for (mode, hardware_maximum, request_window, peer_window, final_window) in
        [(Mode::Ht, 32, 64, 512, 32), (Mode::He, 512, 256, 768, 512)]
    {
        let mut j = modern_join();
        let source = modern_ies(false);
        let mut local = Vec::new();
        let mut rest = source.as_slice();
        while !rest.is_empty() {
            let size = usize::from(rest[1]);
            let element = &rest[..size + 2];
            let omit = (mode == Mode::Ht && element[0] == 191)
                || (element[0] == 255
                    && (element.get(2) == Some(&108)
                        || (mode == Mode::Ht && element.get(2) == Some(&35))));
            if !omit {
                local.extend_from_slice(element);
            }
            rest = &rest[size + 2..];
        }
        let width = if mode == Mode::Ht {
            Width::Mhz40
        } else {
            Width::Mhz80
        };
        j.request =
            wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, mode, width).unwrap();
        let mut s = Station::new(LOCAL).unwrap();
        let configured = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
        s.complete_configuration(ticket(&configured), Completion::Accepted, 3)
            .unwrap();
        s.configure_tx_block_ack(hardware_maximum).unwrap();
        let (prepare, session) = prepare(&mut s, 3, 0);
        // SAFETY: source canonical software cursor after native TID drain.
        let (wire, _, bytes) = transmit(
            unsafe {
                s.complete_tx_block_ack_prepare(prepare, Completion::Accepted, Some(17), s.now + 1)
            }
            .unwrap(),
        );
        let parameters = u16::from_le_bytes(bytes[27..29].try_into().unwrap());
        assert_eq!(parameters >> 6, request_window);
        assert_eq!(bytes.len(), if mode == Mode::Ht { 33 } else { 36 });
        // SAFETY: request publication modeled before the real peer input.
        unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }.unwrap();
        let frame = peer_response(&session, session.dialog(), 0, peer_window, 0, true);
        let (_, _, agreement) = programming(receive_tx(&mut s, &frame), true);
        assert_eq!(agreement.unwrap().window(), final_window);
    }
}

#[test]
fn source_no_amsdu_latches_even_on_wrong_dialog_and_does_not_clear_on_later_yes() {
    let mut s = station(1024);
    let session = operational(&mut s, 3, 0);
    assert!(s.tx_block_ack_allows_software_amsdu(&session).unwrap());
    let frame = peer_response(&session, session.dialog().wrapping_add(1), 0, 64, 0, false);
    assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
    assert!(!s.tx_block_ack_allows_software_amsdu(&session).unwrap());
    let positive = peer_response(&session, session.dialog(), 0, 64, 0, true);
    assert!(matches!(receive_tx(&mut s, &positive), TxAction::None));
    assert!(!s.tx_block_ack_allows_software_amsdu(&session).unwrap());
}

#[test]
fn local_stop_revokes_before_disable_then_delba_publication_before_tid_reuse() {
    let mut s = station(1024);
    let session = operational(&mut s, 3, 0);
    let (stop, _, _) = programming(s.stop_tx_block_ack(3, true).unwrap(), false);
    assert!(s.validate_tx_block_ack(&session).is_err());
    // SAFETY: real disable/old TX callbacks/aggregate owners retired.
    let (wire, _, bytes) =
        transmit(unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap());
    assert_eq!(&bytes[24..], &[3, 2, 0, 0x38, 37, 0]);
    assert!(matches!(
        s.begin_tx_block_ack(3, 0, s.now + 1),
        Err(BaError::Busy)
    ));
    s.validate_tx_block_ack_transmit(wire, &session, &bytes)
        .unwrap();
    assert!(matches!(
        // SAFETY: queued old DELBA cannot be published after a future request.
        unsafe { s.complete_tx_block_ack_transmit(wire, Completion::Accepted, s.now + 1) }.unwrap(),
        TxAction::ResumeLegacy { .. }
    ));
    assert!(matches!(
        s.begin_tx_block_ack(3, 0, s.now + 1).unwrap(),
        TxAction::Prepare { .. }
    ));
}

#[test]
fn recipient_delba_cancels_pending_prepare_request_and_operational_completion() {
    for stage in 0..3 {
        let mut s = station(1024);
        let (prepare_ticket, session) = prepare(&mut s, 3, 0);
        let mut pending = prepare_ticket;
        let mut agreement = None;
        if stage >= 1 {
            // SAFETY: synchronized TID state, kept through cancellation.
            let (wire, _, _) = transmit(
                unsafe {
                    s.complete_tx_block_ack_prepare(
                        pending,
                        Completion::Accepted,
                        Some(3),
                        s.now + 1,
                    )
                }
                .unwrap(),
            );
            pending = wire;
        }
        if stage == 2 {
            // SAFETY: request publication acknowledged before peer input.
            unsafe { s.complete_tx_block_ack_transmit(pending, Completion::Accepted, s.now + 1) }
                .unwrap();
            let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
            let (ticket, _, a) = programming(receive_tx(&mut s, &frame), true);
            pending = ticket;
            agreement = a;
        }
        let delba = response(0xd0, &[3, 2, 0, 0x30, 37, 0]);
        assert!(matches!(receive_tx(&mut s, &delba), TxAction::None));
        assert!(s.active_tx_block_ack(3).is_none());
        match stage {
            0 => assert!(s.validate_tx_block_ack_prepare(pending, &session).is_err()),
            1 => assert!(
                s.validate_tx_block_ack_transmit(pending, &session, &[])
                    .is_err()
            ),
            _ => assert!(
                s.validate_tx_block_ack_program(pending, &session, agreement)
                    .is_err()
            ),
        }
        // SAFETY: model the old real operation finishing after peer cancellation.
        let action = unsafe {
            match stage {
                0 => s.complete_tx_block_ack_prepare(
                    pending,
                    Completion::Accepted,
                    Some(3),
                    s.now + 1,
                ),
                1 => s.complete_tx_block_ack_transmit(pending, Completion::Accepted, s.now + 1),
                _ => s.complete_tx_block_ack_program(pending, Completion::Accepted),
            }
        }
        .unwrap();
        let (stop, _, _) = programming(action, false);
        assert!(matches!(
            // SAFETY: only a completed stop now releases kept pending TX.
            unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
            TxAction::ResumeLegacy { .. }
        ));
        assert!(s.validate_tx_block_ack(&session).is_err());
    }
}

#[test]
fn deadlines_start_at_publication() {
    let mut s = station(1024);
    let session = request_sent(&mut s, 3);
    let due = s.next_tx_block_ack_deadline().unwrap();
    assert!(matches!(
        s.poll_tx_block_ack(due - 1).unwrap(),
        TxAction::None
    ));
    let (stop, _, _) = programming(s.poll_tx_block_ack(due).unwrap(), false);
    let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
    assert!(matches!(receive_tx(&mut s, &frame), TxAction::None));
    // SAFETY: stop completion modeled.
    let (wire, _, _) =
        transmit(unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap());
    // SAFETY: terminal rejected old DELBA publication still permits native legacy reuse.
    unsafe { s.complete_tx_block_ack_transmit(wire, Completion::RejectedAndIdle, s.now + 1) }
        .unwrap();

    let active = operational(&mut s, 4, 10);
    let first = s.next_tx_block_ack_deadline().unwrap();
    assert!(matches!(
        s.poll_tx_block_ack(first - 1).unwrap(),
        TxAction::None
    ));
    // SAFETY: only a real current aggregate publication refreshes inactivity.
    unsafe { s.tx_block_ack_published(&active, first - 1) }.unwrap();
    let refreshed = s.next_tx_block_ack_deadline().unwrap();
    assert_eq!(refreshed, first - 1 + 10 * 1024);
    assert!(matches!(
        s.poll_tx_block_ack(first).unwrap(),
        TxAction::None
    ));
    programming(s.poll_tx_block_ack(refreshed).unwrap(), false);
    assert!(s.validate_tx_block_ack(&active).is_err());
}

#[test]
fn retry_limits_count_wire_requests() {
    let mut s = station(1024);
    for attempt in 0..16 {
        if attempt >= 4 {
            assert!(matches!(
                s.begin_tx_block_ack(3, 0, s.now + 1),
                Err(BaError::Busy)
            ));
            s.clock(s.now + 15_000_000).unwrap();
        }
        let session = request_sent(&mut s, 3);
        let declined = peer_response(&session, session.dialog(), 37, 64, 0, true);
        let (stop, _, _) = programming(receive_tx(&mut s, &declined), false);
        // SAFETY: each independent native owner stopped/drained.
        unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap();
    }
    s.clock(s.now + 15_000_000).unwrap();
    assert!(matches!(
        s.begin_tx_block_ack(3, 0, s.now + 1),
        Err(BaError::Busy)
    ));
    // Other TIDs keep independent budgets. Four failed wire requests
    // exhaust the burst, then a real accepted peer resets that TID's count.
    for _ in 0..4 {
        let session = request_sent(&mut s, 4);
        let declined = peer_response(&session, session.dialog(), 37, 64, 0, true);
        let (stop, _, _) = programming(receive_tx(&mut s, &declined), false);
        // SAFETY: matching stop completes before this TID's next attempt.
        unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap();
    }
    assert!(matches!(
        s.begin_tx_block_ack(4, 0, s.now + 1),
        Err(BaError::Busy)
    ));
    s.clock(s.now + 15_000_000).unwrap();
    let other = operational(&mut s, 4, 0);
    assert_eq!(other.tid(), 4);
    let (stop, _, _) = programming(s.stop_tx_block_ack(4, false).unwrap(), false);
    // SAFETY: native session stop/drain modeled.
    unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap();
    assert!(matches!(
        s.begin_tx_block_ack(4, 0, s.now + 1).unwrap(),
        TxAction::Prepare { .. }
    ));
}

#[test]
fn uncertain_stop_never_releases_pending_tx() {
    let mut s = station(1024);
    let (ticket, session) = prepare(&mut s, 3, 0);
    assert!(matches!(
        // SAFETY: model explicitly uncertain real preparation; no idle proof.
        unsafe { s.complete_tx_block_ack_prepare(ticket, Completion::Uncertain, None, s.now + 1) }
            .unwrap(),
        TxAction::None
    ));
    assert!(matches!(
        s.begin_tx_block_ack(3, 0, s.now + 1),
        Err(BaError::Busy)
    ));
    let (stop, _, _) = programming(s.stop_tx_block_ack(3, false).unwrap(), false);
    assert!(matches!(
        // SAFETY: rejected disable is insufficient for retirement.
        unsafe { s.complete_tx_block_ack_program(stop, Completion::RejectedAndIdle) }.unwrap(),
        TxAction::None
    ));
    assert!(s.validate_tx_block_ack(&session).is_err());
    assert!(matches!(
        s.begin_tx_block_ack(3, 0, s.now + 1),
        Err(BaError::Busy)
    ));
}

#[test]
fn uncertain_operational_ack_cannot_be_replayed_into_success_or_legacy_queue_release() {
    let mut s = station(1024);
    let session = request_sent(&mut s, 3);
    let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
    let (enable, _, _) = programming(receive_tx(&mut s, &frame), true);
    assert!(matches!(
        // SAFETY: transport cannot establish the terminal command result.
        unsafe { s.complete_tx_block_ack_program(enable, Completion::Uncertain) }.unwrap(),
        TxAction::None
    ));
    assert!(s.validate_tx_block_ack(&session).is_err());
    // SAFETY: a late old ticket cannot be recast as an activation acknowledgement.
    assert!(unsafe { s.complete_tx_block_ack_program(enable, Completion::Accepted) }.is_err());
    assert!(matches!(
        s.begin_tx_block_ack(3, 0, s.now + 1),
        Err(BaError::Busy)
    ));
    let (stop, _, _) = programming(s.stop_tx_block_ack(3, false).unwrap(), false);
    assert!(matches!(
        // SAFETY: independently completed disable includes retirement of the old
        // uncertain command callback and every old-session TX user.
        unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
        TxAction::ResumeLegacy { .. }
    ));
}

#[test]
fn disconnect_revokes_data_and_late_operational_ack_requires_stop_without_delba() {
    let mut s = station(1024);
    let session = request_sent(&mut s, 3);
    let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
    let (enable, _, _) = programming(receive_tx(&mut s, &frame), true);
    let removal = s.disconnect().unwrap();
    assert!(s.validate_tx_block_ack(&session).is_err());
    // SAFETY: old successful operation finishes after association revocation.
    let (stop, _, agreement) = programming(
        unsafe { s.complete_tx_block_ack_program(enable, Completion::Accepted) }.unwrap(),
        false,
    );
    s.validate_tx_block_ack_program(stop, &session, agreement)
        .unwrap();
    assert!(matches!(
        // SAFETY: independently acknowledged native stop under kept old ownership.
        unsafe { s.complete_tx_block_ack_program(stop, Completion::Accepted) }.unwrap(),
        TxAction::ResumeLegacy { .. }
    ));
    s.complete_removal(ticket(&removal), Completion::Accepted)
        .unwrap();
    assert!(s.active_tx_block_ack(3).is_none());
}
#[test]
fn cancellation_validator_requires_exact_pending_ticket_session_and_payload() {
    for stage in 0..3 {
        let mut s = station(1024);
        let (ticket, session) = prepare(&mut s, 3, 0);
        let mut action = TxAction::Prepare {
            ticket,
            session: session.clone(),
        };
        if stage >= 1 {
            // SAFETY: this canonical peer model has synchronized TID preparation.
            action = unsafe {
                s.complete_tx_block_ack_prepare(ticket, Completion::Accepted, Some(3), s.now + 1)
            }
            .unwrap();
        }
        if stage == 2 {
            let TxAction::Transmit { ticket, .. } = action else {
                unreachable!()
            };
            // SAFETY: modeled publication completed before the peer response.
            unsafe { s.complete_tx_block_ack_transmit(ticket, Completion::Accepted, s.now + 1) }
                .unwrap();
            let frame = peer_response(&session, session.dialog(), 0, 64, 0, true);
            action = receive_tx(&mut s, &frame);
        }
        assert!(s.validate_tx_block_ack_cancellation(&action).is_err());
        let delba = response(0xd0, &[3, 2, 0, 0x30, 37, 0]);
        assert!(matches!(receive_tx(&mut s, &delba), TxAction::None));
        s.validate_tx_block_ack_cancellation(&action).unwrap();
        let clone = |replacement: Arc<Session>, bad_ticket: bool, bad_payload: bool| {
            let change = |mut ticket: Ticket| {
                if bad_ticket {
                    ticket.serial += 1;
                }
                ticket
            };
            match &action {
                TxAction::Prepare { ticket, .. } => TxAction::Prepare {
                    ticket: change(*ticket),
                    session: replacement,
                },
                TxAction::Transmit { ticket, bytes, .. } => {
                    let mut bytes = bytes.clone();
                    if bad_payload {
                        bytes.push(0);
                    }
                    TxAction::Transmit {
                        ticket: change(*ticket),
                        session: replacement,
                        bytes,
                    }
                }
                TxAction::Program {
                    ticket, agreement, ..
                } => {
                    let agreement = agreement.map(|mut a| {
                        if bad_payload {
                            a.window += 1;
                        }
                        a
                    });
                    TxAction::Program {
                        ticket: change(*ticket),
                        session: replacement,
                        agreement,
                    }
                }
                _ => unreachable!(),
            }
        };
        let copied = Arc::new(Session {
            ticket: session.ticket,
            context: session.context.clone(),
            tid: session.tid,
            dialog: session.dialog,
        });
        assert!(
            s.validate_tx_block_ack_cancellation(&clone(copied, false, false))
                .is_err()
        );
        assert!(
            s.validate_tx_block_ack_cancellation(&clone(session.clone(), true, false))
                .is_err()
        );
        if stage != 0 {
            assert!(
                s.validate_tx_block_ack_cancellation(&clone(session.clone(), false, true))
                    .is_err()
            );
        }
        s.validate_tx_block_ack_cancellation(&action).unwrap();
    }
}
