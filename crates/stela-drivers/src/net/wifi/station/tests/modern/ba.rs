use super::*;
use crate::net::wifi::station::ba::{Action as BaAction, Error as BaError, RxSession};

mod tx;

fn associated(maximum: u16, amsdu: bool) -> Station {
    let mut s = Station::new(LOCAL).unwrap();
    let j = modern_join();
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    s.complete_configuration(ticket(&a), Completion::Accepted, 3)
        .unwrap();
    s.configure_rx_block_ack(maximum, amsdu).unwrap();
    s
}
fn request(dialog: u8, tid: u8, window: u16, timeout: u16, start: u16, immediate: bool) -> Mpdu {
    let parameters = u16::from(tid) << 2 | (window & 1023) << 6 | if immediate { 2 } else { 0 };
    let mut body = vec![3, 0, dialog];
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&timeout.to_le_bytes());
    body.extend_from_slice(&(start << 4).to_le_bytes());
    if window >= 1024 {
        body.extend_from_slice(&[159, 1, 1 | ((window >> 10) as u8) << 5]);
    }
    response(0xd0, &body)
}
fn receive(s: &mut Station, frame: &Mpdu) -> Result<BaAction, BaError> {
    s.receive_block_ack(s.association_epoch().unwrap(), frame, s.now + 1)
}
fn program(a: BaAction, enable: bool) -> (Ticket, Arc<RxSession>) {
    let BaAction::Program {
        ticket,
        session,
        enable: actual,
    } = a
    else {
        panic!("program expected")
    };
    assert_eq!(actual, enable);
    (ticket, session)
}
fn status(a: BaAction) -> (u16, Vec<u8>) {
    let BaAction::Transmit {
        bytes,
        session: None,
        ..
    } = a
    else {
        panic!("refusal wire expected")
    };
    (u16::from_le_bytes(bytes[27..29].try_into().unwrap()), bytes)
}
fn active(s: &mut Station, dialog: u8, tid: u8) -> Arc<RxSession> {
    let (ticket, planned) = program(
        receive(s, &request(dialog, tid, 64, 0, 10, true)).unwrap(),
        true,
    );
    s.validate_rx_block_ack_program(ticket, &planned, true)
        .unwrap();
    // SAFETY: this pure fixture models exact completed native install/queue readiness.
    let a = unsafe { s.complete_rx_block_ack(ticket, Completion::Accepted) }.unwrap();
    let BaAction::Transmit {
        session: Some(installed),
        bytes,
        ..
    } = a
    else {
        panic!("positive reply")
    };
    assert_eq!(u16::from_le_bytes(bytes[27..29].try_into().unwrap()), 0);
    assert!(Arc::ptr_eq(&planned, &installed));
    s.validate_rx_block_ack(&installed).unwrap();
    installed
}

#[test]
fn only_real_current_native_install_completion_activates_exact_session_and_positive_reply() {
    let mut s = associated(1024, true);
    let (t, session) = program(
        receive(&mut s, &request(7, 3, 1024, 19, 4095, true)).unwrap(),
        true,
    );
    assert!(s.active_rx_block_ack(3).is_none());
    assert!(s.validate_rx_block_ack(&session).is_err());
    assert_eq!(
        (
            session.tid(),
            session.start_sequence(),
            session.window(),
            session.timeout_tu()
        ),
        (3, 4095, 1024, 19)
    );
    assert!(session.amsdu_in_ampdu());
    assert!(!session.firmware_amsdu());
    s.validate_rx_block_ack_program(t, &session, true).unwrap();
    // SAFETY: modeled exact native command/queue acknowledgement only.
    let a = unsafe { s.complete_rx_block_ack(t, Completion::Accepted) }.unwrap();
    let BaAction::Transmit {
        bytes,
        session: Some(installed),
        context,
        ..
    } = a
    else {
        panic!("positive reply")
    };
    assert_eq!(&bytes[24..], &[3, 1, 7, 0, 0, 15, 0, 19, 0, 159, 1, 0x21]);
    assert!(Arc::ptr_eq(&context, session.context()));
    assert!(Arc::ptr_eq(&installed, &session));
    assert!(s.validate_rx_block_ack_program(t, &session, true).is_err());
    assert!(s.validate_rx_block_ack(&session).is_ok());
    // SAFETY: duplicate completion must not mutate or return another positive reply.
    assert!(matches!(
        unsafe { s.complete_rx_block_ack(t, Completion::Accepted) },
        Err(BaError::Stale)
    ));
}

#[test]
fn default_window_and_actual_hardware_clamp_are_applied_after_source_validation() {
    let mut s = associated(256, false);
    let (_, session) = program(
        receive(&mut s, &request(1, 0, 0, 0, 10, true)).unwrap(),
        true,
    );
    assert_eq!(session.window(), 256);
    assert!(!session.amsdu_in_ampdu());
    assert_eq!(s.configure_rx_block_ack(512, false), Err(BaError::Busy));
    assert_eq!(
        s.configure_rx_block_ack(0, false),
        Err(BaError::InvalidLimits)
    );
    assert_eq!(
        s.configure_rx_block_ack(1025, false),
        Err(BaError::InvalidLimits)
    );
}

#[test]
fn unrelated_generic_ie_errors_ignore_extension_and_keep_valid_base_addba_request() {
    for tail in [vec![3, 0], vec![0, 0, 0, 0], vec![196, 0]] {
        let mut s = associated(1024, true);
        let original = request(1, 3, 32, 0, 10, true);
        let mut bytes = original.bytes().to_vec();
        bytes.extend_from_slice(&[159, 1, 0x21]);
        bytes.extend_from_slice(&tail);
        let frame = Mpdu::new(bytes, original.radio, original.security).unwrap();
        let (_, session) = program(receive(&mut s, &frame).unwrap(), true);
        assert_eq!(session.window(), 32);
    }
}

#[test]
fn source_invalid_tid_policy_and_oversize_refusals_keep_actual_air_parameters() {
    for (tid, window, immediate, expected) in [
        (15, 512, true, 37),
        (3, 512, false, 38),
        (3, 2048, true, 38),
    ] {
        let mut s = associated(64, true);
        let (code, bytes) =
            status(receive(&mut s, &request(9, tid, window, 7, 10, immediate)).unwrap());
        assert_eq!(code, expected);
        let parameters = u16::from_le_bytes(bytes[29..31].try_into().unwrap());
        assert_eq!((parameters >> 2) & 15, u16::from(tid));
        assert_eq!(parameters >> 6, window & 1023);
        assert_eq!(bytes[35] >> 5, (window >> 10) as u8);
        assert!(s.active_rx_block_ack(tid).is_none());
    }
}

#[test]
fn same_dialog_source_driver_reorder_profile_declines_without_resetting_live_queue() {
    let mut s = associated(1024, true);
    let session = active(&mut s, 7, 3);
    for timeout in [0, 90] {
        assert_eq!(
            status(receive(&mut s, &request(7, 3, 32, timeout, 20, true)).unwrap()).0,
            37
        );
        assert!(Arc::ptr_eq(s.active_rx_block_ack(3).unwrap(), &session));
    }
}

#[test]
fn replacement_stops_and_invalidates_old_session_before_programming_new_exact_ssn() {
    let mut s = associated(1024, true);
    let old = active(&mut s, 1, 3);
    let (stop, stopping) = program(
        receive(&mut s, &request(2, 3, 32, 9, 22, true)).unwrap(),
        false,
    );
    assert!(Arc::ptr_eq(&old, &stopping));
    assert!(s.active_rx_block_ack(3).is_none());
    assert!(s.validate_rx_block_ack(&old).is_err());
    s.validate_rx_block_ack_program(stop, &old, false).unwrap();
    // SAFETY: pure model supplies actual completed stop/drain.
    let (install, next) = program(
        unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
        true,
    );
    assert_ne!(install, old.ticket());
    assert!(!Arc::ptr_eq(&next, &old));
    assert_eq!(
        (next.start_sequence(), next.window(), next.timeout_tu()),
        (22, 32, 9)
    );
    assert!(s.validate_rx_block_ack(&next).is_err());
    // SAFETY: second native install is independently acknowledged.
    unsafe { s.complete_rx_block_ack(install, Completion::Accepted) }.unwrap();
    s.validate_rx_block_ack(&next).unwrap();
    assert!(s.validate_rx_block_ack(&old).is_err());
}

#[test]
fn rejected_idle_install_refuses_peer_while_uncertain_install_retains_and_cannot_retry() {
    for outcome in [Completion::RejectedAndIdle, Completion::Uncertain] {
        let mut s = associated(1024, true);
        let (ticket, old) = program(
            receive(&mut s, &request(1, 0, 64, 0, 5, true)).unwrap(),
            true,
        );
        // SAFETY: fixture explicitly distinguishes a truly idle rejection from uncertainty.
        let action = unsafe { s.complete_rx_block_ack(ticket, outcome) }.unwrap();
        if outcome == Completion::RejectedAndIdle {
            assert_eq!(status(action).0, 37);
            program(
                receive(&mut s, &request(2, 0, 64, 0, 9, true)).unwrap(),
                true,
            );
        } else {
            assert!(matches!(action, BaAction::None));
            assert_eq!(
                status(receive(&mut s, &request(2, 0, 64, 0, 9, true)).unwrap()).0,
                37
            );
            let (stop, held) = program(s.stop_rx_block_ack(0, None).unwrap(), false);
            assert!(Arc::ptr_eq(&held, &old));
            // SAFETY: only subsequent actual stop/drain can retire this owner.
            assert!(matches!(
                unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
                BaAction::None
            ));
        }
        assert!(s.validate_rx_block_ack(&old).is_err());
    }
}

#[test]
fn failed_stop_never_releases_or_restarts_the_old_ownership() {
    let mut s = associated(1024, true);
    let old = active(&mut s, 1, 0);
    let (ticket, _) = program(s.stop_rx_block_ack(0, Some(37)).unwrap(), false);
    // SAFETY: a rejected disable is not actual retirement and stays quarantined.
    assert!(matches!(
        unsafe { s.complete_rx_block_ack(ticket, Completion::RejectedAndIdle) }.unwrap(),
        BaAction::None
    ));
    assert!(s.active_rx_block_ack(0).is_none());
    assert_eq!(
        status(receive(&mut s, &request(2, 0, 64, 0, 10, true)).unwrap()).0,
        37
    );
    let (again, held) = program(s.stop_rx_block_ack(0, None).unwrap(), false);
    assert!(Arc::ptr_eq(&held, &old));
    assert_ne!(again, ticket);
}

#[test]
fn local_delba_is_sent_only_after_disable_drain_with_recipient_direction() {
    let mut s = associated(1024, true);
    let old = active(&mut s, 1, 3);
    let (ticket, _) = program(s.stop_rx_block_ack(3, Some(37)).unwrap(), false);
    assert!(s.validate_rx_block_ack(&old).is_err());
    // SAFETY: native firmware stop and real queue retirement acknowledged.
    let BaAction::Transmit {
        bytes,
        session: None,
        ..
    } = unsafe { s.complete_rx_block_ack(ticket, Completion::Accepted) }.unwrap()
    else {
        panic!("DELBA after stop")
    };
    assert_eq!(&bytes[24..], &[3, 2, 0, 0x30, 37, 0]);
}

#[test]
fn actual_peer_initiator_delba_stops_rx_without_sending_a_reply() {
    let mut s = associated(1024, true);
    active(&mut s, 1, 3);
    let frame = response(0xd0, &[3, 2, 0, 0x38, 37, 0]);
    let (ticket, _) = program(receive(&mut s, &frame).unwrap(), false);
    // SAFETY: actual native stop/drain completed in the fixture.
    assert!(matches!(
        unsafe { s.complete_rx_block_ack(ticket, Completion::Accepted) }.unwrap(),
        BaAction::None
    ));
}

#[test]
fn peer_delba_cancels_pending_install_and_late_ack_requires_stop_instead_of_success() {
    for result in [
        Completion::Accepted,
        Completion::RejectedAndIdle,
        Completion::Uncertain,
    ] {
        let mut s = associated(1024, true);
        let (install, session) = program(
            receive(&mut s, &request(1, 3, 64, 0, 10, true)).unwrap(),
            true,
        );
        let delba = response(0xd0, &[3, 2, 0, 0x38, 37, 0]);
        assert!(matches!(receive(&mut s, &delba).unwrap(), BaAction::None));
        assert!(
            s.validate_rx_block_ack_program(install, &session, true)
                .is_err()
        );
        // SAFETY: model returns the real outstanding install outcome after cancellation.
        let next = unsafe { s.complete_rx_block_ack(install, result) }.unwrap();
        assert!(s.active_rx_block_ack(3).is_none());
        if result == Completion::Accepted {
            let (stop, held) = program(next, false);
            assert!(Arc::ptr_eq(&held, &session));
            // SAFETY: only stop/drain of the late successful install retires it.
            assert!(matches!(
                unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
                BaAction::None
            ));
        } else {
            assert!(matches!(next, BaAction::None));
        }
        assert!(s.validate_rx_block_ack(&session).is_err());
    }
}

#[test]
fn peer_delba_cancels_replacement_while_old_disable_is_still_pending() {
    let mut s = associated(1024, true);
    let old = active(&mut s, 1, 3);
    let (stop, _) = program(
        receive(&mut s, &request(2, 3, 32, 0, 90, true)).unwrap(),
        false,
    );
    let delba = response(0xd0, &[3, 2, 0, 0x38, 37, 0]);
    assert!(matches!(receive(&mut s, &delba).unwrap(), BaAction::None));
    s.validate_rx_block_ack_program(stop, &old, false).unwrap();
    // SAFETY: completing this old stop cannot trigger the cancelled new install.
    assert!(matches!(
        unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
        BaAction::None
    ));
    assert!(s.active_rx_block_ack(3).is_none());
}

#[test]
fn wrong_peer_radio_epoch_integrity_and_protected_actions_cannot_create_agreements() {
    let original = request(1, 0, 64, 0, 5, true);
    for mutation in 0..5 {
        let mut s = associated(1024, true);
        let mut frame = original.clone();
        match mutation {
            0 => frame.radio.channel += 4,
            1 => frame.fcs_error = true,
            2 => frame.monitor_only = true,
            3 => {
                let mut b = frame.bytes().to_vec();
                b[10] ^= 4;
                frame = Mpdu::new(b, frame.radio, frame.security).unwrap();
            }
            _ => {
                let mut b = frame.bytes().to_vec();
                b[1] |= 0x40;
                frame = Mpdu::new(b, frame.radio, frame.security).unwrap();
            }
        }
        assert!(receive(&mut s, &frame).is_err());
        assert!(s.active_rx_block_ack(0).is_none());
    }
    let mut s = associated(1024, true);
    assert!(matches!(
        s.receive_block_ack(s.epoch + 1, &original, 4),
        Err(BaError::Stale)
    ));
}

#[test]
fn bar_requires_exact_current_peer_tid_and_acknowledged_active_queue() {
    let mut s = associated(1024, true);
    let current = active(&mut s, 1, 3);
    let mut bytes = vec![0; 20];
    bytes[..2].copy_from_slice(&0x0084u16.to_le_bytes());
    bytes[4..10].copy_from_slice(&LOCAL.0);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..18].copy_from_slice(&0x3004u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0x1230u16.to_le_bytes());
    let frame = Mpdu::new(
        bytes.clone(),
        response(0xd0, &[]).radio,
        SecurityStatus::default(),
    )
    .unwrap();
    let BaAction::Bar {
        session,
        start_sequence,
    } = receive(&mut s, &frame).unwrap()
    else {
        panic!("actual BAR")
    };
    assert!(Arc::ptr_eq(&session, &current));
    assert_eq!(start_sequence, 0x123);
    bytes[17] = 0x40;
    let other = Mpdu::new(bytes, frame.radio.clone(), SecurityStatus::default()).unwrap();
    assert!(matches!(receive(&mut s, &other), Err(BaError::NoSession)));
    s.stop_rx_block_ack(3, None).unwrap();
    assert!(matches!(receive(&mut s, &frame), Err(BaError::NoSession)));
}

#[test]
fn disconnect_revokes_pending_install_and_active_sessions_but_allows_actual_stop() {
    let mut s = associated(1024, true);
    let installed = active(&mut s, 1, 3);
    let (pending, plan) = program(
        receive(&mut s, &request(2, 4, 64, 0, 5, true)).unwrap(),
        true,
    );
    let removal = s.disconnect().unwrap();
    assert!(s.validate_rx_block_ack(&installed).is_err());
    assert!(
        s.validate_rx_block_ack_program(pending, &plan, true)
            .is_err()
    );
    // SAFETY: late ACK is rejected; it cannot revive a disconnected association.
    assert!(matches!(
        unsafe { s.complete_rx_block_ack(pending, Completion::Accepted) },
        Err(BaError::Stale)
    ));
    let (stop, old) = program(s.stop_rx_block_ack(3, Some(37)).unwrap(), false);
    s.validate_rx_block_ack_program(stop, &old, false).unwrap();
    // SAFETY: acknowledged stop during disconnect cannot send a new management frame.
    assert!(matches!(
        unsafe { s.complete_rx_block_ack(stop, Completion::Accepted) }.unwrap(),
        BaAction::None
    ));
    s.complete_removal(ticket(&removal), Completion::Accepted)
        .unwrap();
    assert!(matches!(
        s.stop_rx_block_ack(4, None),
        Err(BaError::NoSession)
    ));
}
