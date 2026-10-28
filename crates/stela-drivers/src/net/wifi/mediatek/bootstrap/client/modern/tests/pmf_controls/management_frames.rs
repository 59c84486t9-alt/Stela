// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek PMF management frames fixtures.
use super::*;

#[test]
fn actual_prekey_eapol_has_distinct_guarded_transport_and_no_robust_fallback() {
    let (mut driver, model, mut owner, state, protection) = configured();
    let epoch = driver.station().association_epoch().unwrap();
    let admission = permit(&mut owner, &driver, AssociationUse::Authentication);
    let mut frame = eth(0x888e);
    frame[..6].copy_from_slice(&AP.0);
    // SAFETY: only this genuine model OS's EAPOL control-port transport is granted.
    unsafe {
        driver.transmit_modern(
            &mut owner,
            admission,
            epoch,
            &frame,
            TxClass::ControlPortPlaintext,
            None,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][24..32], &[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    assert_eq!(
        u16::from_le_bytes(sent[0][..2].try_into().unwrap()) & 0x4000,
        0
    );
    poll(&mut driver, &mut owner, &state, 106).unwrap();
    driver.poll_released().unwrap();
    let eapol = response(0x0208, &[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 1, 2, 3]);
    // A plaintext data descriptor still needs the actual configured peer WCID.
    // Retain the original WCID0 input as a hostile profile mismatch first.
    let mut raw = incoming_bytes(&eapol, None, false);
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    assert!(matches!(
        poll(&mut driver, &mut owner, &state, 107),
        Err(ClientError::WrongProfile)
    ));
    assert!(!protection.authenticated.get());
    assert!(!driver.station().port_open(None, None));
    let peer = driver.state().profile.unwrap().wcid;
    let original = raw.clone();
    let descriptor = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    raw[4..8].copy_from_slice(&((descriptor & !0xfff) | u32::from(peer)).to_le_bytes());
    assert_eq!(&raw[..4], &original[..4]);
    assert_eq!(&raw[8..], &original[8..]);
    assert_eq!(
        u32::from_le_bytes(raw[4..8].try_into().unwrap()) & !0xfff,
        descriptor & !0xfff
    );
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    let events = poll(&mut driver, &mut owner, &state, 107).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Ingress(station::data::Ingress::ControlPort { .. })
    )));
    assert!(!protection.authenticated.get());
    assert!(
        owner
            .admit_association(
                driver.station(),
                driver.modern_context().unwrap().clone(),
                AssociationUse::Data
            )
            .is_err()
    );
    assert!(driver.authorize_port(epoch).is_err());
    assert!(driver.begin_tx_block_ack(6, 0, 108).is_err());
    assert!(driver.poll(108, &Source, &mut Policy(true)).is_err());
    // ieee80211_drop_unencrypted_mgmt drops a robust action before keys,
    // but permits a departure during the 4-way handshake.
    let commands = model.response.lock().unwrap().client_commands.len();
    incoming(&model, &response(0xd0, &[3, 2, 0, 0, 37, 0]), None, false);
    assert!(
        poll(&mut driver, &mut owner, &state, 108)
            .unwrap()
            .is_empty()
    );
    assert_eq!(driver.station().phase(), station::Phase::Associated);
    assert!(driver.station().block_ack_idle());
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    incoming(&model, &response(0xc0, &[7, 0]), None, false);
    poll(&mut driver, &mut owner, &state, 109).unwrap();
    assert_eq!(driver.station().phase(), station::Phase::Disconnecting);
}

#[test]
fn actual_pmf_protected_block_ack_uses_current_session_and_real_firmware_ack() {
    let (mut driver, model, mut owner, state, protection) = configured();
    protection.authenticated.set(true);
    let session = attach(&mut driver, &mut owner);
    assert!(driver.begin_tx_block_ack(6, 0, frontend_tick(110)).is_err());
    let mut request = vec![3, 0, 7];
    request.extend_from_slice(&(3u16 | (6 << 2) | (8 << 6)).to_le_bytes());
    request.extend_from_slice(&0u16.to_le_bytes());
    request.extend_from_slice(&(17u16 << 4).to_le_bytes());
    incoming(
        &model,
        &response(0x40d0, &request),
        Some((1, 0, 101)),
        false,
    );
    let mut events = poll(&mut driver, &mut owner, &state, frontend_tick(111)).unwrap();
    let Event::ProtectedManagement(original) = events.pop().unwrap() else {
        panic!("protected BA observation")
    };
    let mut received = Some(original);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    unsafe {
        driver.receive_management_block_ack(
            &mut owner,
            admission,
            &mut received,
            frontend_tick(112),
        )
    }
    .unwrap();
    assert!(received.is_none());
    assert!(driver.station().active_rx_block_ack(6).is_none());
    for now in [frontend_tick(113), frontend_tick(114)] {
        let admission = permit(&mut owner, &driver, AssociationUse::Management);
        unsafe { driver.progress_block_ack(&mut owner, admission, &PmfSource(state.clone()), now) }
            .unwrap();
    }
    assert!(driver.station().active_rx_block_ack(6).is_some());
    assert!(
        model
            .response
            .lock()
            .unwrap()
            .receive_ba
            .contains_key(&(1, 6))
    );
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        u16::from_le_bytes(sent[0][..2].try_into().unwrap()) & 0x40fc,
        0x40d0
    );
    assert_eq!(&sent[0][24..29], &[3, 1, 7, 0, 0]);
    poll(&mut driver, &mut owner, &state, frontend_tick(115)).unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert!(Arc::ptr_eq(
        released[0].context.management_session().unwrap(),
        &session
    ));
}
