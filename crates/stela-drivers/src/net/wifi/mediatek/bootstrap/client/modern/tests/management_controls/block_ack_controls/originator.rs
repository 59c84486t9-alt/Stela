// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management originator fixtures.
use super::*;

#[test]
fn originator_delba_waits_for_packet_drain() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    begin(&mut driver, &mut owner, &session, NOW);
    progress(&mut driver, &mut owner, &state, NOW + 1);
    let dialog = match driver.state().ba_actions.front().unwrap() {
        station::ba::Action::Tx(station::ba::tx::Action::Transmit { session, .. }) => {
            session.dialog()
        }
        _ => panic!("real prepared ADDBA request"),
    };
    progress(&mut driver, &mut owner, &state, NOW + 2);
    let mut body = vec![3, 1, dialog, 0, 0];
    body.extend_from_slice(&(3u16 | u16::from(TID) << 2 | 8 << 6).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    let proof = observe(&mut driver, &model, &body, 101, NOW + 3);
    consume(&mut driver, &mut owner, proof, NOW + 4);
    progress(&mut driver, &mut owner, &state, NOW + 5);
    assert!(driver.station().active_tx_block_ack(TID).is_some());
    assert!(!model.response.lock().unwrap().transmit_ba.is_empty());
    let proof = observe(&mut driver, &model, &delete(false), 102, NOW + 6);
    consume(&mut driver, &mut owner, proof, NOW + 7);
    state.allowed.set(false);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    assert_cipher_descriptor(&model, &session, true);
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0][1] & 0x40, 0x40);
    assert_eq!(&sent[0][24..27], &[3, 0, dialog]);
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    driver.poll(NOW + 8, &Source, &mut Policy(true)).unwrap();
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert!(Arc::ptr_eq(
        released[0].context.management_session().unwrap(),
        &session
    ));
    driver.progress_block_ack_stop().unwrap();
    assert!(driver.station().block_ack_idle());
    assert!(model.response.lock().unwrap().transmit_ba.is_empty());
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    stop(&mut driver, &model);
}

#[test]
fn timeout_disables_before_guarded_delba() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let epoch = driver.station().association_epoch().unwrap();
    driver.authorize_port(epoch).unwrap();
    begin(&mut driver, &mut owner, &session, NOW);
    progress(&mut driver, &mut owner, &state, NOW + 1);
    progress(&mut driver, &mut owner, &state, NOW + 2);
    let deadline = driver.next_transmit_deadline().unwrap();
    assert!(deadline > NOW + 2);
    driver.poll_block_ack_timers(deadline).unwrap();
    assert!(driver.next_transmit_deadline().is_none());
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    assert_cipher_descriptor(&model, &session, true);
    finish_tx(&model);
    driver
        .poll(deadline + 1, &Source, &mut Policy(true))
        .unwrap();
    let request = driver.poll_released().unwrap();
    assert_eq!(request.len(), 1);
    assert!(Arc::ptr_eq(
        request[0].context.management_session().unwrap(),
        &session
    ));
    let commands = model.response.lock().unwrap().client_commands.len();
    driver.progress_block_ack_stop().unwrap();
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands + 1
    );
    assert!(driver.pending_block_ack());
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    state.allowed.set(false);
    assert!(
        // SAFETY: The protected DELBA action and its session remain retained after
        // firmware disable. Revoked current policy must deny its publication before
        // advancing the TX queue.
        unsafe {
            driver.progress_block_ack(
                &mut owner,
                permit,
                &GuardedSource(state.clone()),
                deadline + 2,
            )
        }
        .is_err()
    );
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    state.allowed.set(true);
    progress(&mut driver, &mut owner, &state, deadline + 3);
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    assert!(Native::tx_ba_blocks_data(driver.state(), TID));
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let pending = driver.state().ba_actions.len();
    assert!(
        // SAFETY: The current session remains owned, but its protected DELBA packet
        // has not drained. Initiation must refuse that pending owner before changing
        // canonical state or queueing another exchange.
        unsafe {
            driver.begin_management_block_ack(&mut owner, permit, &session, TID, 0, deadline + 3)
        }
        .is_err()
    );
    assert!(driver.station().block_ack_idle());
    assert_eq!(driver.state().ba_actions.len(), pending);
    let permit = admit(&mut owner, &driver, AssociationUse::Data);
    let allocations = state.allocations.get();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(matches!(
        // SAFETY: The data frame is borrowed only for this call, and all current
        // key/native owners remain live. The pending DELBA must block this TID before
        // allocation or publication can bypass its drain.
        unsafe {
            driver.transmit_modern(
                &mut owner,
                permit,
                epoch,
                &eth(0x0800),
                TxClass::Data,
                Some(TID),
                &GuardedSource(state.clone()),
                &mut Policy(true),
            )
        },
        Err(ClientError::Busy)
    ));
    assert_eq!(state.allocations.get(), allocations);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert_cipher_descriptor(&model, &session, false);
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0][1] & 0x40, 0x40);
    assert_eq!(&sent[0][24..26], &[3, 2]);
    driver
        .poll(deadline + 4, &Source, &mut Policy(true))
        .unwrap();
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    let delba = driver.poll_released().unwrap();
    assert_eq!(delba.len(), 1);
    assert!(Arc::ptr_eq(
        delba[0].context.management_session().unwrap(),
        &session
    ));
    driver.progress_block_ack_stop().unwrap();
    assert!(driver.state().transmit_ba[usize::from(TID)].is_none());
    assert!(driver.station().block_ack_idle());
    assert!(!driver.pending_block_ack());
    assert!(!Native::tx_ba_blocks_data(driver.state(), TID));
    let permit = admit(&mut owner, &driver, AssociationUse::Data);
    // SAFETY: The prior DELBA command and packet completed and were released before
    // this call. The current session, key and native owners remain retained under
    // fresh data guards while the new payload is queued.
    unsafe {
        driver.transmit_modern(
            &mut owner,
            permit,
            epoch,
            &eth(0x0800),
            TxClass::Data,
            Some(TID),
            &GuardedSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    assert_eq!(finish_tx(&model).len(), 1);
    driver
        .poll(deadline + 5, &Source, &mut Policy(true))
        .unwrap();
    assert_eq!(driver.poll_released().unwrap().len(), 1);
    begin(&mut driver, &mut owner, &session, deadline + 5);
    assert!(!driver.station().block_ack_idle());
    stop(&mut driver, &model);
}
