// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management recipient fixtures.
use super::*;

#[test]
fn protected_recipient_ack_response_and_txfree_unmap_retain_original_session() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let proof = observe(&mut driver, &model, &request(), 101, NOW);
    assert!(driver.station().block_ack_idle());
    assert!(model.response.lock().unwrap().receive_ba.is_empty());
    consume(&mut driver, &mut owner, proof, NOW + 1);
    assert!(driver.station().active_rx_block_ack(TID).is_none());
    rotate_refused(&mut driver, &mut owner, &session);
    progress(&mut driver, &mut owner, &state, NOW + 2);
    assert!(driver.station().active_rx_block_ack(TID).is_some());
    assert!(!model.response.lock().unwrap().receive_ba.is_empty());
    assert_eq!(
        driver
            .state()
            .controller
            .state()
            .data_tx
            .as_ref()
            .unwrap()
            .outstanding_tokens(),
        0
    );
    progress(&mut driver, &mut owner, &state, NOW + 3);
    rotate_refused(&mut driver, &mut owner, &session);
    assert_cipher_descriptor(&model, &session, false);
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        u16::from_le_bytes(sent[0][..2].try_into().unwrap()) & 0x40fc,
        0x40d0
    );
    assert_eq!(&sent[0][24..29], &[3, 1, 7, 0, 0]);
    assert!(driver.poll_released().unwrap().is_empty());
    driver.poll(NOW + 4, &Source, &mut Policy(true)).unwrap();
    let mut released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    let packet = released.pop().unwrap();
    assert!(Arc::ptr_eq(
        packet.context.management_session().unwrap(),
        &session
    ));
    assert_eq!(packet.context.key(), Some(session.pairwise_key()));
    let proof = observe(&mut driver, &model, &delete(true), 102, NOW + 5);
    consume(&mut driver, &mut owner, proof, NOW + 6);
    state.allowed.set(false);
    // Actual firmware disable needs no new TX permission and publishes no DELBA.
    driver.progress_block_ack_stop().unwrap();
    assert!(driver.station().block_ack_idle());
    assert!(model.response.lock().unwrap().receive_ba.is_empty());
    assert!(!driver.pending_block_ack());
    stop(&mut driver, &model);
    drop(driver);
    drop(owner);
    drop(state);
    drop(session);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    drop(packet);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn protected_recipient_delba_drains_published_positive_response_before_native_disable() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let proof = observe(&mut driver, &model, &request(), 101, NOW);
    consume(&mut driver, &mut owner, proof, NOW + 1);
    progress(&mut driver, &mut owner, &state, NOW + 2);
    progress(&mut driver, &mut owner, &state, NOW + 3);
    let proof = observe(&mut driver, &model, &delete(true), 102, NOW + 4);
    consume(&mut driver, &mut owner, proof, NOW + 5);
    assert!(driver.station().active_rx_block_ack(TID).is_none());
    let commands = model.response.lock().unwrap().client_commands.len();
    state.allowed.set(false);
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    assert!(driver.state().receive_ba[usize::from(TID)].is_some());
    assert_cipher_descriptor(&model, &session, false);
    finish_tx(&model);
    assert!(matches!(
        driver.progress_block_ack_stop(),
        Err(ClientError::NeedsDrain)
    ));
    driver.poll(NOW + 6, &Source, &mut Policy(true)).unwrap();
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
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands + 1
    );
    assert!(model.response.lock().unwrap().receive_ba.is_empty());
    assert!(driver.station().block_ack_idle());
    stop(&mut driver, &model);
}
