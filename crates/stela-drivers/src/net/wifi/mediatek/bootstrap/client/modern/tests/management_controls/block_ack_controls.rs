// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Original completed native RX, actual firmware commands and packet retirement.
//! These modeled OS permissions never qualify a physical or production OS peer.
use super::*;

const TID: u8 = 6;

fn request() -> Vec<u8> {
    let mut body = vec![3, 0, 7];
    body.extend_from_slice(&(3u16 | (u16::from(TID) << 2) | (8 << 6)).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(17u16 << 4).to_le_bytes());
    body
}
fn delete(initiator: bool) -> Vec<u8> {
    let mut body = vec![3, 2];
    body.extend_from_slice(&(u16::from(TID) << 12 | u16::from(initiator) << 11).to_le_bytes());
    body.extend_from_slice(&37u16.to_le_bytes());
    body
}
fn observe(driver: &mut Native, model: &Model, body: &[u8], pn: u64, now: u64) -> Received {
    incoming(model, &response(0x40d0, body), Some((1, 0, pn)), false);
    let mut events = driver.poll(now, &Source, &mut Policy(true)).unwrap();
    assert_eq!(events.len(), 1);
    let Event::ProtectedManagement(received) = events.pop().unwrap() else {
        panic!("actual authenticated native management envelope");
    };
    assert!(received.frame().header().protected());
    assert_eq!(received.body(), body);
    received
}
fn consume(driver: &mut Native, owner: &mut Owner, received: Received, now: u64) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: this modeled OS explicitly selects protected BA MLME for its
    // original authenticated envelope and subsequent guarded response/teardown.
    let mut retained = Some(received);
    unsafe { driver.receive_management_block_ack(owner, permit, &mut retained, now) }.unwrap();
    assert!(retained.is_none());
}
fn progress(driver: &mut Native, owner: &mut Owner, state: &Rc<AuthorityState>, now: u64) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: actual modeled requester and original OS policy cover all deferred effects.
    unsafe { driver.progress_block_ack(owner, permit, &GuardedSource(state.clone()), now) }
        .unwrap();
}
fn begin(driver: &mut Native, owner: &mut Owner, session: &Arc<Session>, now: u64) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: explicitly selected protected BA MLME in this modeled OS only.
    unsafe { driver.begin_management_block_ack(owner, permit, session, TID, 0, now) }.unwrap();
}
fn assert_cipher_descriptor(model: &Model, session: &Session, request: bool) {
    let queue = model.queues[&0xd4300].lock().unwrap();
    assert_ne!(queue.index, queue.head);
    let memory = model.memory.lock().unwrap();
    let pointer = crate::net::wifi::mediatek::bootstrap::client::tests::pointer;
    let descriptor = unsafe {
        core::slice::from_raw_parts(
            pointer(&memory, queue.base + u64::from(queue.index) * 16, 16),
            16,
        )
    };
    let address = u32::from_le_bytes(descriptor[..4].try_into().unwrap()) as u64;
    let actual = unsafe { core::slice::from_raw_parts(pointer(&memory, address, 64), 64) };
    let word1 = u32::from_le_bytes(actual[4..8].try_into().unwrap());
    let word3 = u32::from_le_bytes(actual[12..16].try_into().unwrap());
    assert_eq!(word3 & 2, 2); // actual MT_TXD3_PROTECT_FRAME
    assert_eq!(word1 & 0xfff, u32::from(session.pairwise_key().slot()));
    assert_eq!((word1 >> 21) & 15, if request { 2 } else { 0 });
}

fn rotate_refused(driver: &mut Native, owner: &mut Owner, session: &Session) {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: negative actual drain control; no old user may be released here.
    assert!(matches!(
        unsafe {
            driver.rotate_management_key_modern(
                owner,
                permit,
                session,
                5,
                &[0x66; 16],
                PacketNumber::new(200).unwrap(),
            )
        },
        Err(ClientError::NeedsDrain)
    ));
}

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
fn protected_originator_response_program_and_delba_wait_for_real_packet_drain() {
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
fn deferred_older_authenticated_addba_cannot_reverse_newer_delba() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let older = observe(&mut driver, &model, &request(), 101, NOW);
    let newer = observe(&mut driver, &model, &delete(true), 102, NOW + 1);
    consume(&mut driver, &mut owner, newer, NOW + 2);
    assert_eq!(driver.state().ba_management_pn.unwrap().value(), 102);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    let commands = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    assert!(matches!(
        {
            let mut retained = Some(older);
            let result = unsafe {
                driver.receive_management_block_ack(&mut owner, permit, &mut retained, NOW + 3)
            };
            assert!(retained.is_some());
            result
        },
        Err(ClientError::Key(mailbox::key::Error::Security(
            wifi::security::Error::Replay
        )))
    ));
    assert!(driver.station().block_ack_idle());
    assert!(!driver.pending_block_ack());
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    // Independent hardware-ingress replay must still refuse the exact PN.
    incoming(
        &model,
        &response(0x40d0, &request()),
        Some((1, 0, 102)),
        false,
    );
    assert!(driver.poll(NOW + 4, &Source, &mut Policy(true)).is_err());
    assert_eq!(driver.state().ba_management_pn.unwrap().value(), 102);
    stop(&mut driver, &model);
    drop(session);
    drop(owner);
    drop(state);
}

#[test]
fn protected_ba_consumption_and_begin_reacquire_current_policy_before_state_changes() {
    for begin_exchange in [false, true] {
        let (mut driver, model, mut owner, state) = fixture();
        let session = attach(&mut driver, &mut owner);
        let proof = observe(&mut driver, &model, &request(), 101, NOW);
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        let head = model.queues[&0xd4300].lock().unwrap().head;
        let log = model.bar.0.lock().unwrap().log.len();
        state.allowed.set(false);
        let mut retained = Some(proof);
        let result = if begin_exchange {
            unsafe {
                driver.begin_management_block_ack(&mut owner, permit, &session, TID, 0, NOW + 1)
            }
        } else {
            unsafe {
                driver.receive_management_block_ack(&mut owner, permit, &mut retained, NOW + 1)
            }
        };
        assert!(result.is_err());
        assert!(retained.is_some());
        assert!(driver.station().block_ack_idle());
        assert!(driver.state().ba_management.is_none());
        assert!(driver.state().ba_management_pn.is_none());
        assert!(!driver.pending_block_ack());
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
        assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
        stop(&mut driver, &model);
    }
}

#[test]
fn rotated_or_disconnected_original_ba_observation_cannot_inherit_new_admission() {
    for disconnect in [false, true] {
        let (mut driver, model, mut owner, state) = fixture();
        let first = attach(&mut driver, &mut owner);
        let proof = observe(&mut driver, &model, &request(), 101, NOW);
        let mut permit = Some(admit(&mut owner, &driver, AssociationUse::Management));
        if disconnect {
            driver.disconnect().unwrap();
        } else {
            unsafe {
                driver.rotate_management_key_modern(
                    &mut owner,
                    permit.take().unwrap(),
                    &first,
                    5,
                    &[0x66; 16],
                    PacketNumber::new(200).unwrap(),
                )
            }
            .unwrap();
            // New admission for the unchanged context cannot retag old RX.
            permit = Some(admit(&mut owner, &driver, AssociationUse::Management));
        }
        let commands = model.response.lock().unwrap().client_commands.len();
        let log = model.bar.0.lock().unwrap().log.len();
        let mut retained = Some(proof);
        assert!(
            unsafe {
                driver.receive_management_block_ack(
                    &mut owner,
                    permit.unwrap(),
                    &mut retained,
                    NOW + 1,
                )
            }
            .is_err()
        );
        assert!(retained.is_some());
        assert!(driver.station().active_rx_block_ack(TID).is_none());
        assert!(!driver.pending_block_ack());
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            commands
        );
        assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
        stop(&mut driver, &model);
        drop(state);
    }
}

#[test]
fn uncertain_protected_ba_command_and_packet_unmap_keep_complete_original_owners() {
    for command_failure in [false, true] {
        let (mut driver, model, mut owner, state) = fixture();
        let session = attach(&mut driver, &mut owner);
        let proof = observe(&mut driver, &model, &request(), 101, NOW);
        consume(&mut driver, &mut owner, proof, NOW + 1);
        if command_failure {
            model.response.lock().unwrap().status = 9;
            let permit = admit(&mut owner, &driver, AssociationUse::Management);
            assert!(
                unsafe {
                    driver.progress_block_ack(
                        &mut owner,
                        permit,
                        &GuardedSource(state.clone()),
                        NOW + 2,
                    )
                }
                .is_err()
            );
        } else {
            progress(&mut driver, &mut owner, &state, NOW + 2);
            progress(&mut driver, &mut owner, &state, NOW + 3);
            finish_tx(&model);
            driver.poll(NOW + 4, &Source, &mut Policy(true)).unwrap();
            model.memory.lock().unwrap().fail_unmap = true;
            assert!(driver.poll_released().is_err());
        }
        assert!(Arc::ptr_eq(
            driver.state().ba_management.as_ref().unwrap(),
            &session
        ));
        drop(driver);
        drop(owner);
        drop(state);
        drop(session);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}

#[test]
fn protected_ba_deferral_is_bounded_and_refuses_before_canonical_or_dma_changes() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    for step in 0..32 {
        let proof = observe(&mut driver, &model, &request(), 101 + step, NOW + 2 * step);
        consume(&mut driver, &mut owner, proof, NOW + 2 * step + 1);
    }
    assert_eq!(driver.state().ba_actions.len(), 32);
    let proof = observe(&mut driver, &model, &request(), 133, NOW + 64);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let commands = model.response.lock().unwrap().client_commands.len();
    let maps = model.memory.lock().unwrap().mappings.len();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    let mut retained = Some(proof);
    let original_frame = retained.as_ref().unwrap().frame().bytes().to_vec();
    assert!(matches!(
        unsafe { driver.receive_management_block_ack(&mut owner, permit, &mut retained, NOW + 65) },
        Err(ClientError::Busy)
    ));
    assert_eq!(retained.as_ref().unwrap().frame().bytes(), original_frame);
    assert!(Arc::ptr_eq(retained.as_ref().unwrap().session(), &session));
    assert_eq!(driver.state().ba_actions.len(), 32);
    assert_eq!(driver.state().ba_management_pn.unwrap().value(), 132);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(model.memory.lock().unwrap().mappings.len(), maps);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert_eq!(state.allocations.get(), 0);
    progress(&mut driver, &mut owner, &state, NOW + 66);
    progress(&mut driver, &mut owner, &state, NOW + 67);
    assert_cipher_descriptor(&model, &session, false);
    finish_tx(&model);
    driver.poll(NOW + 68, &Source, &mut Policy(true)).unwrap();
    driver.poll_released().unwrap();
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    unsafe { driver.receive_management_block_ack(&mut owner, permit, &mut retained, NOW + 69) }
        .unwrap();
    assert!(retained.is_none());
    assert_eq!(driver.state().ba_management_pn.unwrap().value(), 133);
    stop(&mut driver, &model);
    drop(session);
}

#[test]
fn genuine_foreign_session_and_group_bip_observations_cannot_enter_pairwise_ba() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let (mut foreign, foreign_model, mut foreign_owner, foreign_state) = fixture();
    let foreign_session = attach(&mut foreign, &mut foreign_owner);
    let proof = observe(&mut foreign, &foreign_model, &request(), 101, NOW);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert!(matches!(
        {
            let mut retained = Some(proof);
            let result = unsafe {
                driver.receive_management_block_ack(&mut owner, permit, &mut retained, NOW)
            };
            assert!(retained.is_some());
            result
        },
        Err(ClientError::Station(station::Error::Stale))
    ));
    // Complete unchanged independent BIP vector: a real authenticated group
    // envelope is still not a pairwise Block Ack action or permission.
    let bytes = vec![
        0xc0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 2, 6, 7, 8, 9, 10, 2, 6, 7, 8, 9, 10, 0, 0, 7,
        0, 76, 16, 4, 0, 101, 0, 0, 0, 0, 0, 0xc4, 0x80, 0xa2, 0x3a, 0x2c, 0x44, 0x77, 0x70,
    ];
    let mut raw = incoming_bytes(&bytes, None, false);
    raw[4] = 1;
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    let mut events = driver.poll(NOW, &Source, &mut Policy(true)).unwrap();
    let Event::ProtectedManagement(proof) = events.pop().unwrap() else {
        panic!("actual BIP proof")
    };
    assert!(proof.group());
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    let log = model.bar.0.lock().unwrap().log.len();
    assert!(matches!(
        {
            let mut retained = Some(proof);
            let result = unsafe {
                driver.receive_management_block_ack(&mut owner, permit, &mut retained, NOW)
            };
            assert!(retained.is_some());
            result
        },
        Err(ClientError::Unsupported)
    ));
    assert!(driver.station().block_ack_idle());
    assert!(driver.state().ba_management.is_none());
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    stop(&mut driver, &model);
    stop(&mut foreign, &foreign_model);
    drop(session);
    drop(foreign_session);
    drop(state);
    drop(foreign_state);
}

#[test]
fn authenticated_malformed_and_non_ba_bodies_remain_original_observations() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    for (step, body) in [
        vec![3, 0],
        vec![3, 1, 7, 0, 0],
        vec![3, 2, 0, 0],
        vec![3, 3],
        vec![8, 0, 1, 2],
    ]
    .into_iter()
    .enumerate()
    {
        let proof = observe(
            &mut driver,
            &model,
            &body,
            101 + step as u64,
            NOW + step as u64,
        );
        let mut retained = Some(proof);
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        let commands = model.response.lock().unwrap().client_commands.len();
        let log = model.bar.0.lock().unwrap().log.len();
        assert!(
            unsafe {
                driver.receive_management_block_ack(
                    &mut owner,
                    permit,
                    &mut retained,
                    NOW + step as u64,
                )
            }
            .is_err()
        );
        assert_eq!(retained.as_ref().unwrap().body(), body);
        assert!(driver.state().ba_management_pn.is_none());
        assert!(driver.station().block_ack_idle());
        assert!(!driver.pending_block_ack());
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            commands
        );
        assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    }
    stop(&mut driver, &model);
    drop(session);
    drop(state);
}

#[test]
fn policy_revocation_after_queueing_retains_exact_protected_action_without_publication() {
    for before_command in [false, true] {
        let (mut driver, model, mut owner, state) = fixture();
        let session = attach(&mut driver, &mut owner);
        let proof = observe(&mut driver, &model, &request(), 101, NOW);
        consume(&mut driver, &mut owner, proof, NOW + 1);
        if !before_command {
            progress(&mut driver, &mut owner, &state, NOW + 2);
        }
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        let pending = driver.state().ba_actions.len();
        let commands = model.response.lock().unwrap().client_commands.len();
        let head = model.queues[&0xd4300].lock().unwrap().head;
        let maps = model.memory.lock().unwrap().mappings.len();
        state.allowed.set(false);
        assert!(
            unsafe {
                driver.progress_block_ack(
                    &mut owner,
                    permit,
                    &GuardedSource(state.clone()),
                    NOW + 3,
                )
            }
            .is_err()
        );
        assert_eq!(driver.state().ba_actions.len(), pending);
        assert!(Arc::ptr_eq(
            driver.state().ba_management.as_ref().unwrap(),
            &session
        ));
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            commands
        );
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
        assert_eq!(model.memory.lock().unwrap().mappings.len(), maps);
        assert_eq!(state.allocations.get(), 0);
        stop(&mut driver, &model);
    }
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

#[test]
fn real_native_negotiation_timeout_disables_before_guarded_protected_local_delba() {
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
