// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management provenance fixtures.
use super::*;

#[test]
fn older_addba_cannot_reverse_delba() {
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
            let result =
            // SAFETY: The older authenticated envelope remains owned by this live
            // session. Its stale management packet number must be rejected before
            // canonical BA state or DMA ownership changes.
            unsafe {
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
fn foreign_and_group_observation_preflight() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let (mut foreign, foreign_model, mut foreign_owner, foreign_state) = fixture();
    let foreign_session = attach(&mut foreign, &mut foreign_owner);
    let proof = observe(&mut foreign, &foreign_model, &request(), 101, NOW);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert!(matches!(
        {
            let mut retained = Some(proof);
            let result =
            // SAFETY: Both independent model peers and their backing stay live. This
            // foreign session is mismatched; requester/session
            // validation must refuse it before consuming the original envelope.
            unsafe {
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
            let result =
            // SAFETY: The current authenticated group envelope remains owned, but it
            // is not a pairwise BA action. Guarded classification must reject it
            // before canonical state or queue publication changes.
            unsafe {
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
fn malformed_actions_preserve_observations() {
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
            // SAFETY: Each authenticated envelope has live backing under the current
            // session. Only its BA body/classification is invalid; refusal must
            // preserve the owned observation and avoid canonical or DMA effects.
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
