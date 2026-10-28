// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management retention fixtures.
use super::*;

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
