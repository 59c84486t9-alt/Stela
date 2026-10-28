// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management policy fixtures.
use super::*;

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
