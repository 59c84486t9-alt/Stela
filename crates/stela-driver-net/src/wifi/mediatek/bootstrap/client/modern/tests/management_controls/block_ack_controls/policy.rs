// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management policy fixtures.
use super::*;

#[test]
fn guard_revalidation_before_block_ack_changes() {
    if crate::test_process::isolate_model() {
        return;
    }
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
            // SAFETY: The session and native backing remain held, but policy was
            // revoked after preflight. Fresh guard acquisition must deny initiation
            // before modifying BA state or publishing a packet.
            unsafe {
                driver.begin_management_block_ack(&mut owner, permit, &session, TID, 0, NOW + 1)
            }
        } else {
            // SAFETY: The authenticated envelope remains in kept storage while
            // its current OS policy is revoked. Guard checks must deny consumption
            // before taking that envelope or changing canonical BA state.
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
fn stale_block_ack_observation() {
    if crate::test_process::isolate_model() {
        return;
    }
    for disconnect in [false, true] {
        let (mut driver, model, mut owner, state) = fixture();
        let first = attach(&mut driver, &mut owner);
        let proof = observe(&mut driver, &model, &request(), 101, NOW);
        let mut permit = Some(admit(&mut owner, &driver, AssociationUse::Management));
        if disconnect {
            driver.disconnect().unwrap();
        } else {
            // SAFETY: The old RX envelope is held but not being consumed, and no
            // asynchronous model key user exists. Current leases serialize rotation
            // and keep the original requester/backing through its acknowledgement.
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
            // SAFETY: The kept envelope belongs to a retired key namespace or
            // removed context. Fresh admission must reject it without retagging or
            // consuming its original owned frame.
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
fn queued_action_policy_revocation() {
    if crate::test_process::isolate_model() {
        return;
    }
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
            // SAFETY: The queued BA action and original session keep their native
            // resources. Revoked policy must be rechecked before the next
            // command/allocation, without releasing or rewriting the pending action.
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
