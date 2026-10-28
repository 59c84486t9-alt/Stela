// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management dma lifetime fixtures.
use super::*;

#[test]
fn actual_modern_management_tx_guards_allocation_and_retains_descriptor_free_unmap_owner() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let receipt = unsafe {
        driver.transmit_management_modern(
            &mut owner,
            permit,
            &session,
            Transmit::SaQueryResponse([0xa5, 0x5a]),
            &GuardedSource(state.clone()),
        )
    }
    .unwrap();
    assert_eq!(state.allocations.get(), 2);
    assert_eq!(finish_tx(&model)[0][24..], [8, 1, 0xa5, 0x5a]);
    assert!(driver.poll_released().unwrap().is_empty());
    driver.poll(NOW, &Source, &mut Policy(true)).unwrap();
    let mut released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    let packet = released.pop().unwrap();
    assert_eq!(packet.receipt, receipt);
    assert!(Arc::ptr_eq(
        packet.context.management_session().unwrap(),
        &session
    ));
    assert!(core::ptr::eq(
        packet.context.association_context().unwrap(),
        session.association_context().unwrap()
    ));
    assert_eq!(packet.context.key(), Some(session.pairwise_key()));
    assert_eq!(driver.phase(), ClientPhase::Associated);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    state.allowed.set(false);
    assert!(
        unsafe {
            driver.transmit_management_modern(
                &mut owner,
                permit,
                &session,
                Transmit::Deauthenticate(7),
                &GuardedSource(state.clone()),
            )
        }
        .is_err()
    );
    assert_eq!(state.allocations.get(), 2);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    drop(owner);
    drop(state);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    drop(packet);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn uncertain_modern_initial_key_batch_and_failed_tx_unmap_retain_complete_owners() {
    for key_failure in [false, true] {
        let (mut driver, model, mut owner, state) = fixture();
        if key_failure {
            let permit = admit(&mut owner, &driver, AssociationUse::Management);
            let epoch = driver.station().association_epoch().unwrap();
            model.response.lock().unwrap().status = 9;
            assert!(
                unsafe {
                    driver.install_management_key_modern(
                        &mut owner,
                        permit,
                        epoch,
                        4,
                        &[0x55; 16],
                        PacketNumber::new(100).unwrap(),
                    )
                }
                .is_err()
            );
            assert_eq!(driver.phase(), ClientPhase::Quarantined);
            assert!(driver.state().management.is_none());
        } else {
            let session = attach(&mut driver, &mut owner);
            let proof = received(&mut driver, &model, 9);
            let permit = admit(&mut owner, &driver, AssociationUse::Management);
            unsafe {
                driver.transmit_management_modern(
                    &mut owner,
                    permit,
                    &session,
                    Transmit::Disassociate(8),
                    &GuardedSource(state.clone()),
                )
            }
            .unwrap();
            finish_tx(&model);
            driver.poll(NOW, &Source, &mut Policy(true)).unwrap();
            model.memory.lock().unwrap().fail_unmap = true;
            assert!(driver.poll_released().is_err());
            let permit = admit(&mut owner, &driver, AssociationUse::Management);
            assert!(
                unsafe {
                    driver.with_management_modern::<_, _, ()>(
                        &mut owner,
                        permit,
                        proof,
                        |_, _, _| panic!("poisoned DMA"),
                    )
                }
                .is_err()
            );
        }
        drop(driver);
        drop(owner);
        drop(state);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}
