// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management dma lifetime fixtures.
use super::*;

#[test]
fn management_tx_retains_packet_owner() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let receipt =
    // SAFETY: The current session, native context and key owners remain retained.
    // Hardware/OS leases cover source allocation and queue publication, and the
    // submitted packet retains its descriptor and payload ownership.
    unsafe {
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
        // SAFETY: The current session and backing stay live, but OS permission was
        // revoked after preflight. Fresh guard acquisition must fail before
        // allocation or a new queue entry.
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
fn key_and_unmap_failures_retain_owners() {
    for key_failure in [false, true] {
        let (mut driver, model, mut owner, state) = fixture();
        if key_failure {
            let permit = admit(&mut owner, &driver, AssociationUse::Management);
            let epoch = driver.station().association_epoch().unwrap();
            model.response.lock().unwrap().status = 9;
            assert!(
                // SAFETY: The fixture has no prior management-key users and retains
                // its original native backing. A failed synchronous key
                // acknowledgement must quarantine ownership rather than release
                // uncertain DMA.
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
            // SAFETY: This current session and requester own the queued management
            // packet. Fresh leases cover publication; all descriptor, payload and key
            // owners remain retained through the later unmap-failure injection.
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
                // SAFETY: The RX envelope remains owned, but the original DMA owner
                // is now poisoned by failed unmap. Validation must reject consumption
                // before invoking the callback or releasing retained resources.
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
