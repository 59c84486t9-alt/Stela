// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Actual source-modeled native peers. These providers authorize only the retained
// simulated requester, never a physical device or a real OS management service.
use super::*;
use crate::net::wifi::mediatek::bootstrap::client::management::{Received, Session, Transmit};
use crate::net::wifi::{mediatek::mailbox, security::PacketNumber};

type Native = Client<Bar, Q, NativeGuard>;
const NOW: u64 = 1_000_200;

fn fixture() -> (Native, Model, Owner, Rc<AuthorityState>) {
    let (mut driver, model, _) = awaiting();
    let (mut owner, state) = authority(&driver, &model);
    let permit = admit(&mut owner, &driver, AssociationUse::Configure);
    // SAFETY: only this exact modeled requester and its actually retained guards.
    unsafe { driver.configure_modern(&mut owner, permit, 105) }.unwrap();
    for (pairwise, index, material) in [(true, 0, 1), (false, 2, 0x44)] {
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        // SAFETY: same actual modeled requester, source policy and key exchange.
        unsafe {
            driver.install_key_modern(
                &mut owner,
                permit,
                pairwise,
                index,
                &[material; 16],
                ReplaySeed::ZERO,
            )
        }
        .unwrap();
    }
    (driver, model, owner, state)
}
fn attach(driver: &mut Native, owner: &mut Owner) -> Arc<Session> {
    let permit = admit(owner, driver, AssociationUse::Management);
    let epoch = driver.station().association_epoch().unwrap();
    // SAFETY: modeled native queues, BA owners, actual RX/IRQ and external users
    // are drained; these bytes represent this model OS's authenticated exchange.
    unsafe {
        driver.install_management_key_modern(
            owner,
            permit,
            epoch,
            4,
            &[0x55; 16],
            PacketNumber::new(100).unwrap(),
        )
    }
    .unwrap()
}
fn received(driver: &mut Native, model: &Model, pn: u64) -> Received {
    incoming(model, &response(0x40c0, &[7, 0]), Some((1, 0, pn)), false);
    let mut events = driver.poll(NOW, &Source, &mut Policy(true)).unwrap();
    assert_eq!(events.len(), 1);
    match events.pop().unwrap() {
        Event::ProtectedManagement(received) => received,
        _ => panic!("actual authenticated RX remains an OS observation"),
    }
}
fn stop(driver: &mut Native, model: &Model) {
    if driver.phase() == ClientPhase::Associated {
        driver.disconnect().unwrap();
    }
    // SAFETY: actual model removal ACK and independent old RX/IRQ/work drain;
    // retained observations are inert and every consuming use revalidates them.
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    driver.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: whole actual modeled controller/DMA/IRQ quiesced independently.
    unsafe { driver.stop_after_quiesce() }.unwrap();
}

#[test]
fn modern_management_initial_batch_uses_actual_context_guards_and_retry_ipn() {
    let (mut driver, model, mut owner, state) = fixture();
    let before = model.response.lock().unwrap().client_commands.len();
    let session = attach(&mut driver, &mut owner);
    assert!(core::ptr::eq(
        session.association_context().unwrap(),
        driver.modern_context().unwrap().as_ref()
    ));
    assert_eq!(session.management_key().gtk(), session.group_key());
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 1
    );
    assert!(
        state
            .windows
            .borrow()
            .iter()
            .any(|&(a, b)| a == before && b == before + 1)
    );
    assert_eq!(
        model.response.lock().unwrap().keys[&19],
        [vec![0x44; 16], vec![0x55; 16]].concat()
    );
    assert!(!driver.station().port_open(
        Some(driver.state().ptk.as_ref().unwrap().slot()),
        Some(driver.state().gtk.as_ref().unwrap().slot())
    ));
    let proof = received(&mut driver, &model, 9);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert_eq!(
        unsafe {
            driver.with_management_modern(&mut owner, permit, proof, |_, body, pn| {
                assert!(state.hardware.get() && state.os.get());
                assert_eq!(body, [7, 0]);
                pn.value()
            })
        }
        .unwrap(),
        9
    );
    let again = attach(&mut driver, &mut owner);
    assert!(Arc::ptr_eq(&again, &session));
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 1
    );
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 9)), false);
    assert!(matches!(
        driver.poll(NOW + 1, &Source, &mut Policy(true)),
        Err(ClientError::Key(mailbox::key::Error::Security(
            wifi::security::Error::Replay
        )))
    ));
    stop(&mut driver, &model);
    drop(driver);
    drop(again);
    drop(session);
    drop(owner);
    drop(state);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn old_and_fresh_revoked_management_admission_never_publish_initial_key_batch() {
    let (mut driver, model, mut owner, state) = fixture();
    let epoch = driver.station().association_epoch().unwrap();
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let before = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    state.allowed.set(false);
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
    assert!(
        owner
            .admit_association(
                driver.station(),
                driver.modern_context().unwrap().clone(),
                AssociationUse::Management
            )
            .is_err()
    );
    state.allowed.set(true);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    state.revision.set(state.revision.get() + 1);
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
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    assert!(driver.state().management.is_none());
    let session = attach(&mut driver, &mut owner);
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    drop(owner);
    drop(state);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn actual_pending_canonical_ba_and_native_aggregation_refuse_initial_igtk_batch() {
    for mode in 0..3 {
        let (mut driver, model, mut owner, state) = fixture();
        if mode != 0 {
            let parameters: u16 = 2 | (6 << 2) | (8 << 6);
            let mut body = vec![3, 0, 7];
            body.extend_from_slice(&parameters.to_le_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&(17u16 << 4).to_le_bytes());
            incoming(&model, &response(0xd0, &body), None, false);
            driver.poll(NOW, &Source, &mut Policy(true)).unwrap();
            assert!(driver.station().active_rx_block_ack(6).is_none());
            assert!(driver.state().receive_ba[6].is_none());
        } else {
            driver.begin_tx_block_ack(6, 0, NOW).unwrap();
            assert!(driver.state().transmit_ba[6].is_some());
        }
        if mode == 2 {
            // Complete actual RX BA firmware install, publish its ADDBA response,
            // and retire both source TX receipts before buffering real QoS RX.
            for now in [NOW + 1, NOW + 2] {
                let permit = admit(&mut owner, &driver, AssociationUse::Management);
                unsafe {
                    driver.progress_block_ack(
                        &mut owner,
                        permit,
                        &GuardedSource(state.clone()),
                        now,
                    )
                }
                .unwrap();
            }
            assert_eq!(finish_tx(&model).len(), 1);
            driver.poll(NOW + 3, &Source, &mut Policy(true)).unwrap();
            assert_eq!(driver.poll_released().unwrap().len(), 1);
            driver
                .authorize_port(driver.station().association_epoch().unwrap())
                .unwrap();
            incoming(&model, &qos_packet(17), Some((1, 0, 1)), false);
            assert_eq!(
                driver
                    .poll(NOW + 4, &Source, &mut Policy(true))
                    .unwrap()
                    .len(),
                1
            );
            incoming(&model, &qos_packet(19), Some((1, 0, 3)), false);
            assert!(
                driver
                    .poll(NOW + 5, &Source, &mut Policy(true))
                    .unwrap()
                    .is_empty()
            );
            assert!(driver.state().receive_ba[6].is_some());
            assert!(driver.next_receive_deadline().is_some());
            assert!(!driver.pending_block_ack());
        }
        assert!(!driver.station().block_ack_idle());
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        let epoch = driver.station().association_epoch().unwrap();
        let before = model.response.lock().unwrap().client_commands.len();
        assert!(matches!(
            unsafe {
                driver.install_management_key_modern(
                    &mut owner,
                    permit,
                    epoch,
                    4,
                    &[0x55; 16],
                    PacketNumber::new(100).unwrap(),
                )
            },
            Err(ClientError::NeedsDrain)
        ));
        assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
        assert!(driver.state().management.is_none());
        // Whole association removal is the actual completion/drain boundary;
        // no test silently clears pending records to make the batch succeed.
        stop(&mut driver, &model);
        drop(driver);
        drop(owner);
        drop(state);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    }
}

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
fn deferred_modern_envelopes_require_current_policy_and_cannot_use_unguarded_consumption() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    let first = received(&mut driver, &model, 9);
    assert!(matches!(
        driver.with_management(first, |_, _, _| panic!("unguarded modern OS effect")),
        Err(ClientError::ModernAdmissionRequired)
    ));
    let second = received(&mut driver, &model, 10);
    let third = received(&mut driver, &model, 11);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    state.allowed.set(false);
    assert!(
        unsafe {
            driver.with_management_modern::<_, _, ()>(&mut owner, permit, second, |_, _, _| {
                panic!("revoked OS effect")
            })
        }
        .is_err()
    );
    state.allowed.set(true);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    driver.disconnect().unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    assert!(
        unsafe {
            driver.with_management_modern::<_, _, ()>(&mut owner, permit, third, |_, _, _| {
                panic!("removed association effect")
            })
        }
        .is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    drop(owner);
    drop(state);
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

#[test]
fn current_modern_key_retries_preserve_management_ipn_and_replacement_cannot_change_namespace() {
    let (mut driver, model, mut owner, state) = fixture();
    let session = attach(&mut driver, &mut owner);
    // Unchanged complete independent source CMAC vector (same original GTK,
    // IGTK, peer and IPN101 used by existing legacy/native BIP controls).
    let bytes = vec![
        0xc0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 2, 6, 7, 8, 9, 10, 2, 6, 7, 8, 9, 10, 0, 0, 7,
        0, 76, 16, 4, 0, 101, 0, 0, 0, 0, 0, 0xc4, 0x80, 0xa2, 0x3a, 0x2c, 0x44, 0x77, 0x70,
    ];
    let mut raw = incoming_bytes(&bytes, None, false);
    raw[4] = 1;
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    let mut events = driver.poll(NOW, &Source, &mut Policy(true)).unwrap();
    let Event::ProtectedManagement(proof) = events.pop().unwrap() else {
        panic!("actual source BIP observation");
    };
    assert!(proof.group());
    assert_eq!(proof.packet_number().value(), 101);
    let before = model.response.lock().unwrap().client_commands.len();
    for (pairwise, index, value, key) in [
        (true, 0, 1, session.pairwise_key()),
        (false, 2, 0x44, session.group_key()),
    ] {
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        assert_eq!(
            unsafe {
                driver.install_key_modern(
                    &mut owner,
                    permit,
                    pairwise,
                    index,
                    &[value; 16],
                    ReplaySeed::ZERO,
                )
            }
            .unwrap(),
            key
        );
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        assert!(matches!(
            unsafe {
                driver.install_key_modern(
                    &mut owner,
                    permit,
                    pairwise,
                    index,
                    &[value ^ 0xff; 16],
                    ReplaySeed::ZERO,
                )
            },
            Err(ClientError::Key(mailbox::key::Error::Security(
                wifi::security::Error::KeyStillInstalled
            )))
        ));
    }
    let again = attach(&mut driver, &mut owner);
    assert!(Arc::ptr_eq(&again, &session));
    assert_eq!(
        driver
            .state()
            .gtk
            .as_ref()
            .unwrap()
            .igtk_receive_floor()
            .unwrap()
            .value(),
        101
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    unsafe {
        driver.with_management_modern(&mut owner, permit, proof, |_, body, pn| {
            assert_eq!(body, [7, 0]);
            assert_eq!(pn.value(), 101);
        })
    }
    .unwrap();
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    assert!(matches!(
        driver.poll(NOW + 1, &Source, &mut Policy(true)),
        Err(ClientError::Key(mailbox::key::Error::Bip(
            mailbox::key::bip::Error::Authentication(wifi::security::management::Error::Replay)
        )))
    ));
    // Robust BA actions belong to this transport's OS consumer. No inferred
    // non-PMF/PMF MLME grant silently enables a native aggregation agreement.
    let before = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    assert!(matches!(
        driver.begin_tx_block_ack(6, 0, NOW + 2),
        Err(ClientError::Unsupported)
    ));
    assert!(driver.station().block_ack_idle());
    assert!(driver.state().transmit_ba.iter().all(Option::is_none));
    assert!(!driver.pending_block_ack());
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    let parameters: u16 = 2 | (6 << 2) | (8 << 6);
    let mut body = vec![3, 0, 7];
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    incoming(&model, &response(0xd0, &body), None, false);
    assert!(driver.poll(NOW + 2, &Source, &mut Policy(true)).is_err());
    assert!(!driver.pending_block_ack());
    assert!(driver.station().block_ack_idle());
    assert!(model.response.lock().unwrap().receive_ba.is_empty());
    stop(&mut driver, &model);
    drop(driver);
    drop(again);
    drop(session);
    drop(owner);
    drop(state);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn actual_modern_reconnect_rejects_original_received_and_tx_session_under_fresh_admission() {
    let (mut driver, model, mut old_owner, old_state) = fixture();
    let old_session = attach(&mut driver, &mut old_owner);
    let old_received = received(&mut driver, &model, 9);
    let old_context = driver.modern_context().unwrap().clone();
    driver.disconnect().unwrap();
    // SAFETY: actual old peer/key removal ACK, descriptor/RX/IRQ and deferred
    // model users drained; this retained observation can only be revalidated.
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    let (join, beacon) = modern_inputs(&driver);
    let response_elements = beacon.elements.clone();
    driver
        .join_modern(
            join,
            beacon,
            profile(),
            NOW + 10,
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    driver.poll(NOW + 11, &Source, &mut Policy(true)).unwrap();
    driver.poll_released().unwrap();
    incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    driver.poll(NOW + 12, &Source, &mut Policy(true)).unwrap();
    assert_eq!(finish_tx(&model)[0][..2], [0, 0]);
    driver.poll(NOW + 13, &Source, &mut Policy(true)).unwrap();
    driver.poll_released().unwrap();
    let mut body = vec![0x11, 0, 0, 0, 1, 0xc0];
    body.extend_from_slice(&response_elements);
    incoming(&model, &response(0x10, &body), None, false);
    driver.poll(NOW + 14, &Source, &mut Policy(true)).unwrap();
    let (mut owner, state) = authority(&driver, &model);
    assert!(!Arc::ptr_eq(driver.modern_context().unwrap(), &old_context));
    let permit = admit(&mut owner, &driver, AssociationUse::Configure);
    unsafe { driver.configure_modern(&mut owner, permit, NOW + 15) }.unwrap();
    for (pairwise, index, value) in [(true, 0, 3), (false, 2, 0x66)] {
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        unsafe {
            driver.install_key_modern(
                &mut owner,
                permit,
                pairwise,
                index,
                &[value; 16],
                ReplaySeed::ZERO,
            )
        }
        .unwrap();
    }
    let session = attach(&mut driver, &mut owner);
    assert_ne!(session.association_epoch(), old_session.association_epoch());
    assert_ne!(session.pairwise_key(), old_session.pairwise_key());
    assert_ne!(session.group_key(), old_session.group_key());
    let before = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert!(
        unsafe {
            driver.with_management_modern::<_, _, ()>(
                &mut owner,
                permit,
                old_received,
                |_, _, _| panic!("old envelope cannot inherit current context/keys"),
            )
        }
        .is_err()
    );
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert!(
        unsafe {
            driver.transmit_management_modern(
                &mut owner,
                permit,
                &old_session,
                Transmit::SaQueryRequest([1, 2]),
                &GuardedSource(state.clone()),
            )
        }
        .is_err()
    );
    assert_eq!(state.allocations.get(), 0);
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    let fresh = received(&mut driver, &model, 1);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert_eq!(
        unsafe { driver.with_management_modern(&mut owner, permit, fresh, |_, _, pn| pn.value()) }
            .unwrap(),
        1
    );
    stop(&mut driver, &model);
    drop(driver);
    drop(session);
    drop(old_session);
    drop(owner);
    drop(state);
    drop(old_owner);
    drop(old_state);
    drop(old_context);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

mod rotation_controls;
