// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management context fixtures.
use super::*;

#[test]
fn deferred_envelope_guard_revalidation() {
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
fn reconnect_rejects_stale_context_and_keys() {
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
    let epoch = driver.station().association_epoch().unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    let head = model.queues[&0xd4300].lock().unwrap().head;
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: actual model old users were drained above. Even this fresh GTK
    // namespace cannot revive the original IGTK with a reset replay floor.
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
        Err(ClientError::Key(mailbox::key::Error::Bip(
            mailbox::key::bip::Error::RetiredMaterial
        )))
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    assert!(driver.state().management.is_none());
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: same actual drained requester and authenticated model OS exchange
    // as attach(), now supplying fresh temporal material for this association.
    let session = unsafe {
        driver.install_management_key_modern(
            &mut owner,
            permit,
            epoch,
            4,
            &[0x77; 16],
            PacketNumber::new(100).unwrap(),
        )
    }
    .unwrap();
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
