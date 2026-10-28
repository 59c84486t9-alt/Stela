// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek PMF key sessions fixtures.
use super::*;

#[test]
fn configuration_and_igtk_failure() {
    for dropped in [false, true] {
        let (mut driver, model, before, mut owner, state, _) = awaiting_pmf();
        let context = driver.modern_context().unwrap().clone();
        let admission = permit(&mut owner, &driver, AssociationUse::Configure);
        if dropped {
            model.response.lock().unwrap().drop = true;
        } else {
            model.response.lock().unwrap().bss_status = 9;
        }
        assert!(
            // SAFETY: The original context and DMA owners remain live under fresh model
            // guards. Injected loss or failure of the firmware acknowledgement must
            // quarantine them rather than release uncertain resources.
            unsafe { driver.configure_modern(&mut owner, admission, 105) }.is_err()
        );
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert_eq!(driver.completed_modern_requests(), 0);
        assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            before + 1
        );
        assert!(!driver.station().port_open(None, None));
        drop(driver);
        drop(owner);
        drop(state);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
    for dropped in [false, true] {
        let (mut driver, model, mut owner, state, protection) = configured();
        protection.authenticated.set(true);
        for (pairwise, index, material) in [(true, 0, 1), (false, 2, 0x44)] {
            let admission = permit(&mut owner, &driver, AssociationUse::Management);
            // SAFETY: The authenticated fixture OS supplies this pairwise/group key
            // material for its current peer. The same retained native context is
            // serialized by both guards, with no concurrent key or frame user.
            unsafe {
                driver.install_key_modern(
                    &mut owner,
                    admission,
                    pairwise,
                    index,
                    &[material; 16],
                    ReplaySeed::ZERO,
                )
            }
            .unwrap();
        }
        let admission = permit(&mut owner, &driver, AssociationUse::Management);
        let epoch = driver.station().association_epoch().unwrap();
        if dropped {
            model.response.lock().unwrap().drop = true;
        } else {
            model.response.lock().unwrap().status = 9;
        }
        assert!(
            // SAFETY: No prior management session, key callback or asynchronous IRQ
            // user exists in this fixture. Its current epoch and native backing
            // remain owned while a deliberately failed acknowledgement is retained.
            unsafe {
                driver.install_management_key_modern(
                    &mut owner,
                    admission,
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
        assert!(!driver.station().port_open(
            Some(driver.state().ptk.as_ref().unwrap().slot()),
            Some(driver.state().gtk.as_ref().unwrap().slot())
        ));
        drop(driver);
        drop(owner);
        drop(state);
        drop(protection);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}

#[test]
fn igtk_rotation_revokes_old_session() {
    let (mut driver, model, mut owner, state, protection) = configured();
    protection.authenticated.set(true);
    protection.port.set(true);
    let first = attach(&mut driver, &mut owner);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: The first session belongs to this current retained peer and its key
    // acknowledgements completed synchronously. The fixture explicitly grants its
    // authenticated port policy under both leases.
    unsafe { driver.authorize_port_pmf(&mut owner, admission, &first) }.unwrap();
    incoming(
        &model,
        &response(0x40d0, &[8, 1, 3, 4]),
        Some((1, 0, 9)),
        false,
    );
    let mut events = poll(&mut driver, &mut owner, &state, 110).unwrap();
    let Event::ProtectedManagement(delayed) = events.pop().unwrap() else {
        panic!("original authenticated envelope")
    };
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: same modeled OS exchange, old slot peer-retired, actual users drained.
    let second = unsafe {
        driver.rotate_management_key_modern(
            &mut owner,
            admission,
            &first,
            5,
            &[0x66; 16],
            PacketNumber::new(200).unwrap(),
        )
    }
    .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(first.pairwise_key(), second.pairwise_key());
    assert_eq!(first.group_key(), second.group_key());
    assert!(driver.station().port_open(
        Some(driver.state().ptk.as_ref().unwrap().slot()),
        Some(driver.state().gtk.as_ref().unwrap().slot())
    ));
    let before = model.bar.0.lock().unwrap().log.len();
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    assert!(
        // SAFETY: The old session remains a live Arc, but rotation replaced its
        // authority. The original requester and current guards must reject that stale
        // session before any modeled register effect.
        unsafe { driver.authorize_port_pmf(&mut owner, admission, &first) }.is_err()
    );
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    assert!(
        // SAFETY: The delayed RX envelope is still owned, but its management session
        // was retired by rotation. Current context validation must reject it before
        // invoking the callback or exposing a borrowed body.
        unsafe {
            driver.with_management_modern::<_, _, ()>(&mut owner, admission, delayed, |_, _, _| {
                panic!("retired Session must remain inert")
            })
        }
        .is_err()
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: The second session is the current acknowledged rotation result, with
    // unchanged retained data-key owners. The same fixture OS grants port
    // authorization under newly acquired hardware/OS leases.
    unsafe { driver.authorize_port_pmf(&mut owner, admission, &second) }.unwrap();
    let admission = permit(&mut owner, &driver, AssociationUse::Data);
    let epoch = driver.station().association_epoch().unwrap();
    // SAFETY: The data frame is borrowed only for this call; its queued DMA and key
    // owners remain retained. The current requester and authenticated model OS grant
    // data submission under both guards.
    unsafe {
        driver.transmit_modern(
            &mut owner,
            admission,
            epoch,
            &eth(0x0800),
            TxClass::Data,
            None,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    assert_eq!(finish_tx(&model).len(), 1);
    poll(&mut driver, &mut owner, &state, 111).unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert!(Arc::ptr_eq(
        released[0].context.management_session().unwrap(),
        &second
    ));
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    driver.disconnect().unwrap();
    assert!(
        // SAFETY: The session Arc and original native backing remain live after
        // disconnect, but the earlier admission is stale. Current guard/context checks
        // must reject authorization without restarting the association.
        unsafe { driver.authorize_port_pmf(&mut owner, admission, &second) }.is_err()
    );
}
