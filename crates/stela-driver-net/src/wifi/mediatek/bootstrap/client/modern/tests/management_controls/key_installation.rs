// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management key installation fixtures.
use super::*;

#[test]
fn initial_key_batch_and_replay_floor() {
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
    assert!(!driver.station().port_open(&[
        driver.state().ptk.as_ref().unwrap().slot(),
        driver.state().gtk.as_ref().unwrap().slot()
    ]));
    let proof = received(&mut driver, &model, 9);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert_eq!(
        // SAFETY: The envelope and current session keep this requester and its RX
        // backing. Both current model guards scope the callback, which returns only
        // the packet-number scalar and no borrowed frame view.
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
fn key_retries_preserve_ipn_namespace() {
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
            // SAFETY: This is an idempotent retry of the same current key material
            // and kept peer. Both model leases serialize the operation,
            // preserving the existing key handle and management replay floor.
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
            // SAFETY: The original installed key and all backing remain held. The
            // changed material must be refused before replacing the live
            // key or resetting its replay namespace.
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
    // SAFETY: The authenticated group envelope keeps the original session after
    // same-key retries. Current guards scope its borrowed body; the callback only
    // checks bytes and a scalar packet number.
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
