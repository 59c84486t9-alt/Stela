// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek management admission fixtures.
use super::*;

#[test]
fn revoked_initial_key_admission() {
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
fn pending_block_ack_prevents_initial_igtk() {
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
