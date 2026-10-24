// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Actual policy admission spans live native IGTK command/ACK/DMA publication.
use super::*;

#[test]
fn modern_live_igtk_update_guards_real_command_and_revokes_deferred_namespace() {
    let (mut driver, model, mut owner, state) = fixture();
    let first = attach(&mut driver, &mut owner);
    let delayed = received(&mut driver, &model, 9);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let before = model.response.lock().unwrap().client_commands.len();
    state.allowed.set(false);
    // SAFETY: genuine modeled exchange/drain, but actual OS policy has revoked publication.
    assert!(
        unsafe {
            driver.rotate_management_key_modern(
                &mut owner,
                permit,
                &first,
                5,
                &[0x66; 16],
                PacketNumber::new(200).unwrap(),
            )
        }
        .is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(Arc::ptr_eq(
        driver.state().management.as_ref().unwrap(),
        &first
    ));
    state.allowed.set(true);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: exact modeled requester/admission and independently drained old users.
    let second = unsafe {
        driver.rotate_management_key_modern(
            &mut owner,
            permit,
            &first,
            5,
            &[0x66; 16],
            PacketNumber::new(200).unwrap(),
        )
    }
    .unwrap();
    assert!(
        state
            .windows
            .borrow()
            .iter()
            .any(|&(a, b)| a == before && b == before + 1)
    );
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(core::ptr::eq(
        first.association_context().unwrap(),
        second.association_context().unwrap()
    ));
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    assert!(
        unsafe {
            driver.with_management_modern::<_, _, ()>(&mut owner, permit, delayed, |_, _, _| {
                panic!("old protected observation inherited new keys")
            })
        }
        .is_err()
    );
    let current = received(&mut driver, &model, 10);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    state.allowed.set(false);
    assert!(
        unsafe {
            driver.with_management_modern::<_, _, ()>(&mut owner, permit, current, |_, _, _| {
                panic!("revoked current OS policy")
            })
        }
        .is_err()
    );
    state.allowed.set(true);
    let before = model.response.lock().unwrap().client_commands.len();
    // The unguarded producer cannot serve a modern association, even for valid new material.
    assert!(matches!(
        unsafe {
            driver.rotate_management_key(&second, 4, &[0x77; 16], PacketNumber::new(300).unwrap())
        },
        Err(ClientError::ModernAdmissionRequired)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    stop(&mut driver, &model);
    drop(driver);
    drop(first);
    drop(second);
    drop(owner);
    drop(state);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn modern_live_igtk_checks_canonical_pending_ba_even_without_native_queue() {
    let (mut driver, model, mut owner, state) = fixture();
    let first = attach(&mut driver, &mut owner);
    assert!(matches!(
        driver.begin_tx_block_ack(6, 0, NOW),
        Err(ClientError::Unsupported)
    ));
    assert!(driver.station().block_ack_idle());
    // Exercise the defensive boundary against a genuine canonical pending BA
    // owner independently of a native queue. This is an actual Station issuance,
    // not an invented boolean or an always-empty native queue check. The public
    // native initiation above remains refused until protected OS BA MLME exists.
    let action = driver
        .state_mut()
        .station
        .begin_tx_block_ack(6, 0, NOW)
        .unwrap();
    assert!(!driver.station().block_ack_idle());
    assert!(driver.state().transmit_ba[6].is_none());
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    let before = model.response.lock().unwrap().client_commands.len();
    // SAFETY: negative drain control; the actual pending canonical owner must refuse.
    assert!(matches!(
        unsafe {
            driver.rotate_management_key_modern(
                &mut owner,
                permit,
                &first,
                5,
                &[0x66; 16],
                PacketNumber::new(200).unwrap(),
            )
        },
        Err(ClientError::NeedsDrain)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(Arc::ptr_eq(
        driver.state().management.as_ref().unwrap(),
        &first
    ));
    drop(action);
    // Whole-association teardown is the real retirement boundary; never clear
    // pending state directly merely to make a live key update pass.
    stop(&mut driver, &model);
    drop(driver);
    drop(first);
    drop(owner);
    drop(state);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn modern_live_igtk_removed_context_refuses_before_policy_or_mmio_effect() {
    let (mut driver, model, mut owner, state) = fixture();
    let first = attach(&mut driver, &mut owner);
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    driver.disconnect().unwrap();
    let commands = model.response.lock().unwrap().client_commands.len();
    let log = model.bar.0.lock().unwrap().log.len();
    // SAFETY: removed real context must refuse the producer, not repurpose its copied peer/epoch.
    assert!(
        unsafe {
            driver.rotate_management_key_modern(
                &mut owner,
                permit,
                &first,
                5,
                &[0x66; 16],
                PacketNumber::new(200).unwrap(),
            )
        }
        .is_err()
    );
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), log);
    stop(&mut driver, &model);
    drop(driver);
    drop(first);
    drop(owner);
    drop(state);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}
