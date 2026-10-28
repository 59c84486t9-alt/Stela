// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek PMF authentication flow fixtures.
use super::*;

#[test]
fn actual_pmf_preassociation_denial_cancels_only_unpublished_ticket_and_retry_is_guarded() {
    for hardware in [false, true] {
        let (mut driver, model, join, observed, mut owner, state, protection) = preparing();
        let before = model.bar.0.lock().unwrap().log.len();
        let commands = model.response.lock().unwrap().client_commands.len();
        let mappings = model.memory.lock().unwrap().mappings.len();
        assert!(
            driver
                .join_modern(
                    join.clone(),
                    observed.bss().clone(),
                    profile(),
                    100,
                    &Source,
                    &mut Policy(true)
                )
                .is_err()
        );
        state.auth_hardware.set(hardware);
        protection.selected.set(!hardware);
        assert!(
            unsafe {
                driver.join_modern_pmf(
                    &mut owner,
                    join.clone(),
                    &observed,
                    profile(),
                    100,
                    &PmfSource(state.clone()),
                    &mut Policy(true),
                )
            }
            .is_err()
        );
        assert_eq!(driver.phase(), ClientPhase::Idle);
        assert_eq!(driver.station().phase(), station::Phase::Idle);
        assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            commands
        );
        assert_eq!(model.memory.lock().unwrap().mappings.len(), mappings);
        assert!(driver.state().pmf_selected.is_none());
        assert!(driver.state().pmf_authentication.is_none());
        let withdrawn_epoch = state
            .tickets
            .borrow()
            .last()
            .map_or(0, |ticket| ticket.epoch());
        state.auth_hardware.set(true);
        protection.selected.set(true);
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                join,
                &observed,
                profile(),
                101,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .unwrap();
        assert_eq!(driver.phase(), ClientPhase::Joining);
        assert!(driver.station().association_epoch().unwrap() > withdrawn_epoch);
        assert!(
            state
                .windows
                .borrow()
                .iter()
                .any(|&(start, end)| start == commands && end > start)
        );
        assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
        assert!(!state.hardware.get() && !state.os.get());
    }
}

#[test]
fn actual_pmf_pending_publication_cannot_inherit_revised_or_foreign_authentication_guards() {
    for revision in [false, true] {
        let (mut driver, model, join, observed, mut owner, state, protection) = preparing();
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                join.clone(),
                &observed,
                profile(),
                100,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .unwrap();
        let commands = model.response.lock().unwrap().client_commands.len();
        let before = model.bar.0.lock().unwrap().log.len();
        let mappings = model.memory.lock().unwrap().mappings.len();
        let ticket = driver.station().pmf_authentication().unwrap().0;
        if revision {
            state.revision.set(2);
        } else {
            protection.selected.set(false);
        }
        assert!(
            unsafe {
                driver.poll_pmf_authentication(
                    &mut owner,
                    101,
                    &PmfSource(state.clone()),
                    &mut Policy(true),
                )
            }
            .is_err()
        );
        assert!(driver.poll(101, &Source, &mut Policy(true)).is_err());
        assert!(
            driver
                .poll_station(101, &Source, &mut Policy(true))
                .is_err()
        );
        let (mut foreign, foreign_state, _) = authority_pmf(observed, &join, &model);
        assert!(
            unsafe {
                driver.poll_pmf_authentication(
                    &mut foreign,
                    101,
                    &PmfSource(foreign_state),
                    &mut Policy(true),
                )
            }
            .is_err()
        );
        assert_eq!(driver.station().pmf_authentication().unwrap().0, ticket);
        assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            commands
        );
        assert_eq!(model.memory.lock().unwrap().mappings.len(), mappings);
        assert!(
            driver
                .state()
                .controller
                .state()
                .data_tx
                .as_ref()
                .unwrap()
                .outstanding_tokens()
                > 0
        );
        drop(driver);
        drop(owner);
        drop(state);
        drop(protection);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn actual_pmf_timeout_retry_and_auth_response_requalify_each_canonical_ticket() {
    let (mut driver, model, join, observed, mut owner, state, _) = preparing();
    unsafe {
        driver.join_modern_pmf(
            &mut owner,
            join,
            &observed,
            profile(),
            100,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let first = driver.station().pmf_authentication().unwrap().0;
    finish_tx(&model);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            101,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    driver.poll_released().unwrap();
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            500_101,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let retried = driver.station().pmf_authentication().unwrap().0;
    assert_ne!(first, retried);
    assert_eq!(first.epoch(), retried.epoch());
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            500_102,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    driver.poll_released().unwrap();
    incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            500_103,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let association = driver.station().pmf_authentication().unwrap().0;
    assert_ne!(retried, association);
    assert_eq!(association.epoch(), first.epoch());
    let actual = finish_tx(&model);
    assert_eq!(actual[0][..2], [0, 0]);
    for ticket in [first, retried, association] {
        assert!(state.tickets.borrow().contains(&ticket));
    }
}
