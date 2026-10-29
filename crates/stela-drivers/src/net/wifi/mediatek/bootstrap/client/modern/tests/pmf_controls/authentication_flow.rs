// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek PMF authentication flow fixtures.
use super::*;

#[test]
fn preassociation_denial_and_guarded_retry() {
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
            // SAFETY: The original scan, request and DMA backing remain held. One
            // hardware/OS policy factor is denied; acquisition must
            // reject before publishing authentication or issuing a new DMA command.
            unsafe {
                driver.join_modern_pmf(
                    &mut owner,
                    PmfJoin {
                        join: join.clone(),
                        observed: &observed,
                    },
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
        // SAFETY: Both policy factors were restored for the same original observation
        // and native owner. The rejected attempt published no request; retry is
        // serialized by fresh model leases and keeps all DMA backing.
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                PmfJoin {
                    join,
                    observed: &observed,
                },
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
fn pending_publication_guard_revision() {
    for revision in [false, true] {
        let (mut driver, model, join, observed, mut owner, state, protection) = preparing();
        // SAFETY: The initial request uses its original observation and native
        // backing before any revision change. Both guards serialize publication and
        // keep pending frame DMA for the later revocation checks.
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                PmfJoin {
                    join: join.clone(),
                    observed: &observed,
                },
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
            // SAFETY: The pending ticket and its DMA remain owned by the original
            // model requester. A changed revision or withdrawn selection must be
            // refused under fresh guards without inheriting the earlier publication
            // grant.
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
            // SAFETY: Both model owners and the pending DMA remain live. This newly
            // branded owner is foreign despite matching context values;
            // authentication must reject it before altering the original ticket.
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
fn authentication_retry_tickets() {
    let (mut driver, model, join, observed, mut owner, state, _) = preparing();
    // SAFETY: The selected request, original scan and native-memory owner remain
    // current. Both model leases serialize the first authentication request; no
    // physical device or concurrent reset user exists.
    unsafe {
        driver.join_modern_pmf(
            &mut owner,
            PmfJoin {
                join,
                observed: &observed,
            },
            profile(),
            100,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let first = driver.station().pmf_authentication().unwrap().0;
    finish_tx(&model);
    // SAFETY: The original authentication TX completed through the synchronous device
    // peer, and its DMA owner remains held until release. Current guards check
    // this owner and pending ticket.
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
    // SAFETY: The original frame was acknowledged and released before this timeout.
    // The same model owner and live backing are requalified under both guards before
    // retry creates a fresh canonical ticket.
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
    // SAFETY: The retried authentication TX completed through the same synchronous
    // peer. Its ticket and native-memory owner remain held while fresh leases
    // check completion and later release.
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
    // SAFETY: The injected authentication response is backed by the RX queue
    // and current retry context. Fresh hardware/OS guards check it before
    // publishing the association ticket and its DMA.
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
