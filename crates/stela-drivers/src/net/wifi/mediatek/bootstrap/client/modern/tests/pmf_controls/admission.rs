// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek PMF admission fixtures.
use super::*;

#[test]
fn pmf_admission_and_legacy_denial() {
    let (mut driver, model, before, mut owner, state, protection) = awaiting_pmf();
    let (mut ordinary, _) = authority(&driver, &model);
    assert!(matches!(
        ordinary.admit_association(
            driver.station(),
            driver.modern_context().unwrap().clone(),
            AssociationUse::Configure
        ),
        Err(reg::Error::OsDenied)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    let admission = permit(&mut owner, &driver, AssociationUse::Configure);
    protection.selected.set(false);
    assert!(
        // SAFETY: The admission names this retained model requester and context.
        // Selection was deliberately revoked after preflight; fresh OS guards must deny
        // configuration before any modeled command is published.
        unsafe { driver.configure_modern(&mut owner, admission, 105) }.is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(!state.hardware.get() && !state.os.get());
    protection.selected.set(true);
    let admission = permit(&mut owner, &driver, AssociationUse::Configure);
    // SAFETY: Selection is restored for the original retained context and native
    // memory. Both model leases are reacquired synchronously and no device, reset or
    // concurrent policy writer can race configuration.
    unsafe { driver.configure_modern(&mut owner, admission, 105) }.unwrap();
    assert_eq!(driver.completed_modern_requests(), 7);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 7
    );
    assert!(
        protection
            .uses
            .borrow()
            .contains(&AssociationUse::Configure)
    );
}

#[test]
fn selected_rsn_and_ap_response() {
    let (driver, _) = setup();
    for band in [Band::Ghz2, Band::Ghz5] {
        let local = driver.local_advertisement(band).unwrap();
        let mut bytes = vec![0, 1, b'x'];
        bytes.extend_from_slice(local.elements());
        append_ie(&mut bytes, 48, &selected_rsn());
        assert!(
            AssociationRequest::new_modern_with_local(
                0x11,
                10,
                bytes.clone(),
                local.capabilities().clone(),
                Mode::Ht,
                Width::Mhz20
            )
            .is_err()
        );
        let selected = AssociationRequest::new_modern_with_local_pmf(
            0x11,
            10,
            bytes.clone(),
            local.capabilities().clone(),
            Mode::Ht,
            Width::Mhz20,
        )
        .unwrap();
        assert_eq!(selected.pmf().unwrap().rsn(), selected_rsn());
        assert_eq!(selected.elements(), bytes);
        // wpa_supplicant's RSNX (H2E, SAE-PK) travels with the request.
        append_ie(&mut bytes, 244, &[0x20]);
        let extended = AssociationRequest::new_modern_with_local_pmf(
            0x11,
            10,
            bytes.clone(),
            local.capabilities().clone(),
            Mode::Ht,
            Width::Mhz20,
        )
        .unwrap();
        assert_eq!(extended.elements(), bytes);
    }
    for case in 0..4 {
        assert!(
            awaiting_with(|_, bss, response| {
                let mut bad = selected_rsn();
                match case {
                    0 => {
                        bad[17] = 8;
                        bss.elements = replace_rsn(&bss.elements, &bad);
                    }
                    1 => append_ie(&mut bss.elements, 48, &bad),
                    2 => {
                        bad[18] = 0x80;
                        *response = replace_rsn(response, &bad);
                    }
                    _ => append_ie(response, 48, &bad),
                }
            })
            .is_err()
        );
    }
}

#[test]
fn scan_observation_provenance() {
    let (mut driver, model, join, old, _, _, _) = preparing();
    let (_, other_model, _, foreign, _, _, _) = preparing();
    let (mut owner, state, _) = authority_pmf(old.clone(), &join, &model);
    let before = model.bar.0.lock().unwrap().log.len();
    assert!(
        // SAFETY: Both original and foreign observations retain their own model
        // backing. The foreign observation is intentionally mismatched; requester
        // validation must reject it before minting authentication authority.
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                PmfJoin {
                    join: join.clone(),
                    observed: &foreign,
                },
                profile(),
                100,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .is_err()
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
    assert!(state.tickets.borrow().is_empty());
    let (_, bss) = inputs(&driver);
    let fresh = observe_at(&mut driver, &model, &bss, 10);
    assert!(!Arc::ptr_eq(&old, &fresh));
    let (mut owner, state, _) = authority_pmf(fresh.clone(), &join, &model);
    let before = model.bar.0.lock().unwrap().log.len();
    assert!(
        // SAFETY: The old observation stays a live Arc, while this owner selects the
        // fresh scan receipt. The model has no asynchronous radio user; stale
        // provenance must be rejected before queue publication.
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                PmfJoin {
                    join: join.clone(),
                    observed: &old,
                },
                profile(),
                100,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .is_err()
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
    assert!(state.tickets.borrow().is_empty());
    // SAFETY: This fresh observation belongs to the original live requester and
    // selected request. Both current model leases cover authentication submission and
    // retain its scan and native-memory owners.
    unsafe {
        driver.join_modern_pmf(
            &mut owner,
            PmfJoin {
                join,
                observed: &fresh,
            },
            profile(),
            100,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    assert!(!other_model.memory.lock().unwrap().mappings.is_empty());
}
