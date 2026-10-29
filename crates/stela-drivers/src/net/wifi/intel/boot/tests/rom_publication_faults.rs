// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn ax210_every_launch_csr_fault_quarantines_owner_after_publication() {
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start_ax210(
        &catalog,
        crate::net::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
        &source,
        &domain,
        &state,
        &drops,
    );
    let ops = state.lock().unwrap().ops.clone();
    let publication = ops
        .iter()
        .position(|op| matches!(op, Op::Write(0x118, _)))
        .unwrap();
    boot.stop().unwrap();
    drop(boot);
    for index in 0..ops.len() {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
        state.lock().unwrap().fail = Some(index);
        // SAFETY: This iteration owns fresh exclusive Source RAM in its AX210 model Domain;
        // only serialized CSR failure is injected, and uncertain publication keeps that owner.
        let result = unsafe {
            RomBoot::start_ax210(
                power,
                crate::net::wifi::intel::identity::stage(&ax210_profile(), &catalog).unwrap(),
                crate::net::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                Some(domain.clone()),
                32,
                ProductResetPolicy::NoIwlmei,
            )
        };
        assert!(
            matches!(result, Err(Error::Access(power::AccessError::Unavailable))),
            "operation{index}"
        );
        assert_eq!(
            drops.load(Ordering::Relaxed),
            usize::from(index < publication)
        );
        assert_eq!(
            domain.records.lock().unwrap().live.is_empty(),
            index < publication
        );
    }
    for (index, op) in ops.iter().enumerate() {
        if !matches!(op, Op::Read(_)) {
            continue;
        }
        for value in [u32::MAX, 0xa5a5a5a0, 0x5a5a5a5f] {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
            state.lock().unwrap().sentinel = Some((index, value));
            // SAFETY: Fresh Source/Domain belong to this sole AX210 model/reset owner;
            // sentinel reads are serialized model data, with mappings kept after publication.
            let result = unsafe {
                RomBoot::start_ax210(
                    power,
                    crate::net::wifi::intel::identity::stage(&ax210_profile(), &catalog).unwrap(),
                    crate::net::wifi::intel::platform::load_step(observation, &step_catalog)
                        .unwrap(),
                    &source,
                    Some(domain.clone()),
                    32,
                    ProductResetPolicy::NoIwlmei,
                )
            };
            assert!(matches!(result,Err(Error::FailedRead{value:actual,..})if actual==value));
            assert_eq!(
                drops.load(Ordering::Relaxed),
                usize::from(index < publication)
            );
        }
    }
}

#[test]
fn every_csr_start_failure_after_first_possible_publication_quarantines_bar_and_dma() {
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    let ops = state.lock().unwrap().ops.clone();
    let publication = ops
        .iter()
        .position(|op| matches!(op, Op::Write(0x40, _)))
        .unwrap();
    boot.stop().unwrap();
    drop(boot);
    for fail in 0..ops.len() {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let power = awake(state.clone(), drops.clone());
        state.lock().unwrap().fail = Some(fail);
        // SAFETY: This sole AX200 model owner uses fresh exclusive Source/Domain RAM;
        // injected CSR failures cannot create a concurrent device or release exposed backing.
        let result = unsafe {
            Ax200Boot::start(
                power,
                crate::net::wifi::intel::identity::stage(&profile(), &catalog).unwrap(),
                &source,
                Some(domain.clone()),
                32,
            )
        };
        assert!(
            matches!(result, Err(Error::Access(power::AccessError::Unavailable))),
            "operation{fail}"
        );
        if fail < publication {
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        } else {
            assert!(!domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
    }
}
