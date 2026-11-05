// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn every_allocation_map_and_visibility_failure_before_pointer_publication_releases() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    for stage in 0..3 {
        for fail in 0..if stage == 2 { 43 } else { 42 } {
            let source = Source {
                fail_at: (stage == 0).then_some(fail),
                ..Default::default()
            };
            let domain = Arc::new(Domain {
                records: Mutex::new(Records {
                    map_fail: (stage == 1).then_some(fail),
                    sync_fail: (stage == 2).then_some(fail),
                    ..Default::default()
                }),
            });
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: This iteration owns exclusive Source RAM in its modeled Domain;
            // allocation/map/visibility faults are serialized and occur before pointer publication.
            let result = unsafe {
                Ax200Boot::start(
                    awake(state.clone(), drops.clone()),
                    crate::wifi::intel::identity::stage(&profile(), &catalog).unwrap(),
                    &source,
                    Some(domain.clone()),
                    32,
                )
            };
            assert!(
                matches!(
                    (&result, stage),
                    (
                        Err(Error::Dma(dma::Error::Memory(
                            crate::bus::dma::memory::MemoryError::OutOfMemory
                        ))),
                        0
                    ) | (
                        Err(Error::Dma(dma::Error::Dma(
                            crate::bus::dma::mapping::DmaError::MappingFailed
                        ))),
                        1
                    ) | (
                        Err(Error::Dma(dma::Error::Dma(
                            crate::bus::dma::mapping::DmaError::VisibilityFailed
                        ))),
                        2
                    )
                ),
                "stage{stage} fail{fail}"
            );
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert!(
                !state
                    .lock()
                    .unwrap()
                    .ops
                    .iter()
                    .any(|op| matches!(op, Op::Write(0x40, _)))
            );
        }
    }
}

#[test]
fn failed_csr_read_sentinels_and_cpu_visibility_never_become_alive() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    let ops = state.lock().unwrap().ops.clone();
    boot.stop().unwrap();
    drop(boot);
    for (index, op) in ops.iter().enumerate() {
        if !matches!(op, Op::Read(_)) {
            continue;
        }
        for value in [u32::MAX, 0xa5a5a5a0, 0x5a5a5a5f] {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let power = awake(state.clone(), drops.clone());
            state.lock().unwrap().sentinel = Some((index, value));
            // SAFETY: The new model epoch exclusively owns Source/Domain and its register data;
            // injected sentinel reads introduce no asynchronous device or competing reset owner.
            let result = unsafe {
                Ax200Boot::start(
                    power,
                    crate::wifi::intel::identity::stage(&profile(), &catalog).unwrap(),
                    &source,
                    Some(domain),
                    32,
                )
            };
            assert!(matches!(result,Err(Error::FailedRead{value:actual,..}) if actual==value));
        }
    }
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    event(&state, 1);
    boot.poll().unwrap();
    let live = domain.records.lock().unwrap().live.len();
    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    domain.records.lock().unwrap().cpu_sync_fail = Some(0);
    assert!(matches!(
        boot.poll(),
        Err(Error::Dma(dma::Error::Dma(
            crate::bus::dma::mapping::DmaError::VisibilityFailed
        )))
    ));
    assert_eq!(domain.records.lock().unwrap().live.len(), live);
    boot.stop().unwrap();
    drop(boot);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
