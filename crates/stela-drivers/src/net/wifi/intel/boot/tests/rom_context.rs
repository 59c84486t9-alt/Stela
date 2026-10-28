// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn ax210_publishes_iml_scratch_dummy_tails_and_retains_pnvm_context_after_alive() {
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let step = crate::net::wifi::intel::platform::load_step(observation, &step_catalog).unwrap();
    let step_pointer = step.image().unwrap().bytes().as_ptr();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start_ax210(&catalog, step, &source, &domain, &state, &drops);
    assert_eq!(
        boot.step_configuration()
            .unwrap()
            .image()
            .unwrap()
            .bytes()
            .as_ptr(),
        step_pointer
    );
    let memory = boot.ax210.as_ref().unwrap();
    let context = boot.context.region().address;
    let scratch = memory.scratch.region().address;
    let info = memory.info.region().address;
    let iml = memory.iml.region().address;
    let wire = device_read(&domain, context, 0, 104);
    let addr = |at| u64::from_le_bytes(wire[at..at + 8].try_into().unwrap());
    assert_eq!(
        (addr(8), addr(24), addr(32), addr(88)),
        (info, info + 2048, info + 3072, scratch)
    );
    assert_eq!(
        device_read(&domain, scratch, 76, 8),
        [1, 0x12, 0x34, 0x56, 0x78, 0, 0, 0]
    );
    assert_eq!(device_read(&domain, iml, 0, 64), [0xa5; 64]);
    // The hardware may really write both dummy tail slots, including after
    // ALIVE; these are mapped writable RAM, never null/dummy host pointers.
    device_write(&domain, info, 2048, &0x1234u32.to_le_bytes(), false);
    device_write(&domain, info, 3072, &0x5678u32.to_le_bytes(), false);
    let ops = state.lock().unwrap().ops.clone();
    let publish = ops
        .iter()
        .position(|op| matches!(op, Op::Write(0x118, _)))
        .unwrap();
    assert_eq!(
        &ops[publish..publish + 8],
        &[
            Op::Write(0x118, context as u32),
            Op::Write(0x11c, (context >> 32) as u32),
            Op::Write(0x120, iml as u32),
            Op::Write(0x124, (iml >> 32) as u32),
            Op::Write(0x128, 64),
            Op::Read(0),
            Op::Write(0, 0x456f8902),
            Op::Write(0xd4, 0x88fa88fa)
        ]
    );
    assert!(ops.contains(&Op::Write(0x444, 0x03d05c44)));
    assert!(!ops.iter().any(|op| matches!(op, Op::Write(0x40 | 0x44, _))));
    let live = domain.records.lock().unwrap().live.len();
    assert_eq!(live, 45);
    event(&state, 1);
    assert!(boot.poll().unwrap().is_none());
    for (index, buffer) in boot.buffers.iter().enumerate() {
        let descriptor = device_read(&domain, boot.free.region().address, index * 16, 16);
        assert_eq!(
            u16::from_le_bytes(descriptor[..2].try_into().unwrap()),
            index as u16 + 1
        );
        assert_eq!(
            u64::from_le_bytes(descriptor[8..].try_into().unwrap()),
            buffer.allocation.region().address
        );
        assert_eq!(buffer.device_owned, index < 24);
    }
    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    let report = boot.poll().unwrap().unwrap();
    assert_eq!(report.sku, [0x610d0, 0x1234, 0x55667788]);
    assert_eq!(domain.records.lock().unwrap().live.len(), live - 3); // LMAC+UMAC+IML
    assert_eq!(boot.state, State::Alive);
    assert_eq!(
        boot.post_alive_plan().unwrap().pnvm,
        crate::net::wifi::intel::platform::PnvmSource::Bios {
            external_fallback: true
        }
    );
    for address in [context, scratch, info] {
        assert!(
            domain
                .records
                .lock()
                .unwrap()
                .live
                .contains_key(&id(address))
        );
    }
    assert!(!domain.records.lock().unwrap().live.contains_key(&id(iml)));
    device_write(&domain, info, 3072, &0x99u32.to_le_bytes(), false);
    boot.stop().unwrap();
    assert!(domain.records.lock().unwrap().live.is_empty());
    drop(boot);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        source.calls.load(Ordering::Relaxed),
        source.released.load(Ordering::Relaxed)
    );
}

#[test]
fn ax210_all_prepublication_faults_release_and_each_partial_stop_can_retry() {
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    for stage in 0..3 {
        for fail in 0..if stage == 2 { 48 } else { 45 } {
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
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let result = unsafe {
                RomBoot::start_ax210(
                    awake_profile(state.clone(), drops.clone(), ax210_profile()),
                    crate::net::wifi::intel::identity::stage(&ax210_profile(), &catalog).unwrap(),
                    crate::net::wifi::intel::platform::load_step(observation, &step_catalog)
                        .unwrap(),
                    &source,
                    Some(domain.clone()),
                    32,
                    ProductResetPolicy::NoIwlmei,
                )
            };
            assert!(
                matches!(result, Err(Error::Dma(_))),
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
                    .any(|op| matches!(op, Op::Write(0x118, _)))
            );
            assert_eq!(
                source.calls.load(Ordering::Relaxed) - (stage == 0) as usize,
                source.released.load(Ordering::Relaxed)
            );
        }
    }
    for fail in 0..45 {
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
        domain.records.lock().unwrap().unmap_fail = Some(fail);
        assert!(matches!(
            boot.stop(),
            Err(Error::Dma(dma::Error::Dma(
                crate::bus::dma::mapping::DmaError::InvalidationFailed
            )))
        ));
        assert_eq!(boot.state, State::Quiescent);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
