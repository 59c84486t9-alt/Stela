// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn rom_pointer_csr_alive_restock_and_dma_alive_are_distinct_owned_states() {
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    let request = profile().firmware_request();
    let original = resources::Provider::load(&catalog, request.requirement()).unwrap();
    assert_eq!(boot.firmware_source().name(), request.name);
    assert_eq!(
        boot.firmware_source().target(),
        request.requirement().target
    );
    assert_eq!(boot.firmware_source().sha256(), original.sha256());
    assert_eq!(boot.firmware_source().provenance(), original.provenance());
    assert_eq!(
        boot.firmware_source().bytes().as_ptr(),
        original.bytes().as_ptr()
    );
    let context = device_read(&domain, boot.context.region().address, 0, 1792);
    assert_eq!(
        u64::from_le_bytes(context[24..32].try_into().unwrap()),
        boot.free.region().address
    );
    assert_eq!(
        u64::from_le_bytes(context[48..56].try_into().unwrap()),
        boot.command.region().address
    );
    {
        let locked = state.lock().unwrap();
        let registers = &locked.registers;
        assert_eq!(registers.get(&12), Some(&0));
        assert_eq!(registers.get(&0xd4), Some(&0x88fa88fa));
        assert_eq!(registers.get(&0x444), Some(&0x03005c44));
        assert_eq!(registers.get(&0x44c), Some(&1));
    }
    assert!(boot.poll().unwrap().is_none());
    assert_eq!(boot.state, State::Published);
    let live = domain.records.lock().unwrap().live.len();
    assert_eq!(boot.post_alive_plan(), Err(Error::State));
    event(&state, 1);
    assert!(boot.poll().unwrap().is_none());
    assert_eq!(boot.state, State::Restocked);
    assert_eq!(boot.credits, 24);
    assert_eq!(domain.records.lock().unwrap().live.len(), live);
    assert_eq!(state.lock().unwrap().registers.get(&0x1c80), Some(&24));
    for (n, buffer) in boot.buffers.iter().enumerate() {
        let raw = device_read(&domain, boot.free.region().address, n * 8, 8);
        assert_eq!(
            u64::from_le_bytes(raw.try_into().unwrap()),
            buffer.allocation.region().address | (n as u64 + 1)
        );
        assert_eq!(buffer.device_owned, n < 24);
    }
    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    event(&state, 1 << 31);
    let report = boot.poll().unwrap().unwrap();
    assert_eq!(report.sku, [0x610d0, 0x1234, 0x55667788]);
    assert_eq!(report.notification_version, 6);
    assert_eq!(boot.state, State::Alive);
    assert_eq!(
        boot.post_alive_plan().unwrap().pnvm,
        crate::wifi::intel::platform::PnvmSource::Bios {
            external_fallback: false
        }
    );
    assert_eq!(domain.records.lock().unwrap().cpu_syncs, 1);
    assert_eq!(domain.records.lock().unwrap().live.len(), live - 3);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
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
fn duplicate_unsubmitted_wrong_queue_failed_alive_and_bad_producer_never_release_rom() {
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    for mode in 0..7 {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        let live = domain.records.lock().unwrap().live.len();
        event(&state, 1);
        boot.poll().unwrap();
        match mode {
            0 => {
                complete(&boot, &domain, 0, 1, &rx_packet(2, 0xcafe, 0));
                assert!(boot.poll().unwrap().is_none());
                device_write(
                    &domain,
                    boot.used.region().address,
                    4,
                    &1u32.to_le_bytes(),
                    false,
                );
                device_write(
                    &domain,
                    boot.status.region().address,
                    0,
                    &2u16.to_le_bytes(),
                    false,
                );
            }
            1 => {
                device_write(
                    &domain,
                    boot.used.region().address,
                    0,
                    &31u32.to_le_bytes(),
                    false,
                );
                device_write(
                    &domain,
                    boot.status.region().address,
                    0,
                    &1u16.to_le_bytes(),
                    false,
                );
            }
            2 => complete(&boot, &domain, 0, 1, &rx_packet(1, 0xdead, 0)),
            3 => complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 2)),
            4 => device_write(
                &domain,
                boot.status.region().address,
                0,
                &25u16.to_le_bytes(),
                false,
            ),
            _ => {
                device_write(
                    &domain,
                    boot.used.region().address,
                    0,
                    &(if mode == 5 { 0u32 } else { 1000 }).to_le_bytes(),
                    false,
                );
                device_write(
                    &domain,
                    boot.status.region().address,
                    0,
                    &1u16.to_le_bytes(),
                    false,
                );
            }
        }
        assert!(boot.poll().is_err(), "mode{mode}");
        assert_eq!(boot.state, State::Poisoned);
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        boot.stop().unwrap();
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn failed_retirement_keeps_owner_for_retry() {
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    for fail in 0..42 {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        domain.records.lock().unwrap().unmap_fail = Some(fail);
        assert!(
            matches!(
                boot.stop(),
                Err(Error::Dma(dma::Error::Dma(
                    crate::bus::dma::mapping::DmaError::InvalidationFailed
                )))
            ),
            "unmap{fail}"
        );
        assert_eq!(boot.state, State::Quiescent);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    state.lock().unwrap().stop_ack = false;
    let live = domain.records.lock().unwrap().live.len();
    assert!(matches!(
        boot.stop(),
        Err(Error::Timeout { register: 0x20 })
    ));
    assert_eq!(domain.records.lock().unwrap().live.len(), live);
    state.lock().unwrap().stop_ack = true;
    boot.stop().unwrap();
    drop(boot);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
