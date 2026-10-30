// SPDX-License-Identifier: MIT
//! Real EP0 configuration-zero acknowledgement and endpoint lifetime controls.
use super::*;
use periodic_tests::{attached_periodic, input_interrupt};

#[test]
fn configuration_zero_retires_endpoint_handles() {
    let (mut c, m, id, bulk, interrupt) = attached_periodic(64, 1, 4);
    let ticket = c.submit_bulk_out(output(&bulk), &[7], 1_000_000).unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 1);
    assert!(c.ports[0].as_ref().unwrap().endpoints[2].unwrap().toggle);
    let before = m.lock().unwrap().setup_trace.len();
    let epoch = c.ports[0].as_ref().unwrap().configuration;
    c.unconfigure(&id).unwrap();
    {
        let p = m.lock().unwrap();
        assert_eq!(
            p.setup_trace[before..],
            [[0, 9, 0, 0, 0, 0, 0, 0], [0x80, 8, 0, 0, 0, 0, 1, 0]]
        );
        assert_eq!(p.configurations[0], 0);
        assert_eq!(p.addresses[0], Some(7));
        assert!(p.mapped && p.bme && !p.retired);
        assert_eq!(p.unmapped, 0);
        assert_eq!(p.words[(OP + STS) / 4] & (ASS | PSS), 0);
    }
    let device = c.ports[0].as_ref().unwrap();
    assert_eq!(device.configuration, epoch + 1);
    assert_eq!(device.configuration_value, 0);
    assert!(device.endpoints.iter().all(Option::is_none));
    assert!(c.bulk_pipes(&id).unwrap().is_empty());
    assert!(c.interrupt_pipes(&id).unwrap().is_empty());
    let before = m.lock().unwrap().io;
    assert!(matches!(
        c.submit_bulk_in(input(&bulk), 1, 1_000_000),
        Err(Error::Stale)
    ));
    assert!(matches!(
        c.submit_interrupt_in(input_interrupt(&interrupt), 1, 1_000_000),
        Err(Error::Stale)
    ));
    assert!(matches!(c.suspend_port(&id), Err(Error::Invalid)));
    assert_eq!(m.lock().unwrap().io, before);
    let fresh = c.configure(&id, 0).unwrap();
    let ticket = c.submit_bulk_out(output(&fresh), &[9], 1_000_000).unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 1);
    assert!(!m.lock().unwrap().bulk_toggles.last().unwrap());
    let irq = c.interrupt_pipes(&id).unwrap();
    let ticket = c
        .submit_interrupt_in(input_interrupt(&irq), 3, 1_000_000)
        .unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().data, [0, 1, 2]);
    c.shutdown().unwrap();
}

#[test]
fn configuration_zero_busy_and_foreign_preflight_preserves_current_dma() {
    for periodic in [false, true] {
        let (mut c, m, id, bulk, interrupt) = attached_periodic(64, 1, 4);
        let current = if periodic {
            c.submit_interrupt_in(input_interrupt(&interrupt), 3, 1_000_000)
                .unwrap()
        } else {
            c.submit_bulk_in(input(&bulk), 3, 1_000_000).unwrap()
        };
        let before = {
            let p = m.lock().unwrap();
            (
                p.io,
                p.device.clone(),
                p.cpu_syncs,
                p.device_syncs,
                p.setup_trace.clone(),
            )
        };
        assert_eq!(c.unconfigure(&id), Err(Error::Busy));
        let foreign = DeviceId {
            owner: Rc::new(()),
            generation: id.generation,
            port: id.port,
        };
        assert_eq!(c.unconfigure(&foreign), Err(Error::Stale));
        let after = {
            let p = m.lock().unwrap();
            (
                p.io,
                p.device.clone(),
                p.cpu_syncs,
                p.device_syncs,
                p.setup_trace.clone(),
            )
        };
        assert_eq!(before, after);
        assert_eq!(c.poll(&current).unwrap().unwrap().data, [0, 1, 2]);
        assert_eq!(m.lock().unwrap().configurations[0], 1);
        c.shutdown().unwrap();
    }
    let m = Arc::new(Mutex::new(Shared::new()));
    let mut c = controller(m.clone());
    let id = c.reset_port(1).unwrap();
    let before = m.lock().unwrap().io;
    assert_eq!(c.unconfigure(&id), Err(Error::Invalid));
    assert_eq!(m.lock().unwrap().io, before);
    c.shutdown().unwrap();
}

#[test]
fn configuration_zero_missing_status_or_observed_value_never_reopens_old_endpoints() {
    for fault in 0..4 {
        let (mut c, m, id, pipes) = attached();
        let epoch = c.ports[0].as_ref().unwrap().configuration;
        {
            let mut p = m.lock().unwrap();
            match fault {
                0 => p.hold_status = Some(9),
                1 => p.configuration_ack = false,
                2 => p.configuration_reply = Some(Vec::new()),
                3 => p.configuration_reply = Some(vec![2]),
                _ => unreachable!(),
            }
        }
        assert_eq!(
            c.unconfigure(&id),
            Err(if fault == 0 {
                Error::Timeout
            } else {
                Error::Invalid
            })
        );
        let device = c.ports[0].as_ref().unwrap();
        assert_eq!(device.configuration, epoch + 1);
        assert_eq!(device.configuration_value, 0);
        assert!(device.endpoints.iter().all(Option::is_none));
        assert!(c.ready().is_err());
        assert_eq!(c.pending.is_some(), fault == 0);
        {
            let p = m.lock().unwrap();
            assert!(p.mapped && p.bme && !p.retired);
            assert_eq!(p.unmapped, 0);
            assert_eq!(p.configurations[0], if fault < 2 { 1 } else { 0 });
        }
        let before = m.lock().unwrap().io;
        assert!(c.submit_bulk_in(input(&pipes), 1, 1_000_000).is_err());
        assert!(c.bulk_pipes(&id).is_err());
        assert_eq!(m.lock().unwrap().io, before);
        // Failed Drop cannot retire either DMA or native resources.
        drop(c);
        let p = m.lock().unwrap();
        assert!(p.mapped && !p.retired);
        assert_eq!(p.unmapped, 0);
    }
}

#[test]
fn configuration_zero_requires_original_drain_and_cache_ownership_before_bus_mutation() {
    for cache in [false, true] {
        let (mut c, m, id, _) = attached();
        let before = m.lock().unwrap().setup_trace.clone();
        let epoch = c.ports[0].as_ref().unwrap().configuration;
        {
            let mut p = m.lock().unwrap();
            p.drain_fail = !cache;
            p.cpu_sync_fail = cache;
        }
        assert!(matches!(c.unconfigure(&id), Err(Error::Dma(_))));
        let p = m.lock().unwrap();
        assert_eq!(p.setup_trace, before);
        assert_eq!(p.configurations[0], 1);
        assert!(p.mapped && p.bme && !p.retired);
        assert_eq!(p.unmapped, 0);
        assert_eq!(c.ports[0].as_ref().unwrap().configuration, epoch);
        assert!(c.pending.is_none());
        assert!(c.ready().is_err());
    }
}
