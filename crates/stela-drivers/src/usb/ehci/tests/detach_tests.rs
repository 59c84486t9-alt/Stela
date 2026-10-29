// SPDX-License-Identifier: MIT
//! A physically enabled old USB address must never alias a newly assigned root.
use super::*;

fn two_roots() -> (Controller, Arc<Mutex<Shared>>) {
    let m = Arc::new(Mutex::new(Shared::new()));
    {
        let mut p = m.lock().unwrap();
        p.words[1] = p.words[1] & !15 | 2;
        p.words[(OP + PORT + 4) / 4] = CONNECT | POWER;
    }
    (controller(m.clone()), m)
}

#[test]
fn pe_clear_isolates_old_address_before_real_reuse_and_fresh_bulk_io() {
    let (mut c, m) = two_roots();
    let old = c.reset_port(1).unwrap();
    c.set_address(&old, 7).unwrap();
    let pipes = c.configure(&old, 0).unwrap();
    let prior = c.submit_bulk_in(input(&pipes), 5, 1_000_000).unwrap();
    assert_eq!(c.poll(&prior).unwrap().unwrap().data, [0, 1, 2, 3, 4]);
    let (from, prior_drains, prior_syncs) = {
        let p = m.lock().unwrap();
        (p.writes.len(), p.drains, p.cpu_syncs)
    };
    c.disable_port(&old).unwrap();
    {
        let p = m.lock().unwrap();
        assert_eq!(p.addresses[0], Some(7)); // PE clear is not device reset.
        assert_eq!(p.words[(OP + PORT) / 4] & ENABLE, 0);
        assert_ne!(p.words[(OP + PORT) / 4] & POWER, 0);
        assert_eq!(p.words[(OP + STS) / 4] & (ASS | PSS), 0);
        assert!(p.drained && p.drains > prior_drains && p.cpu_syncs > prior_syncs);
        let writes: Vec<_> = p.writes[from..]
            .iter()
            .filter(|(at, _)| *at == OP + PORT)
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].1 & (ENABLE | PORT_CHANGES | PORT_RESET | PORT_RESUME),
            0
        );
        assert!(p.mapped && p.bme && !p.retired);
        assert_eq!(p.unmapped, 0);
    }
    let fresh = c.reset_port(2).unwrap();
    c.set_address(&fresh, 7).unwrap(); // Old physical7 is still present but PE0.
    let fresh_pipes = c.configure(&fresh, 0).unwrap();
    let current = c.submit_bulk_in(input(&fresh_pipes), 3, 1_000_000).unwrap();
    let before = m.lock().unwrap().io;
    assert_eq!(c.disable_port(&old), Err(Error::Stale));
    assert!(matches!(c.poll(&prior), Err(Error::Stale)));
    assert!(matches!(
        c.submit_bulk_in(input(&pipes), 1, 1_000_000),
        Err(Error::Stale)
    ));
    assert_eq!(m.lock().unwrap().io, before);
    assert_eq!(c.poll(&current).unwrap().unwrap().data, [0, 1, 2]);
    c.shutdown().unwrap();
}

#[test]
fn default_address_is_released_only_after_root_disable_and_requires_fresh_reset() {
    let (mut c, m) = two_roots();
    let old = c.reset_port(1).unwrap();
    assert!(matches!(c.reset_port(2), Err(Error::Busy)));
    c.disable_port(&old).unwrap();
    assert!(c.default_port.is_none());
    assert_eq!(m.lock().unwrap().addresses[0], Some(0));
    let second = c.reset_port(2).unwrap();
    c.set_address(&second, 8).unwrap();
    let new_first = c.reset_port(1).unwrap();
    assert!(new_first.generation > old.generation);
    c.set_address(&new_first, 7).unwrap();
    let pipes = c.configure(&new_first, 0).unwrap();
    let ticket = c
        .submit_bulk_out(output(&pipes), &[1, 2, 3], 1_000_000)
        .unwrap();
    assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 3);
    c.shutdown().unwrap();
}

#[test]
fn disable_preflight_preserves_pending_bulk_periodic_and_private_suspend_owners() {
    for periodic in [false, true] {
        let (mut c, m, id, bulk, interrupt) = periodic_tests::attached_periodic(64, 1, 4);
        let ticket = if periodic {
            c.submit_interrupt_in(periodic_tests::input_interrupt(&interrupt), 3, 1_000_000)
                .unwrap()
        } else {
            c.submit_bulk_in(input(&bulk), 3, 1_000_000).unwrap()
        };
        let before = {
            let p = m.lock().unwrap();
            (p.io, p.device.clone(), p.cpu_syncs, p.device_syncs)
        };
        assert_eq!(c.disable_port(&id), Err(Error::Busy));
        let foreign = DeviceId {
            owner: Rc::new(()),
            generation: id.generation,
            port: id.port,
        };
        assert_eq!(c.disable_port(&foreign), Err(Error::Stale));
        let after = {
            let p = m.lock().unwrap();
            (p.io, p.device.clone(), p.cpu_syncs, p.device_syncs)
        };
        assert_eq!(after, before);
        assert_eq!(c.poll(&ticket).unwrap().unwrap().data, [0, 1, 2]);
        let asleep = c.suspend_port(&id).unwrap();
        let before = m.lock().unwrap().io;
        assert_eq!(c.disable_port(&id), Err(Error::Stale));
        assert_eq!(m.lock().unwrap().io, before);
        c.resume_port(&asleep).unwrap();
        c.shutdown().unwrap();
    }
}

#[test]
fn missing_pe_clear_or_original_dma_ownership_never_frees_reachable_address_namespace() {
    for fault in 0..3 {
        let (mut c, m) = two_roots();
        let old = c.reset_port(1).unwrap();
        {
            let mut p = m.lock().unwrap();
            match fault {
                0 => p.disable_ack = false,
                1 => p.drain_fail = true,
                2 => p.cpu_sync_fail = true,
                _ => unreachable!(),
            }
        }
        assert!(c.disable_port(&old).is_err());
        assert!(c.ready().is_err());
        assert_eq!(c.default_port, Some(1));
        assert!(matches!(c.reset_port(2), Err(Error::Quarantined)));
        let p = m.lock().unwrap();
        assert_ne!(p.words[(OP + PORT) / 4] & ENABLE, 0);
        assert_eq!(p.addresses[0], Some(0));
        assert!(p.mapped && p.bme && !p.retired);
        assert_eq!(p.unmapped, 0);
        if fault != 0 {
            assert!(c.ports[0].is_some());
        }
        drop(p);
        drop(c);
        let p = m.lock().unwrap();
        assert!(p.mapped && !p.retired);
        assert_eq!(p.unmapped, 0);
    }
}
