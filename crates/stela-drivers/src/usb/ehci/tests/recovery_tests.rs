// SPDX-License-Identifier: MIT
//! Real engine, BME, requester-drain, mapping and root-isolation recovery peer.
use super::*;

fn current(interrupt: bool) -> (Controller, Arc<Mutex<Shared>>, DeviceId, TransferId) {
    let m = Arc::new(Mutex::new(Shared::new()));
    if interrupt {
        let mut p = m.lock().unwrap();
        for (kind, interval) in [(21, 24), (28, 31)] {
            p.description[kind] = 3;
            p.description[interval] = 4;
        }
    }
    let mut c = controller(m.clone());
    let id = c.reset_port(1).unwrap();
    c.set_address(&id, 7).unwrap();
    let bulk = c.configure(&id, 0).unwrap();
    m.lock().unwrap().mode = Mode::Hold;
    let ticket = if interrupt {
        let pipes = c.interrupt_pipes(&id).unwrap();
        let pipe = pipes
            .iter()
            .find(|pipe| pipe.endpoint_address() & 0x80 != 0)
            .unwrap();
        c.submit_interrupt_in(pipe, 32, 1_000_000).unwrap()
    } else {
        c.submit_bulk_in(input(&bulk), 32, 1_000_000).unwrap()
    };
    (c, m, id, ticket)
}

#[test]
fn actual_controller_recovery_retires_ordinary_and_periodic_dma_and_requires_fresh_root_enumeration()
 {
    for interrupt in [false, true] {
        let (mut c, m, id, old) = current(interrupt);
        let serial = c.next_transfer;
        m.lock().unwrap().words[(OP + STS) / 4] |= FATAL;
        assert!(c.poll(&old).is_err());
        c.recover().unwrap();
        {
            let p = m.lock().unwrap();
            assert_eq!(p.allocations, 2);
            assert_eq!(p.unmapped, 1);
            assert!(p.mapped && p.bme && !p.retired);
            assert_eq!(p.words[(OP + STS) / 4] & (HALT | ASS | PSS | FATAL), 0);
            assert_eq!(p.words[(OP + PORT) / 4] & ENABLE, 0);
            assert_eq!(p.addresses[0], Some(7)); // HCRST never invents USB reset.
        }
        assert!(c.pending.is_none());
        assert!(c.ports.iter().all(Option::is_none));
        assert_eq!(c.next_transfer, serial);
        let before = m.lock().unwrap().io;
        assert!(matches!(c.poll(&old), Err(Error::Stale)));
        assert_eq!(c.cancel(&old), Err(Error::Stale));
        assert!(matches!(c.bulk_pipes(&id), Err(Error::Stale)));
        assert_eq!(m.lock().unwrap().io, before);
        m.lock().unwrap().mode = Mode::Complete;
        let fresh = c.reset_port(1).unwrap();
        assert!(fresh.generation > id.generation);
        c.set_address(&fresh, 7).unwrap();
        c.configure(&fresh, 0).unwrap();
        let ticket = if interrupt {
            let pipes = c.interrupt_pipes(&fresh).unwrap();
            c.submit_interrupt_in(
                pipes
                    .iter()
                    .find(|p| p.endpoint_address() & 0x80 != 0)
                    .unwrap(),
                3,
                1_000_000,
            )
            .unwrap()
        } else {
            let pipes = c.bulk_pipes(&fresh).unwrap();
            c.submit_bulk_in(input(&pipes), 3, 1_000_000).unwrap()
        };
        let before = m.lock().unwrap().io;
        assert_eq!(c.cancel(&old), Err(Error::Stale));
        assert_eq!(m.lock().unwrap().io, before);
        assert_eq!(c.poll(&ticket).unwrap().unwrap().data, [0, 1, 2]);
        c.shutdown().unwrap();
    }
}

#[test]
fn recovery_missing_halt_engine_bme_drain_or_unmap_ack_retains_original_pending_dma() {
    for fault in 0..5 {
        let (mut c, m, id, old) = current(fault % 2 != 0);
        let original = c.arena.as_ref().unwrap().address;
        {
            let mut p = m.lock().unwrap();
            match fault {
                0 => p.halt_ack = false,
                1 => p.stop_ack = false,
                2 => p.bme_clear_ack = false,
                3 => p.drain_fail = true,
                _ => p.unmap_fail = true,
            }
        }
        assert!(c.recover().is_err());
        assert!(c.ready().is_err());
        assert_eq!(c.arena.as_ref().unwrap().address, original);
        assert!(c.pending.is_some());
        {
            let p = m.lock().unwrap();
            assert!(p.mapped && !p.retired);
            assert_eq!(p.bme, fault <= 2);
            assert_eq!(p.allocations, 1);
            assert_eq!(p.unmapped, 0);
        }
        let before = m.lock().unwrap().io;
        assert!(matches!(c.poll(&old), Err(Error::Stale)));
        assert!(matches!(c.interrupt_pipes(&id), Err(Error::Stale)));
        assert_eq!(m.lock().unwrap().io, before);
        {
            let mut p = m.lock().unwrap();
            p.halt_ack = true;
            p.stop_ack = true;
            p.bme_clear_ack = true;
            p.drain_fail = false;
            p.unmap_fail = false;
        }
        // A new explicit attempt must repeat real containment; it never
        // converts the earlier timeout or invalidation failure into success.
        c.recover().unwrap();
        assert_eq!(m.lock().unwrap().unmapped, 1);
        assert_eq!(m.lock().unwrap().allocations, 2);
        c.shutdown().unwrap();
    }
}

#[test]
fn reset_or_fresh_allocation_failure_remains_contained_without_returning_old_transfer_results() {
    for reset_failure in [false, true] {
        let (mut c, m, _, old) = current(false);
        {
            let mut p = m.lock().unwrap();
            if reset_failure {
                p.reset_ack = false;
            } else {
                p.allocate_fail = true;
            }
        }
        assert!(c.recover().is_err());
        assert!(c.pending.is_none() && c.arena.is_none());
        {
            let p = m.lock().unwrap();
            assert!(!p.bme && !p.mapped && !p.retired);
            assert_eq!(p.unmapped, 1);
            assert_eq!(p.allocations, 1);
        }
        assert!(matches!(c.poll(&old), Err(Error::Stale)));
        {
            let mut p = m.lock().unwrap();
            p.reset_ack = true;
            p.allocate_fail = false;
        }
        c.recover().unwrap();
        c.shutdown().unwrap();
    }
}

#[test]
fn recovery_must_isolate_inherited_usb_addresses_and_never_reverse_started_shutdown() {
    let (mut c, m, _, old) = current(false);
    m.lock().unwrap().disable_ack = false;
    assert!(c.recover().is_err());
    assert!(c.ready().is_err());
    assert!(matches!(c.poll(&old), Err(Error::Stale)));
    assert_eq!(m.lock().unwrap().words[(OP + PORT) / 4] & ENABLE, ENABLE);
    {
        let p = m.lock().unwrap();
        assert!(p.mapped && p.bme);
    }
    m.lock().unwrap().disable_ack = true;
    c.recover().unwrap();
    m.lock().unwrap().unmap_fail = true;
    assert!(c.shutdown().is_err());
    let before = m.lock().unwrap().io;
    assert_eq!(c.recover(), Err(Error::Quarantined));
    assert_eq!(m.lock().unwrap().io, before);
}

#[test]
fn recovery_cannot_steal_a_private_suspended_root_or_reset_it_on_resume() {
    let (mut c, m, id, old) = current(false);
    c.cancel(&old).unwrap();
    m.lock().unwrap().mode = Mode::Complete;
    let asleep = c.suspend_port(&id).unwrap();
    let before = m.lock().unwrap().io;
    assert!(matches!(c.recover(), Err(Error::Unsupported(_))));
    assert_eq!(m.lock().unwrap().io, before);
    assert!(c.ready().is_ok());
    c.resume_port(&asleep).unwrap();
    c.shutdown().unwrap();
}

#[test]
fn recovery_uses_original_two_millisecond_halt_and_quarter_second_reset_bounds_and_clears_iaad() {
    for (halt_delay, reset_delay, succeeds) in
        [(500, 100_000, true), (5_000, 0, false), (0, 300_000, false)]
    {
        let (mut c, m, _, old) = current(false);
        let from = m.lock().unwrap().writes.len();
        {
            let mut p = m.lock().unwrap();
            p.words[(OP + CMD) / 4] |= 1 << 6; // Source halt clears stale IAAD.
            p.halt_delay_us = halt_delay;
            p.reset_delay_us = reset_delay;
        }
        assert_eq!(c.recover().is_ok(), succeeds);
        assert!(matches!(c.poll(&old), Err(Error::Stale)));
        {
            let p = m.lock().unwrap();
            let halt = p.writes[from..]
                .iter()
                .find(|(at, _)| *at == OP + CMD)
                .unwrap()
                .1;
            assert_eq!(halt & ((1 << 6) | RUN | ASE | PSE), 0);
            if halt_delay > 2_000 {
                assert!(p.mapped && p.bme);
                assert_eq!(p.unmapped, 0);
            }
            if reset_delay > 250_000 {
                assert!(!p.mapped && !p.bme);
                assert_eq!(p.unmapped, 1);
            }
        }
        if succeeds {
            c.shutdown().unwrap();
        }
    }
}
