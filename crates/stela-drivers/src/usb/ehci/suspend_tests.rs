// SPDX-License-Identifier: MIT
//! Held-D0 physical root transitions through actual native registers/EP0/DMA.
use super::*;

fn configured(interrupt: bool) -> (Controller, Arc<Mutex<Shared>>, DeviceId) {
    let m = Arc::new(Mutex::new(Shared::new()));
    if interrupt {
        let mut p = m.lock().unwrap();
        // Same original wire inventory, now two ordinary HS interrupt pipes.
        p.description[21] = 3;
        p.description[24] = 4;
        p.description[28] = 3;
        p.description[31] = 4;
    }
    let mut c = controller(m.clone());
    let id = c.reset_port(1).unwrap();
    c.set_address(&id, 7).unwrap();
    c.configure(&id, 0).unwrap();
    (c, m, id)
}
fn read(c: &mut Controller, id: &DeviceId, interrupt: bool) -> TransferId {
    if interrupt {
        let pipes = c.interrupt_pipes(id).unwrap();
        let input = pipes
            .iter()
            .find(|pipe| pipe.endpoint_address() & 0x80 != 0)
            .unwrap();
        c.submit_interrupt_in(input, 3, 1_000_000).unwrap()
    } else {
        let pipes = c.bulk_pipes(id).unwrap();
        c.submit_bulk_in(input(&pipes), 3, 1_000_000).unwrap()
    }
}

#[test]
fn actual_root_suspend_resume_preserves_address_configuration_toggle_and_dma_with_fresh_owners() {
    for interrupt in [false, true] {
        let (mut c, m, mut id) = configured(interrupt);
        let address = c.arena.as_ref().unwrap().address;
        let configuration = c.ports[0].as_ref().unwrap().configuration;
        for _ in 0..3 {
            let ticket = read(&mut c, &id, interrupt);
            assert_eq!(c.poll(&ticket).unwrap().unwrap().data, [0, 1, 2]);
            let toggle = c.ports[0].as_ref().unwrap().endpoints[17].unwrap().toggle;
            m.lock().unwrap().device_status[0] = 3; // Actual self-power + remote wake.
            let before = m.lock().unwrap().setup_trace.len();
            let asleep = c.suspend_port(&id).unwrap();
            {
                let p = m.lock().unwrap();
                assert_eq!(p.device_status[0], 1);
                assert_eq!(
                    &p.setup_trace[before..],
                    &[
                        [0x80, 0, 0, 0, 0, 0, 2, 0],
                        [0, 1, 1, 0, 0, 0, 0, 0],
                        [0x80, 0, 0, 0, 0, 0, 2, 0],
                    ]
                );
                assert_ne!(p.words[(OP + PORT) / 4] & PORT_SUSPEND, 0);
                assert_eq!(p.words[(OP + CMD) / 4] & (ASE | PSE), 0);
                assert_eq!(p.words[(OP + STS) / 4] & (ASS | PSS), 0);
                assert!(p.drained && p.mapped && p.bme);
                assert_eq!(p.addresses[0], Some(7));
            }
            assert!(c.refresh_roots().unwrap().is_empty());
            let io = m.lock().unwrap().io;
            assert!(matches!(c.bulk_pipes(&id), Err(Error::Stale)));
            assert!(matches!(c.interrupt_pipes(&id), Err(Error::Stale)));
            assert!(matches!(c.poll(&ticket), Err(Error::Stale)));
            assert!(c.reset_port(1).is_err());
            assert_eq!(m.lock().unwrap().io, io);
            let fresh = c.resume_port(&asleep).unwrap();
            assert!(fresh.generation > id.generation);
            assert_eq!(c.ports[0].as_ref().unwrap().configuration, configuration);
            assert_eq!(c.ports[0].as_ref().unwrap().address, 7);
            assert_eq!(
                c.ports[0].as_ref().unwrap().endpoints[17].unwrap().toggle,
                toggle
            );
            let before = m.lock().unwrap().io;
            assert!(matches!(c.resume_port(&asleep), Err(Error::Stale)));
            assert!(matches!(c.suspend_port(&id), Err(Error::Stale)));
            assert_eq!(m.lock().unwrap().io, before);
            assert_eq!(c.arena.as_ref().unwrap().address, address);
            assert_eq!(m.lock().unwrap().allocations, 1);
            id = fresh;
        }
        let ticket = read(&mut c, &id, interrupt);
        assert_eq!(c.poll(&ticket).unwrap().unwrap().actual, 3);
        c.shutdown().unwrap();
    }
}

#[test]
fn root_suspend_busy_foreign_and_default_address_owners_have_no_link_effects() {
    let (mut c, m, id) = configured(false);
    let (mut foreign, other, foreign_id) = configured(false);
    let other_io = other.lock().unwrap().io;
    assert!(matches!(foreign.suspend_port(&id), Err(Error::Stale)));
    assert_eq!(other.lock().unwrap().io, other_io);
    let asleep = foreign.suspend_port(&foreign_id).unwrap();
    let io = m.lock().unwrap().io;
    assert!(matches!(c.resume_port(&asleep), Err(Error::Stale)));
    assert_eq!(m.lock().unwrap().io, io);
    foreign.resume_port(&asleep).unwrap();
    foreign.shutdown().unwrap();
    m.lock().unwrap().mode = Mode::Hold;
    let ticket = read(&mut c, &id, false);
    let io = m.lock().unwrap().io;
    assert!(matches!(c.suspend_port(&id), Err(Error::Busy)));
    assert_eq!(m.lock().unwrap().io, io);
    c.cancel(&ticket).unwrap();
    m.lock().unwrap().mode = Mode::Complete;
    let next = c.reset_port(1).unwrap();
    let io = m.lock().unwrap().io;
    assert!(matches!(c.suspend_port(&next), Err(Error::Invalid)));
    assert_eq!(m.lock().unwrap().io, io);
    c.shutdown().unwrap();
}

#[test]
fn root_missing_suspend_remote_wake_and_resume_acknowledgements_retain_original_owner() {
    for fault in 0..5 {
        let (mut c, m, id) = configured(false);
        {
            let mut p = m.lock().unwrap();
            match fault {
                0 => p.suspend_ack = false,
                1 => {
                    p.device_status[0] = 2;
                    p.wake_clear_ack = false;
                }
                2 => p.device_status[0] = 0x8000,
                3 => p.resume_start_ack = false,
                _ => p.resume_clear_ack = false,
            }
        }
        if fault <= 2 {
            assert!(c.suspend_port(&id).is_err());
        } else {
            let asleep = c.suspend_port(&id).unwrap();
            assert!(c.resume_port(&asleep).is_err());
        }
        assert!(c.ready().is_err());
        assert!(c.bulk_pipes(&id).is_err());
        let p = m.lock().unwrap();
        assert!(p.mapped && p.bme && !p.retired);
        assert_eq!(p.allocations, 1);
        assert_eq!(p.unmapped, 0);
        assert!(c.arena.is_some());
        if matches!(fault, 1 | 2) {
            assert!(
                !p.writes
                    .iter()
                    .any(|(at, value)| *at == OP + PORT && value & PORT_SUSPEND != 0)
            );
        }
    }
}

#[test]
fn root_suspend_waits_for_actual_requester_stop_drain_and_cpu_cache_ownership() {
    for fault in 0..3 {
        let (mut c, m, id) = configured(false);
        {
            let mut p = m.lock().unwrap();
            match fault {
                0 => p.stop_ack = false,
                1 => p.drain_fail = true,
                _ => p.cpu_sync_fail = true,
            }
        }
        let before = m.lock().unwrap().writes.len();
        assert!(c.suspend_port(&id).is_err());
        assert!(c.ready().is_err());
        let p = m.lock().unwrap();
        assert!(
            !p.writes[before..]
                .iter()
                .any(|(at, value)| { *at == OP + PORT && value & PORT_SUSPEND != 0 })
        );
        assert!(p.mapped && p.bme && !p.retired);
        assert_eq!(p.unmapped, 0);
        assert_eq!(p.allocations, 1);
    }
}

#[test]
fn suspended_root_change_or_spontaneous_resume_never_revalidates_old_usb_handles() {
    for fault in 0..5 {
        let (mut c, m, id) = configured(false);
        let asleep = c.suspend_port(&id).unwrap();
        {
            let mut p = m.lock().unwrap();
            match fault {
                0 => p.words[(OP + PORT) / 4] &= !CONNECT,
                1 => p.words[(OP + PORT) / 4] |= 1 << 1,
                2 => p.words[(OP + PORT) / 4] &= !PORT_SUSPEND,
                3 => p.words[(OP + PORT) / 4] &= !POWER,
                _ => p.words[(OP + PORT) / 4] |= OVERCURRENT,
            }
        }
        let before = m.lock().unwrap().setup_trace.len();
        assert!(c.resume_port(&asleep).is_err());
        assert!(c.bulk_pipes(&id).is_err());
        assert_eq!(m.lock().unwrap().setup_trace.len(), before);
        assert!(c.ready().is_err());
        assert_eq!(m.lock().unwrap().unmapped, 0);
    }
}

#[test]
fn suspended_root_drop_and_controller_shutdown_never_invent_resume_or_dma_completion() {
    let (mut c, m, id) = configured(false);
    let asleep = c.suspend_port(&id).unwrap();
    let io = m.lock().unwrap().io;
    drop(asleep);
    assert_eq!(m.lock().unwrap().io, io);
    assert!(c.bulk_pipes(&id).is_err());
    // Complete controller shutdown has its own real HALT/BME-clear/drain
    // boundary, so a still-suspended physical root does not prohibit release.
    c.shutdown().unwrap();
    let p = m.lock().unwrap();
    assert_ne!(p.words[(OP + PORT) / 4] & PORT_SUSPEND, 0);
    assert_eq!(p.words[(OP + PORT) / 4] & PORT_RESUME, 0);
    assert!(!p.mapped && !p.bme && p.retired);
}
