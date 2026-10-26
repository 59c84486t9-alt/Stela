// SPDX-License-Identifier: MIT
//! Actual periodic frame-list/QH/qTD DMA through the retained requester peer.
use super::*;

fn description(packet: u16, transactions: u16, interval: u8) -> Vec<u8> {
    let mut bytes = DESCRIPTION.to_vec();
    bytes[4] = 2;
    bytes.extend_from_slice(&[9, 4, 1, 0, 2, 0xff, 0, 0, 0]);
    let encoded = packet | (transactions - 1) << 11;
    for address in [0x83, 4] {
        bytes.extend_from_slice(&[
            7,
            5,
            address,
            3,
            encoded as u8,
            (encoded >> 8) as u8,
            interval,
        ]);
    }
    let length = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&length.to_le_bytes());
    bytes
}
pub(super) fn attached_periodic(
    packet: u16,
    transactions: u16,
    interval: u8,
) -> (
    Controller,
    Arc<Mutex<Shared>>,
    DeviceId,
    Vec<BulkPipe>,
    Vec<InterruptPipe>,
) {
    let m = Arc::new(Mutex::new(Shared::new()));
    m.lock().unwrap().description = description(packet, transactions, interval);
    let mut c = controller(m.clone());
    let id = c.reset_port(1).unwrap();
    c.set_address(&id, 7).unwrap();
    let bulk = c.configure(&id, 0).unwrap();
    let interrupt = c.interrupt_pipes(&id).unwrap();
    assert_eq!(interrupt.len(), 2);
    (c, m, id, bulk, interrupt)
}
pub(super) fn input_interrupt(pipes: &[InterruptPipe]) -> &InterruptPipe {
    pipes
        .iter()
        .find(|pipe| pipe.endpoint_address() & 0x80 != 0)
        .unwrap()
}
fn output_interrupt(pipes: &[InterruptPipe]) -> &InterruptPipe {
    pipes
        .iter()
        .find(|pipe| pipe.endpoint_address() & 0x80 == 0)
        .unwrap()
}

#[test]
fn actual_periodic_links_smask_mult_intervals_and_duplex_payloads() {
    for interval in 1..=14 {
        for transactions in 1..=3 {
            let (mut c, m, _, bulk, pipes) = attached_periodic(1024, transactions, interval);
            let payload = 1024 * usize::from(transactions);
            let period = 1u32 << (interval - 1);
            assert_eq!(
                input_interrupt(&pipes).interval_microframes(),
                period as u16
            );
            let read = c
                .submit_interrupt_in(input_interrupt(&pipes), payload, 1_000_000)
                .unwrap();
            {
                let m = m.lock().unwrap();
                assert_eq!(m.words[(OP + CMD) / 4] & (PSE | ASE), PSE);
                assert_eq!(m.words[(OP + STS) / 4] & (PSS | ASS), PSS);
                let mask = match interval {
                    1 => 0xff,
                    2 => 0x55,
                    3 => 0x11,
                    _ => 1,
                };
                assert_eq!(m.u32(8), u32::from(transactions) << 30 | mask);
                let list = m.dma_offset(m.words[(OP + 0x14) / 4], (m.iova >> 32) as u32);
                for frame in 0..1024 {
                    assert_eq!(
                        m.u32(list + frame * 4),
                        if frame % (period as usize / 8).max(1) == 0 {
                            m.iova as u32 | 2
                        } else {
                            1
                        }
                    );
                }
                assert!(m.periodic_services.iter().all(|tick| tick % period == 0));
            }
            let completion = c.poll(&read).unwrap().unwrap();
            assert_eq!(completion.actual, payload);
            assert_eq!(
                completion.data,
                (0..payload).map(|n| (n % 251) as u8).collect::<Vec<_>>()
            );
            assert!(matches!(c.poll(&read), Err(Error::Stale)));
            let bytes = vec![0x37; payload];
            let write = c
                .submit_interrupt_out(output_interrupt(&pipes), &bytes, 1_000_000)
                .unwrap();
            assert_eq!(c.poll(&write).unwrap().unwrap().actual, payload);
            assert_eq!(m.lock().unwrap().received, bytes);
            // Switching back to async uses the same retired arena and never
            // leaves periodic reachable while the bulk QH is rebuilt.
            let read = c.submit_bulk_in(input(&bulk), 17, 1_000_000).unwrap();
            assert_eq!(m.lock().unwrap().words[(OP + CMD) / 4] & (PSE | ASE), ASE);
            assert_eq!(c.poll(&read).unwrap().unwrap().actual, 17);
            c.shutdown().unwrap();
            let m = m.lock().unwrap();
            assert!(!m.mapped && !m.bme && m.retired);
        }
    }
}

#[test]
fn periodic_service_follows_actual_microframe_clock_and_frame_list_wrap() {
    let (mut c, m, _, bulk, pipes) = attached_periodic(32, 1, 5); // 16 microframes.
    {
        let mut m = m.lock().unwrap();
        m.periodic_auto = false;
        m.words[(OP + 0x0c) / 4] = 16377;
    }
    let read = c
        .submit_interrupt_in(input_interrupt(&pipes), 32, 1_000_000)
        .unwrap();
    assert!(matches!(
        c.submit_bulk_in(input(&bulk), 1, 1_000_000),
        Err(Error::Busy)
    ));
    m.lock().unwrap().advance_periodic(6);
    assert!(m.lock().unwrap().periodic_services.is_empty());
    assert!(c.poll(&read).unwrap().is_none());
    m.lock().unwrap().advance_periodic(1); // Actual 14-bit FRINDEX wraps to zero.
    assert_eq!(m.lock().unwrap().periodic_services, [0]);
    assert_eq!(c.poll(&read).unwrap().unwrap().actual, 32);
    c.shutdown().unwrap();
}

#[test]
fn interrupt_short_zero_and_partial_nak_preserve_actual_overlay_toggle() {
    let (mut c, m, _, _, pipes) = attached_periodic(32, 2, 4);
    m.lock().unwrap().short_limit = Some(7);
    let short = c
        .submit_interrupt_in(input_interrupt(&pipes), 64, 1_000_000)
        .unwrap();
    assert_eq!(c.poll(&short).unwrap().unwrap().actual, 7);
    assert!(c.ports[0].as_ref().unwrap().endpoints[19].unwrap().toggle);
    m.lock().unwrap().short_limit = None;
    let zero = c
        .submit_interrupt_out(output_interrupt(&pipes), &[], 1_000_000)
        .unwrap();
    assert_eq!(c.poll(&zero).unwrap().unwrap().actual, 0);
    m.lock().unwrap().mode = Mode::Partial;
    let partial = c
        .submit_interrupt_in(input_interrupt(&pipes), 64, 1_000_000)
        .unwrap();
    let original = c.arena.as_ref().unwrap().address;
    m.lock().unwrap().mode = Mode::Hold; // The next scheduled service NAKs.
    assert!(c.poll(&partial).unwrap().is_none());
    m.lock().unwrap().mode = Mode::Complete;
    assert!(c.poll(&partial).unwrap().is_none()); // Resume the untouched overlay.
    let done = c.poll(&partial).unwrap().unwrap();
    assert_eq!(done.actual, 64);
    assert_eq!(done.data, (0..64).map(|n| n as u8).collect::<Vec<_>>());
    assert_eq!(c.arena.as_ref().unwrap().address, original);
    c.shutdown().unwrap();
}

#[test]
fn periodic_failed_ack_drain_and_cache_ownership_keep_exact_dma_quarantined() {
    for failure in 0..5 {
        let (mut c, m, _, _, pipes) = attached_periodic(64, 1, 4);
        if failure == 0 {
            m.lock().unwrap().start_ack = false;
        }
        let ticket = c.submit_interrupt_in(input_interrupt(&pipes), 32, 1_000_000);
        if failure == 0 {
            assert!(matches!(ticket, Err(Error::Timeout)));
        } else {
            let ticket = ticket.unwrap();
            {
                let mut m = m.lock().unwrap();
                match failure {
                    1 => m.stop_ack = false,
                    2 => m.drain_fail = true,
                    3 => m.cpu_sync_fail = true,
                    _ => m.device_sync_fail = true,
                }
                if failure == 4 {
                    m.mode = Mode::Hold;
                }
            }
            if failure == 4 {
                // Fresh publication must retain the exact pending owner when
                // device-cache ownership cannot be transferred.
                assert!(c.poll(&ticket).unwrap().is_some());
                assert!(
                    c.submit_interrupt_in(input_interrupt(&pipes), 32, 1_000_000)
                        .is_err()
                );
            } else {
                assert!(c.poll(&ticket).is_err());
            }
        }
        assert!(c.ready().is_err());
        let m = m.lock().unwrap();
        assert!(m.mapped && m.bme && !m.retired);
        assert_eq!(m.unmapped, 0);
        assert_eq!(m.allocations, 1);
        assert!(c.arena.is_some());
    }
}

#[test]
fn periodic_cancel_stall_clear_and_stale_pipe_require_actual_acknowledgements() {
    let (mut c, m, id, _, pipes) = attached_periodic(64, 1, 4);
    m.lock().unwrap().mode = Mode::Hold;
    let pending = c
        .submit_interrupt_in(input_interrupt(&pipes), 64, 1_000_000)
        .unwrap();
    c.cancel(&pending).unwrap();
    assert!(matches!(c.poll(&pending), Err(Error::Stale)));
    m.lock().unwrap().mode = Mode::Stall;
    let stalled = c
        .submit_interrupt_in(input_interrupt(&pipes), 64, 1_000_000)
        .unwrap();
    assert!(matches!(c.poll(&stalled), Err(Error::Device(_))));
    assert!(matches!(
        c.submit_interrupt_in(input_interrupt(&pipes), 64, 1_000_000),
        Err(Error::Device(_))
    ));
    m.lock().unwrap().mode = Mode::Complete;
    c.clear_interrupt_halt(input_interrupt(&pipes)).unwrap();
    assert!(
        m.lock()
            .unwrap()
            .setup_trace
            .contains(&[2, 1, 0, 0, 0x83, 0, 0, 0])
    );
    assert!(!c.ports[0].as_ref().unwrap().endpoints[19].unwrap().toggle);
    c.configure(&id, 0).unwrap();
    let current = c.interrupt_pipes(&id).unwrap();
    let fresh = c
        .submit_interrupt_in(input_interrupt(&current), 2, 1_000_000)
        .unwrap();
    let before = {
        let m = m.lock().unwrap();
        (m.io, m.device.clone(), m.cpu_syncs, m.device_syncs)
    };
    assert!(matches!(
        c.submit_interrupt_in(input_interrupt(&pipes), 1, 1_000_000),
        Err(Error::Stale)
    ));
    assert_eq!(
        c.clear_interrupt_halt(input_interrupt(&pipes)),
        Err(Error::Stale)
    );
    assert_eq!(c.cancel(&pending), Err(Error::Stale));
    let after = {
        let m = m.lock().unwrap();
        (m.io, m.device.clone(), m.cpu_syncs, m.device_syncs)
    };
    assert_eq!(before, after);
    assert_eq!(c.poll(&fresh).unwrap().unwrap().actual, 2);
    c.shutdown().unwrap();
}

#[test]
fn malformed_or_unencodable_interrupt_descriptors_and_payloads_refuse_before_publication() {
    for (packet, transactions, interval) in [
        (0, 1, 1),
        (1025, 1, 1),
        (32, 4, 1),
        (32, 1, 0),
        (32, 1, 15),
        (32, 1, 16),
    ] {
        let m = Arc::new(Mutex::new(Shared::new()));
        m.lock().unwrap().description = description(packet, transactions, interval);
        let mut c = controller(m.clone());
        let id = c.reset_port(1).unwrap();
        c.set_address(&id, 7).unwrap();
        assert!(c.configure(&id, 0).is_err());
        assert!(
            !m.lock()
                .unwrap()
                .setup_trace
                .iter()
                .any(|setup| setup[1] == 9)
        );
        assert!(c.interrupt_pipes(&id).unwrap().is_empty());
        assert!(m.lock().unwrap().periodic_services.is_empty());
        c.shutdown().unwrap();
    }
    let (mut c, m, _, _, pipes) = attached_periodic(32, 2, 4);
    let before = m.lock().unwrap().writes.len();
    assert!(matches!(
        c.submit_interrupt_in(input_interrupt(&pipes), 65, 1_000_000),
        Err(Error::Unsupported(_))
    ));
    assert!(
        c.submit_interrupt_out(input_interrupt(&pipes), &[1], 1_000_000)
            .is_err()
    );
    assert_eq!(m.lock().unwrap().writes.len(), before);
    c.shutdown().unwrap();
}
