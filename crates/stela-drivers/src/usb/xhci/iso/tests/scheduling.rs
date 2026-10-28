// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous scheduling fixtures.
use super::*;

#[test]
fn scheduled_wrap_and_subframes() {
    for context_bytes in [32, 64] {
        let mut backing = vec![0u64; 32 * 1024];
        let base = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
        let (mut c, model) = controller(&mut dma, HIGH_SPEED, context_bytes, true);
        c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let mut buffer = dma.allocate(4096, 4096).unwrap();
        buffer.bytes_mut().fill(0xa7);
        model.borrow_mut().mfindex = 16_300;
        let id = c.test_device_id(1).unwrap();
        let mut tickets = Vec::new();
        for n in 0..16u16 {
            let target = (16_376 + n) & 0x3fff;
            let ticket = c
                .device(id)
                .unwrap()
                .submit_iso_scheduled(
                    3,
                    buffer.physical() + u64::from(n) * 32,
                    32,
                    IsoSchedule::AtMicroframe(target),
                )
                .unwrap();
            assert_eq!(ticket.schedule(), IsoSchedule::AtMicroframe(target));
            tickets.push(ticket);
        }
        assert!(buffer.bytes().iter().all(|byte| *byte == 0xa7));
        assert_eq!(model.borrow().active.len(), 16);
        for (n, ticket) in tickets.iter().enumerate() {
            assert!(c.completed_iso(ticket).is_none());
            let target = (16_376 + n as u32) & 0x3fff;
            model.borrow_mut().service_at(3, target, SUCCESS);
            assert_eq!(c.completed_iso(ticket).unwrap().unwrap().bytes, 32);
            assert_eq!(&buffer.bytes()[n * 32..(n + 1) * 32], &[0x5a; 32]);
            assert!(c.completed_iso(ticket).unwrap().is_err());
        }
    }
}

#[test]
fn scheduled_window_and_phase_preflight() {
    let mut backing = vec![0u64; 32 * 1024];
    let base = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
    let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    // Real IST=24; at MFINDEX=16368 target 16 has only 32 microframes
    // of notice. Target 33 has an unencodable initial subframe phase.
    for target in [0x4000, u16::MAX, 0x3fe0, 16, 33] {
        assert_schedule_refused(&mut c, &model, buffer.physical(), target);
    }
    model.borrow_mut().mfindex = 0;
    for target in [0, 8, 32, 896 * 8, 1024 * 8, 2047 * 8] {
        assert_schedule_refused(&mut c, &model, buffer.physical(), target);
    }
    // Inclusive final frame of the donor's window, still within one
    // unambiguous future half-cycle. The actual encoded Frame ID is 895.
    let ticket = c
        .submit_iso_scheduled(
            1,
            3,
            buffer.physical(),
            32,
            IsoSchedule::AtMicroframe(895 * 8),
        )
        .unwrap();
    assert_eq!(model.borrow().active[0].1.control >> 20 & 0x7ff, 895);
    for target in [895 * 8, 895 * 8 + 2, 896 * 8] {
        assert_schedule_refused(&mut c, &model, buffer.physical(), target);
    }
    c.cancel(1, 3).unwrap();
    assert!(c.completed_iso(&ticket).unwrap().is_err());

    // Full-speed bInterval=2 means an actual 16-microframe interval.
    let (mut c, model) = controller(&mut dma, FULL_SPEED, 32, true);
    let mut ep = endpoint(0x81, FULL_SPEED);
    ep.interval = 2;
    c.configure(1, &[ep], None, &mut dma).unwrap();
    assert_schedule_refused(&mut c, &model, buffer.physical(), 40);
    let ticket = c
        .submit_iso_scheduled(1, 3, buffer.physical(), 32, IsoSchedule::AtMicroframe(48))
        .unwrap();
    assert_eq!(ticket.schedule(), IsoSchedule::AtMicroframe(48));
    assert_schedule_refused(&mut c, &model, buffer.physical(), 80);
    let next = c
        .submit_iso_scheduled(
            1,
            3,
            buffer.physical() + 32,
            32,
            IsoSchedule::AtMicroframe(64),
        )
        .unwrap();
    assert_eq!(next.schedule(), IsoSchedule::AtMicroframe(64));
    model.borrow_mut().service_at(3, 48, SUCCESS);
    model.borrow_mut().service_at(3, 64, SUCCESS);
    c.completed_iso(&ticket).unwrap().unwrap();
    c.completed_iso(&next).unwrap().unwrap();
}

#[test]
fn late_continuation_and_asap_missed_service() {
    let mut backing = vec![0u64; 32 * 1024];
    let base = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
    let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let first = c
        .submit_iso_scheduled(1, 3, buffer.physical(), 32, IsoSchedule::AtMicroframe(32))
        .unwrap();
    let second = c
        .submit_iso_scheduled(
            1,
            3,
            buffer.physical() + 32,
            32,
            IsoSchedule::AtMicroframe(33),
        )
        .unwrap();
    model.borrow_mut().complete(3, 0, MISSED_SERVICE, 32);
    assert_eq!(
        c.completed_iso(&first).unwrap().unwrap().status,
        IsoStatus::MissedService
    );
    model.borrow_mut().mfindex = 40;
    assert_schedule_refused(&mut c, &model, buffer.physical(), 34);
    let late = c.submit_iso(1, 3, buffer.physical() + 64, 32).unwrap();
    assert_eq!(late.schedule(), IsoSchedule::AtMicroframe(34));
    for ticket in [&second, &late] {
        model.borrow_mut().complete(3, 0, MISSED_SERVICE, 32);
        assert_eq!(
            c.completed_iso(ticket).unwrap().unwrap().status,
            IsoStatus::MissedService
        );
    }
}
