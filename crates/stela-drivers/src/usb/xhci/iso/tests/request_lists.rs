// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous request lists fixtures.
use super::*;

#[test]
fn iso_request_list_wraps_using_retained_interval_and_services_each_native_td() {
    for context_bytes in [32, 64] {
        let mut backing = vec![0u64; 32 * 1024];
        let base = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
        let (mut c, model) = controller(&mut dma, HIGH_SPEED, context_bytes, true);
        let mut ep = endpoint(0x81, HIGH_SPEED);
        ep.interval = 2; // Actual retained recipe: two microframes.
        c.configure(1, &[ep], None, &mut dma).unwrap();
        let mut buffer = dma.allocate(4096, 4096).unwrap();
        buffer.bytes_mut().fill(0xa7);
        model.borrow_mut().mfindex = 16_300;
        let id = c.test_device_id(1).unwrap();
        let requests = c
            .device(id)
            .unwrap()
            .iso_schedule_list(3, IsoSchedule::AtMicroframe(16_376), 8)
            .unwrap();
        assert_eq!(
            requests,
            [16_376, 16_378, 16_380, 16_382, 0, 2, 4, 6].map(IsoSchedule::AtMicroframe)
        );
        assert!(model.borrow().active.is_empty());
        let transfer = c.slot(1).unwrap().endpoints[3].as_ref().unwrap();
        assert_eq!(transfer.ring.index, 0);
        assert!(transfer.iso.as_ref().unwrap().active.is_empty());
        assert_eq!(transfer.iso.as_ref().unwrap().next, None);
        let mut tickets = Vec::new();
        for (n, request) in requests.iter().enumerate() {
            let ticket = c
                .device(id)
                .unwrap()
                .submit_iso_scheduled(3, buffer.physical() + n as u64 * 32, 32, *request)
                .unwrap();
            assert_eq!(ticket.schedule(), *request);
            tickets.push(ticket);
        }
        assert_eq!(model.borrow().active.len(), 8);
        assert!(buffer.bytes().iter().all(|byte| *byte == 0xa7));
        for (n, ticket) in tickets.iter().enumerate() {
            let IsoSchedule::AtMicroframe(target) = requests[n] else {
                unreachable!()
            };
            model.borrow_mut().service_at(3, u32::from(target), SUCCESS);
            assert_eq!(
                c.device(id)
                    .unwrap()
                    .completed_iso(ticket)
                    .unwrap()
                    .unwrap()
                    .bytes,
                32
            );
            assert_eq!(&buffer.bytes()[n * 32..(n + 1) * 32], &[0x5a; 32]);
        }
    }
}

#[test]
fn iso_request_list_refuses_entire_cfc_horizon_phase_and_count_before_publication() {
    let mut backing = vec![0u64; 32 * 1024];
    let base = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
    let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, false);
    c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    // One request is encodable without CFC. Two would require a native
    // continuation, so even the first must remain unpublished on refusal.
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::AtMicroframe(32), 1)
            .unwrap(),
        [IsoSchedule::AtMicroframe(32)]
    );
    assert_list_refused(&mut c, &model, IsoSchedule::AtMicroframe(32), 2);
    assert_list_refused(&mut c, &model, IsoSchedule::AtMicroframe(33), 1);
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::Asap, 2).unwrap(),
        [IsoSchedule::Asap; 2]
    );
    for count in [0, RING_TRBS - 1, usize::MAX] {
        assert_list_refused(&mut c, &model, IsoSchedule::Asap, count);
    }
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::Asap, RING_TRBS - 2)
            .unwrap()
            .len(),
        RING_TRBS - 2
    );

    let (mut c, model) = controller(&mut dma, FULL_SPEED, 64, true);
    c.configure(1, &[endpoint(0x81, FULL_SPEED)], None, &mut dma)
        .unwrap();
    model.borrow_mut().mfindex = 0;
    // Full speed's actual interval is eight microframes. Frame 895 is
    // admissible, while the prospective second request is frame 896.
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::AtMicroframe(895 * 8), 1)
            .unwrap(),
        [IsoSchedule::AtMicroframe(895 * 8)]
    );
    assert_list_refused(&mut c, &model, IsoSchedule::AtMicroframe(895 * 8), 2);
    for start in [0, 8, 32, 41, 0x4000, u16::MAX] {
        assert_list_refused(&mut c, &model, IsoSchedule::AtMicroframe(start), 2);
    }
}

#[test]
fn iso_request_list_uses_retained_next_and_does_not_authorize_later_submission() {
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
    assert_list_refused(&mut c, &model, IsoSchedule::AtMicroframe(32), 2);
    assert_list_refused(&mut c, &model, IsoSchedule::AtMicroframe(34), 2);
    assert_list_refused(&mut c, &model, IsoSchedule::Asap, RING_TRBS - 2);
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::Asap, RING_TRBS - 3)
            .unwrap()
            .len(),
        RING_TRBS - 3
    );
    let requests = c
        .iso_schedule_list(1, 3, IsoSchedule::AtMicroframe(33), 2)
        .unwrap();
    assert_eq!(
        requests,
        [IsoSchedule::AtMicroframe(33), IsoSchedule::AtMicroframe(34)]
    );
    assert_eq!(model.borrow().active.len(), 1);
    model.borrow_mut().mfindex = 40;
    // The list did not preserve the old clock as an admission credential.
    assert_schedule_refused(&mut c, &model, buffer.physical() + 32, 33);
    assert_list_refused(&mut c, &model, requests[0], 2);
    // ASAP remains a request for the original late-TD behavior.
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::Asap, 2).unwrap(),
        [IsoSchedule::Asap; 2]
    );
    let late = c.submit_iso(1, 3, buffer.physical() + 32, 32).unwrap();
    for ticket in [&first, &late] {
        model.borrow_mut().complete(3, 0, MISSED_SERVICE, 32);
        assert_eq!(
            c.completed_iso(ticket).unwrap().unwrap().status,
            IsoStatus::MissedService
        );
    }
}

#[test]
fn iso_request_list_refuses_exact_future_ring_collision_even_with_count_capacity() {
    let mut backing = vec![0u64; 32 * 1024];
    let base = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
    let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    // Hold one terminal result at ring index zero, while collecting the
    // rest. The next two requests cross the Link TRB into that exact slot.
    let retained = c.submit_iso(1, 3, buffer.physical(), 32).unwrap();
    model.borrow_mut().complete(3, 0, SUCCESS, 0);
    for _ in 1..RING_TRBS - 2 {
        let ticket = c.submit_iso(1, 3, buffer.physical() + 32, 32).unwrap();
        model.borrow_mut().complete(3, 0, SUCCESS, 0);
        c.completed_iso(&ticket).unwrap().unwrap();
    }
    assert_eq!(
        c.slot(1).unwrap().endpoints[3].as_ref().unwrap().ring.index,
        RING_TRBS - 2
    );
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::Asap, 1).unwrap(),
        [IsoSchedule::Asap]
    );
    assert_list_refused(&mut c, &model, IsoSchedule::Asap, 2);
    c.completed_iso(&retained).unwrap().unwrap();
    assert_eq!(
        c.iso_schedule_list(1, 3, IsoSchedule::Asap, 2).unwrap(),
        [IsoSchedule::Asap; 2]
    );
}
