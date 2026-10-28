// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous cancellation fixtures.
use super::*;

#[test]
fn cancellation_acknowledges_all_intervals_and_stale_events_before_reuse() {
    for failure in [None, Some(STOP_ENDPOINT), Some(SET_DEQUEUE)] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let tickets: Vec<_> = (0..32)
            .map(|n| {
                controller
                    .submit_iso(1, 3, buffer.physical() + n * 32, 32)
                    .unwrap()
            })
            .collect();
        model.borrow_mut().fail = failure;
        let result = controller.cancel(1, 3);
        if failure.is_some() {
            assert!(result.is_err());
            assert!(controller.submit_iso(1, 3, buffer.physical(), 32).is_err());
            assert_eq!(
                controller.slot(1).unwrap().endpoints[3]
                    .as_ref()
                    .unwrap()
                    .iso
                    .as_ref()
                    .unwrap()
                    .active
                    .len(),
                32
            );
            assert_eq!(model.borrow().active.len(), 32);
        } else {
            result.unwrap();
            assert!(controller.pending.is_empty());
            assert!(model.borrow().active.is_empty());
            for ticket in tickets {
                assert!(controller.completed_iso(&ticket).unwrap().is_err());
            }
            controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
        }
    }
}

#[test]
fn occupancy_wrap_schedule_and_descriptor_failures_do_not_overwrite_owned_trbs() {
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    controller
        .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let tickets: Vec<_> = (0..RING_TRBS - 2)
        .map(|_| controller.submit_iso(1, 3, buffer.physical(), 16).unwrap())
        .collect();
    let before = controller.slot(1).unwrap().endpoints[3]
        .as_ref()
        .unwrap()
        .ring
        .address();
    assert!(controller.submit_iso(1, 3, buffer.physical(), 16).is_err());
    assert_eq!(
        controller.slot(1).unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .ring
            .address(),
        before
    );
    for ticket in tickets {
        model.borrow_mut().complete(3, 0, SUCCESS, 0);
        assert_eq!(
            controller.completed_iso(&ticket).unwrap().unwrap().bytes,
            16
        );
    }
    for _ in 0..300 {
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 16).unwrap();
        model.borrow_mut().complete(3, 0, SUCCESS, 0);
        controller.completed_iso(&ticket).unwrap().unwrap();
    }
    // A late TD is still queued; the controller reports the missed interval.
    model.borrow_mut().mfindex = 1024;
    controller.submit_iso(1, 3, buffer.physical(), 16).unwrap();
    assert!(controller.submit(1, 3, buffer.physical(), 16).is_err());
    for speed in [LOW_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS] {
        assert!(Recipe::new(&endpoint(0x81, HIGH_SPEED), speed).is_err());
    }
    let mut endpoint = endpoint(0x81, HIGH_SPEED);
    endpoint.max_packet |= 3 << 11;
    assert!(Recipe::new(&endpoint, HIGH_SPEED).is_err());
    endpoint.max_packet = 1024;
    endpoint.attributes = 0x31;
    assert!(Recipe::new(&endpoint, HIGH_SPEED).is_err());
}
