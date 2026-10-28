// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous completion fixtures.
use super::*;

#[test]
fn packet_and_transport_failures() {
    for (code, status) in [
        (23, IsoStatus::MissedService),
        (4, IsoStatus::Transaction),
        (3, IsoStatus::Babble),
        (18, IsoStatus::Bandwidth),
        (31, IsoStatus::BufferOverrun),
    ] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma =
        // SAFETY: The completion-fault fixture retains this stable vector for all
        // allocated rings and payloads. Only synchronous model callbacks access its
        // identity-mapped addresses.
        unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 128).unwrap();
        model.borrow_mut().complete(3, 0, code, 32);
        assert_eq!(
            controller.completed_iso(&ticket).unwrap().unwrap().status,
            status
        );
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 128).unwrap();
        model.borrow_mut().complete(3, 0, SUCCESS, 129);
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
        assert!(controller.submit_iso(1, 3, buffer.physical(), 128).is_err());
        controller.cancel(1, 3).unwrap();
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
    }
}

#[test]
fn ring_xrun_and_missed_service_events() {
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma =
    // SAFETY: This xrun fixture keeps the entire vector alive and unresized while its
    // command, event and payload handles are used; there is no physical DMA or
    // asynchronous model access.
    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    controller
        .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let tickets: Vec<_> = (0..3)
        .map(|n| {
            controller
                .submit_iso(1, 3, buffer.physical() + n * 32, 32)
                .unwrap()
        })
        .collect();
    for code in [RING_UNDERRUN, RING_OVERRUN] {
        model.borrow_mut().event(0, code, 3, 0, TRANSFER_EVENT);
        assert!(controller.completed_iso(&tickets[0]).is_none());
    }
    // Without a TD pointer the next event decides how many TDs were missed.
    model
        .borrow_mut()
        .event(0, MISSED_SERVICE, 3, 0, TRANSFER_EVENT);
    assert!(controller.completed_iso(&tickets[0]).is_none());
    model.borrow_mut().complete(3, 1, SUCCESS, 0);
    let missed = IsoCompletion {
        bytes: 0,
        status: IsoStatus::MissedService,
    };
    assert_eq!(controller.completed_iso(&tickets[0]).unwrap(), Ok(missed));
    assert_eq!(
        controller
            .completed_iso(&tickets[1])
            .unwrap()
            .unwrap()
            .bytes,
        32
    );
    assert!(controller.completed_iso(&tickets[2]).is_none());
    // An xrun while TDs are being skipped skips exactly one.
    model
        .borrow_mut()
        .event(0, MISSED_SERVICE, 3, 0, TRANSFER_EVENT);
    model
        .borrow_mut()
        .event(0, RING_OVERRUN, 3, 0, TRANSFER_EVENT);
    assert_eq!(controller.completed_iso(&tickets[2]).unwrap(), Ok(missed));
    controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
}

#[test]
fn incompatible_completions_retain_tickets() {
    for code in [6, 22, 36, 99] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma =
        // SAFETY: This incompatible-event fixture retains its own stable RAM extent
        // through all ticket checks; malformed events cannot create a hardware or
        // background user of that memory.
        unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
        let other = controller
            .submit_iso(1, 3, buffer.physical() + 32, 32)
            .unwrap();
        if code == 6 || code == 22 {
            model.borrow_mut().complete(3, 0, code, 0);
        } else {
            model.borrow_mut().event(0, code, 3, 0, TRANSFER_EVENT);
        }
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
        assert_eq!(
            controller.slot(1).unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .iso
                .as_ref()
                .unwrap()
                .active
                .len(),
            2
        );
        assert!(controller.completed_iso(&other).unwrap().is_err());
        assert!(
            controller
                .submit_iso(1, 3, buffer.physical() + 64, 32)
                .is_err()
        );
        if code == 22 {
            let n = model.borrow().seen.len();
            assert!(controller.cancel(1, 3).is_err());
            assert_eq!(model.borrow().seen.len(), n);
        } else {
            controller.cancel(1, 3).unwrap();
            assert!(model.borrow().active.is_empty());
            assert!(controller.completed_iso(&ticket).unwrap().is_err());
            controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
            if code == 6 {
                assert!(
                    model
                        .borrow()
                        .seen
                        .iter()
                        .any(|(kind, _)| *kind == RESET_ENDPOINT)
                );
            }
        }
    }
}
