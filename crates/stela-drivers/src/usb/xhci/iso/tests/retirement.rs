// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous retirement fixtures.
use super::*;

#[test]
fn endpoint_retirement_keeps_or_quarantines_rings() {
    for failure in [
        None,
        Some(CONFIGURE_ENDPOINT),
        Some(STOP_ENDPOINT),
        Some(SET_DEQUEUE),
    ] {
        let mut dma = TestRegion::new(32 * 1024 * 8);
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
        let endpoints = [
            endpoint(1, HIGH_SPEED),
            endpoint(0x82, HIGH_SPEED),
            endpoint(0x83, HIGH_SPEED),
        ];
        controller.configure(1, &endpoints, None, &mut dma).unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let a = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
        let b = controller
            .submit_iso(1, 5, buffer.physical() + 32, 32)
            .unwrap();
        let keep = controller
            .submit_iso(1, 7, buffer.physical() + 64, 32)
            .unwrap();
        let old_ring = controller.slot(1).unwrap().endpoints[2]
            .as_ref()
            .unwrap()
            .ring
            .buffer
            .physical();
        model.borrow_mut().fail = failure;
        let result = controller.deconfigure(1, &endpoints[..2]);
        if failure.is_some() {
            assert!(result.is_err());
            let slot = controller.slot(1).unwrap();
            assert!(slot.endpoints[2].as_ref().unwrap().poisoned);
            assert!(slot.endpoints[5].as_ref().unwrap().poisoned);
            assert!(slot.retired_rings[2].is_none());
            assert!(slot.retired_rings[5].is_none());
            assert!(!slot.endpoints[7].as_ref().unwrap().poisoned);
            assert!(controller.submit_iso(1, 2, buffer.physical(), 32).is_err());
            assert!(
                controller
                    .configure(1, &endpoints[..2], None, &mut dma)
                    .is_err()
            );
        } else {
            result.unwrap();
            assert!(controller.slot(1).unwrap().endpoints[2].is_none());
            assert!(controller.slot(1).unwrap().endpoints[5].is_none());
            assert!(controller.slot(1).unwrap().endpoints[7].is_some());
            controller
                .configure(1, &endpoints[..2], None, &mut dma)
                .unwrap();
            assert_eq!(
                old_ring,
                controller.slot(1).unwrap().endpoints[2]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .physical()
            );
            assert!(controller.completed_iso(&a).unwrap().is_err());
            assert!(controller.completed_iso(&b).unwrap().is_err());
            model.borrow_mut().complete(7, 0, SUCCESS, 0);
            controller.completed_iso(&keep).unwrap().unwrap();
            let fresh = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
            model
                .borrow_mut()
                .event(a.trb, SUCCESS, 2, 0, TRANSFER_EVENT);
            assert!(controller.completed_iso(&fresh).is_none());
            model.borrow_mut().complete(2, 0, SUCCESS, 0);
            controller.completed_iso(&fresh).unwrap().unwrap();
        }
    }
}

#[test]
fn stalled_cancellation_keeps_buffers() {
    for silent in [STOP_ENDPOINT, SET_DEQUEUE] {
        let mut dma = TestRegion::new(32 * 1024 * 8);
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        controller
            .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
            .unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
        model.borrow_mut().silent = Some(silent);
        assert!(controller.cancel(1, 3).is_err());
        // Only an unanswered Stop Endpoint kills the host; Set Dequeue
        // is aborted and the command ring carries on.
        assert_eq!(controller.command_poisoned, silent == STOP_ENDPOINT);
        assert_eq!(
            controller.slot(1).unwrap().endpoints[3]
                .as_ref()
                .unwrap()
                .iso
                .as_ref()
                .unwrap()
                .active
                .len(),
            1
        );
        assert!(controller.completed_iso(&ticket).unwrap().is_err());
    }
    let mut dma = TestRegion::new(32 * 1024 * 8);
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    controller
        .configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let ticket = controller.submit_iso(1, 3, buffer.physical(), 32).unwrap();
    model.borrow_mut().fatal = true;
    assert!(controller.completed_iso(&ticket).unwrap().is_err());
    assert!(controller.cancel(1, 3).is_err());
    assert_eq!(
        controller.slot(1).unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .iso
            .as_ref()
            .unwrap()
            .active
            .len(),
        1
    );
}
