// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous admission fixtures.
use super::*;

#[test]
fn descriptor_route_and_submission_preflight() {
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma =
    // SAFETY: This admission fixture keeps the exact unresized vector for all
    // command, endpoint and payload allocations. Rejected descriptors and routes
    // cannot start physical DMA or background work.
    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    let endpoint = endpoint(0x81, HIGH_SPEED);
    controller.slot(1).unwrap().attachment.tier = 1;
    assert!(
        controller
            .configure(1, &[endpoint], None, &mut dma)
            .is_err()
    );
    assert!(model.borrow().seen.is_empty());
    controller.slot(1).unwrap().attachment.tier = 0;
    controller
        .configure(1, &[endpoint], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let commands = model.borrow().seen.len();
    let remaining = dma.remaining();
    assert!(controller.deconfigure(1, &[endpoint, endpoint]).is_err());
    assert_eq!(model.borrow().seen.len(), commands);
    assert!(
        controller
            .submit_iso(1, 3, buffer.physical(), 3073)
            .is_err()
    );
    assert!(
        controller
            .submit_iso(1, 3, buffer.physical().next_multiple_of(65536) - 1, 32)
            .is_err()
    );
    assert_eq!(dma.remaining(), remaining);
    assert!(model.borrow().active.is_empty());
    assert!(controller.clear(1, &endpoint).is_err());
    assert_eq!(model.borrow().seen.len(), commands);
    let ticket = controller.submit_iso(1, 3, buffer.physical(), 0).unwrap();
    assert_eq!(model.borrow().active[0].1.control >> 16 & 15, 0);
    model.borrow_mut().complete(3, 0, SUCCESS, 0);
    assert_eq!(controller.completed_iso(&ticket).unwrap().unwrap().bytes, 0);
}

#[test]
fn xhci_1_0_iso_admission() {
    assert!(Capabilities::new(0x96, 0, 0).admit().is_err());
    for version in [0x100, 0x110, 0x120] {
        Capabilities::new(version, 0, 0).admit().unwrap();
    }
}
