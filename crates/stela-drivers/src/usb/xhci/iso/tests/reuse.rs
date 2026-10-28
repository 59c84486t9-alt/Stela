// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous retained-ring reuse fixtures.
use super::*;

struct Exhausted;
impl DmaAllocator for Exhausted {
    fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
        Err(BlockError::NoDmaMemory)
    }
}

#[test]
fn reconfiguration_reuses_ring_cursor() {
    for context_bytes in [32, 64] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma =
        // SAFETY: The reconfiguration fixture keeps this unresized vector alive
        // across every ring-cache reuse. All DMA addresses are CPU pointers into it
        // and all device-peer callbacks are synchronous.
        unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, context_bytes, true);
        let endpoints = [endpoint(1, HIGH_SPEED), endpoint(0x82, HIGH_SPEED)];
        controller.configure(1, &endpoints, None, &mut dma).unwrap();
        let buffer = dma.allocate(4096, 4096).unwrap();
        let original = endpoints.map(|endpoint| {
            controller.slot(1).unwrap().endpoints[usize::from(endpoint.dci())]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .physical()
        });
        let mut old = Vec::new();
        // More than two producer-cycle wraps and many times the native audio
        // reservation's old 8/16-start limit. No allocator reset is permitted.
        for generation in 0..600 {
            let tickets = endpoints.map(|endpoint| {
                controller
                    .submit_iso(1, endpoint.dci(), buffer.physical(), 32)
                    .unwrap()
            });
            // Before this generation's hardware event, an old event must not
            // retire its buffer, including when physical TRB positions recur.
            for ticket in &tickets {
                assert!(controller.completed_iso(ticket).is_none());
            }
            for endpoint in endpoints {
                model.borrow_mut().complete(endpoint.dci(), 0, SUCCESS, 0);
            }
            // Leave successful old events pending while cancellation/drop runs.
            // The acknowledged retirement boundary must drain those events.
            let pointers = endpoints.map(|endpoint| {
                controller.slot(1).unwrap().endpoints[usize::from(endpoint.dci())]
                    .as_ref()
                    .unwrap()
                    .ring
                    .dequeue_pointer()
            });
            controller.deconfigure(1, &endpoints).unwrap();
            for (n, endpoint) in endpoints.iter().enumerate() {
                let cached = controller.slot(1).unwrap().retired_rings[usize::from(endpoint.dci())]
                    .as_ref()
                    .unwrap();
                assert_eq!(cached.buffer.physical(), original[n]);
                assert_eq!(cached.dequeue_pointer(), pointers[n]);
            }
            controller
                .configure(1, &endpoints, None, &mut Exhausted)
                .unwrap();
            for (n, endpoint) in endpoints.iter().enumerate() {
                let ring = &controller.slot(1).unwrap().endpoints[usize::from(endpoint.dci())]
                    .as_ref()
                    .unwrap()
                    .ring;
                assert_eq!(ring.buffer.physical(), original[n]);
                assert_eq!(ring.dequeue_pointer(), pointers[n]);
            }
            old.extend(tickets);
            // Old software tickets remain stale even after physical addresses
            // and cycle bits recur. They cannot consume a new owner's event.
            assert!(controller.completed_iso(&old[0]).unwrap().is_err());
            model.borrow_mut().mfindex = (0x3ff0 + generation * 8) % MICROFRAMES;
        }
        let fresh = controller.submit_iso(1, 2, buffer.physical(), 32).unwrap();
        model.borrow_mut().complete(2, 0, SUCCESS, 0);
        for ticket in &old {
            assert!(controller.completed_iso(ticket).unwrap().is_err());
        }
        assert_eq!(controller.completed_iso(&fresh).unwrap().unwrap().bytes, 32);
    }
}

#[test]
fn allocation_failure_retains_reclaimed_rings() {
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma =
    // SAFETY: This allocation-failure fixture retains the original backing for both
    // reclaimed rings and retry allocations. No callback can outlive the vector or
    // access it concurrently.
    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    let first = endpoint(1, HIGH_SPEED);
    controller.configure(1, &[first], None, &mut dma).unwrap();
    controller.deconfigure(1, &[first]).unwrap();
    let address = controller.slot(1).unwrap().retired_rings[2]
        .as_ref()
        .unwrap()
        .buffer
        .physical();
    let before = model.borrow().seen.len();
    assert_eq!(
        controller.configure(
            1,
            &[first, endpoint(0x82, HIGH_SPEED)],
            None,
            &mut Exhausted
        ),
        Err(BlockError::NoDmaMemory)
    );
    assert_eq!(model.borrow().seen.len(), before);
    assert!(controller.slot(1).unwrap().endpoints[2].is_none());
    assert_eq!(
        controller.slot(1).unwrap().retired_rings[2]
            .as_ref()
            .unwrap()
            .buffer
            .physical(),
        address
    );
    controller
        .configure(1, &[first], None, &mut Exhausted)
        .unwrap();
}

#[test]
fn replacement_failure_quarantines_ring() {
    for silent in [false, true] {
        let mut backing = vec![0u64; 32 * 1024];
        let start = backing.as_mut_ptr() as u64;
        let mut dma =
        // SAFETY: This replacement-failure fixture owns the stable RAM extent
        // throughout rejected/unacknowledged model operations. Quarantine creates no
        // physical DMA or background accessor.
        unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 32, true);
        let endpoint = endpoint(1, HIGH_SPEED);
        controller
            .configure(1, &[endpoint], None, &mut dma)
            .unwrap();
        controller.deconfigure(1, &[endpoint]).unwrap();
        let address = controller.slot(1).unwrap().retired_rings[2]
            .as_ref()
            .unwrap()
            .buffer
            .physical();
        if silent {
            model.borrow_mut().silent = Some(CONFIGURE_ENDPOINT);
        } else {
            model.borrow_mut().fail = Some(CONFIGURE_ENDPOINT);
        }
        assert!(
            controller
                .configure(1, &[endpoint], None, &mut Exhausted)
                .is_err()
        );
        let state = controller.slot(1).unwrap();
        assert!(state.retired_rings[2].is_none());
        let retained = state.endpoints[2].as_ref().unwrap();
        assert_eq!(retained.ring.buffer.physical(), address);
        assert!(retained.poisoned);
        let bytes = retained.ring.buffer.bytes().to_vec();
        let commands = model.borrow().seen.len();
        model.borrow_mut().silent = None;
        model.borrow_mut().fail = None;
        assert!(
            controller
                .configure(1, &[endpoint], None, &mut dma)
                .is_err()
        );
        assert!(controller.deconfigure(1, &[endpoint]).is_err());
        assert_eq!(model.borrow().seen.len(), commands);
        assert_eq!(
            controller.slot(1).unwrap().endpoints[2]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .bytes(),
            bytes
        );
    }
}

#[test]
fn endpoint_owner_preflight() {
    let mut backing = vec![0u64; 32 * 1024];
    let start = backing.as_mut_ptr() as u64;
    let mut dma =
    // SAFETY: This owner-preflight fixture retains all original and foreign ring
    // allocations within its live vector; validation and any model accesses are
    // synchronous.
    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, HIGH_SPEED, 64, true);
    let foreign = endpoint(0x82, HIGH_SPEED);
    let available = endpoint(1, HIGH_SPEED);
    controller.configure(1, &[foreign], None, &mut dma).unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let active = controller.submit_iso(1, 5, buffer.physical(), 32).unwrap();
    let commands = model.borrow().seen.len();
    let bytes = controller.slot(1).unwrap().endpoints[5]
        .as_ref()
        .unwrap()
        .ring
        .buffer
        .bytes()
        .to_vec();
    assert!(
        controller
            .preflight_endpoints(1, &[available, foreign])
            .is_err()
    );
    assert!(
        controller
            .preflight_endpoints(1, &[available, available])
            .is_err()
    );
    assert_eq!(model.borrow().seen.len(), commands);
    assert_eq!(
        controller.slot(1).unwrap().endpoints[5]
            .as_ref()
            .unwrap()
            .ring
            .buffer
            .bytes(),
        bytes
    );
    assert!(
        !controller.slot(1).unwrap().endpoints[5]
            .as_ref()
            .unwrap()
            .poisoned
    );
    model.borrow_mut().complete(5, 0, SUCCESS, 0);
    assert_eq!(
        controller.completed_iso(&active).unwrap().unwrap().bytes,
        32
    );
    controller.preflight_endpoints(1, &[available]).unwrap();
    // Preflight is not a reservation. If another serialized owner claims that
    // DCI before publication, configure must refuse without tearing it down.
    controller
        .configure(1, &[available], None, &mut dma)
        .unwrap();
    let commands = model.borrow().seen.len();
    assert!(
        controller
            .configure(1, &[available], None, &mut dma)
            .is_err()
    );
    assert_eq!(model.borrow().seen.len(), commands);
}
