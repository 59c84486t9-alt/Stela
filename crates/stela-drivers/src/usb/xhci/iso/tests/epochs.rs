// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous identity fixtures.
use super::*;

#[test]
fn retired_ticket_preserves_current_dma() {
    struct NoAccess;
    impl Registers for NoAccess {
        fn read32(&mut self, _: usize) -> u32 {
            panic!("retired isochronous ticket reached MMIO read")
        }
        fn write32(&mut self, _: usize, _: u32) {
            panic!("retired isochronous ticket reached MMIO write")
        }
    }
    for (speed, context_bytes, cfc, already_pending) in
        [(FULL_SPEED, 32, false, false), (HIGH_SPEED, 64, true, true)]
    {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all modeled DMA remains in this live, disjoint allocation.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut previous, _) = addressed_controller(&mut dma, speed, context_bytes, cfc);
        let (mut current, model) = addressed_controller(&mut dma, speed, context_bytes, cfc);
        for c in [&mut previous, &mut current] {
            c.configure(1, &[endpoint(0x81, speed)], None, &mut dma)
                .unwrap();
        }
        let data = dma.allocate(128, 64).unwrap();
        let mut old = previous.submit_iso(1, 3, data.physical(), 32).unwrap();
        let fresh = current.submit_iso(1, 3, data.physical() + 64, 32).unwrap();
        let current_id = current.device_id(1).unwrap();
        // Distinct modeled generations share hardware slot 1. This tests
        // ticket admission, not the separate architectural slot-reuse proof.
        assert_eq!(old.hardware_slot(), fresh.hardware_slot());
        assert_ne!(old.device_id(), current_id);
        assert_eq!(fresh.device_id(), current_id);
        model.borrow_mut().complete(3, 0, SUCCESS, 0);
        if already_pending {
            current.drain();
        }
        let pending = |c: &Controller| {
            c.pending
                .iter()
                .map(|event| (event.parameter, event.status, event.control))
                .collect::<Vec<_>>()
        };
        let pending_before = pending(&current);
        assert_eq!(pending_before.len(), usize::from(already_pending));
        let memory_before = backing.clone();
        let cursor_before = (current.event_index, current.event_cycle);
        let queue_state = |c: &Controller| {
            let endpoint = c.slots[1].as_ref().unwrap().endpoints[3].as_ref().unwrap();
            let queue = endpoint.iso.as_ref().unwrap();
            (
                queue
                    .active
                    .iter()
                    .map(|active| (active.id, active.trb, active.bytes, active.done))
                    .collect::<Vec<_>>(),
                queue.next,
                queue.recovery,
                endpoint.ring.index,
                endpoint.ring.cycle,
            )
        };
        let queue_before = queue_state(&current);
        let registers = core::mem::replace(&mut current.registers, Box::new(NoAccess));
        for (dci, unhealthy) in [(3, false), (u8::MAX, false), (3, true), (u8::MAX, true)] {
            old.dci = dci;
            current.error = unhealthy.then_some(HSE);
            current.command_poisoned = unhealthy;
            let retired = BlockError::Unsupported("xHCI device generation is permanently retired");
            assert_eq!(current.completed_iso(&old), Some(Err(retired)));
            assert_eq!(
                current.device(current_id).unwrap().completed_iso(&old),
                Some(Err(BlockError::Unsupported(
                    "foreign USB isochronous ticket"
                )))
            );
            assert_eq!(current.error, unhealthy.then_some(HSE));
            assert_eq!(current.command_poisoned, unhealthy);
        }
        current.slots[1].as_mut().unwrap().suspended = true;
        assert_eq!(
            current.completed_iso(&old),
            Some(Err(BlockError::Unsupported(
                "xHCI device generation is permanently retired"
            )))
        );
        assert!(matches!(
            current.submit_iso(1, 3, data.physical(), 32),
            Err(BlockError::Unsupported(
                "USB consumer is fenced for device lifecycle"
            ))
        ));
        current.slots[1].as_mut().unwrap().suspended = false;
        assert_eq!(pending(&current), pending_before);
        assert_eq!((current.event_index, current.event_cycle), cursor_before);
        assert_eq!(queue_state(&current), queue_before);
        assert!(backing == memory_before);
        current.registers = registers;
        current.error = None;
        current.command_poisoned = false;
        assert_eq!(
            current.completed_iso(&fresh),
            Some(Ok(IsoCompletion {
                bytes: 32,
                status: IsoStatus::Success
            }))
        );
    }
}

#[test]
fn stale_request_list_identity() {
    let mut backing = vec![0u64; 32 * 1024];
    let base = backing.as_mut_ptr() as u64;
    let mut dma =
    // SAFETY: The stale-list fixture keeps both controller generations and payload
    // allocations within this live stable vector. The independent peers run
    // synchronously and no physical DMA source exists.
    unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
    let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let old = c.test_device_id(1).unwrap();
    c.slot(1).unwrap().generation = identity::next_generation().unwrap();
    struct NoAccess;
    impl Registers for NoAccess {
        fn read32(&mut self, _: usize) -> u32 {
            panic!("stale generation reached MMIO read")
        }
        fn write32(&mut self, _: usize, _: u32) {
            panic!("stale generation reached MMIO write")
        }
    }
    c.registers = Box::new(NoAccess);
    let transfer = c.slot(1).unwrap().endpoints[3].as_ref().unwrap();
    let bytes = transfer.ring.buffer.bytes().to_vec();
    let cursor = (transfer.ring.index, transfer.ring.cycle);
    let commands = model.borrow().seen.clone();
    let device_cursors = model.borrow().cursors.clone();
    for request in [IsoSchedule::Asap, IsoSchedule::AtMicroframe(32)] {
        assert!(
            c.device(old)
                .and_then(|mut device| device.iso_schedule_list(3, request, 2))
                .is_err()
        );
    }
    let transfer = c.slot(1).unwrap().endpoints[3].as_ref().unwrap();
    assert_eq!(transfer.ring.buffer.bytes(), bytes);
    assert_eq!((transfer.ring.index, transfer.ring.cycle), cursor);
    assert!(transfer.iso.as_ref().unwrap().active.is_empty());
    assert_eq!(transfer.iso.as_ref().unwrap().next, None);
    assert_eq!(model.borrow().seen, commands);
    assert_eq!(model.borrow().cursors, device_cursors);
    assert!(model.borrow().active.is_empty());
}

#[test]
fn stale_scheduled_identity() {
    let mut backing = vec![0u64; 32 * 1024];
    let base = backing.as_mut_ptr() as u64;
    let mut dma =
    // SAFETY: This stale-schedule fixture keeps both controller generations and
    // their complete RAM allocations until every ticket check ends; the backing
    // vector is never resized.
    unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
    let (mut c, model) = controller(&mut dma, HIGH_SPEED, 32, true);
    c.configure(1, &[endpoint(0x81, HIGH_SPEED)], None, &mut dma)
        .unwrap();
    let buffer = dma.allocate(4096, 4096).unwrap();
    let old = c.test_device_id(1).unwrap();
    c.slot(1).unwrap().generation = identity::next_generation().unwrap();
    let bytes = c.slot(1).unwrap().endpoints[3]
        .as_ref()
        .unwrap()
        .ring
        .buffer
        .bytes()
        .to_vec();
    let commands = model.borrow().seen.clone();
    assert!(
        c.device(old)
            .and_then(|mut device| device.submit_iso_scheduled(
                3,
                buffer.physical(),
                32,
                IsoSchedule::AtMicroframe(32),
            ))
            .is_err()
    );
    assert_eq!(model.borrow().seen, commands);
    assert!(model.borrow().active.is_empty());
    assert_eq!(
        c.slot(1).unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .ring
            .buffer
            .bytes(),
        bytes
    );
}
