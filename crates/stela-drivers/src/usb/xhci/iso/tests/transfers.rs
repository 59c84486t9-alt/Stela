// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous transfers fixtures.
use super::*;

#[test]
fn routed_payload_completion() {
    for speed in [FULL_SPEED, HIGH_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS] {
        let mut backing = vec![0u64; 256 * 1024];
        let base = backing.as_mut_ptr() as u64;
        let mut dma =
        // SAFETY: The routed-transfer fixture owns this unresized vector throughout
        // controller, descriptor and payload accesses. The independent
        // device peer runs synchronously on the current thread.
        unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
        let parent_speed = if speed == FULL_SPEED {
            HIGH_SPEED
        } else {
            speed
        };
        let mut hub = hub::model::Node::hub(parent_speed, 2);
        if speed == SUPER_SPEED_PLUS {
            // Original wire fixture used by the native hub SSP positive
            // control: symmetric speed ID 1, one 10-Gbit/s lane each way.
            let mut bos = vec![5, 15, 25, 0, 1, 20, 16, 10, 0, 1, 0, 0, 0, 1, 0, 0, 0];
            for kind in [0u32, 2] {
                bos.extend_from_slice(&(1 | 3 << 4 | kind << 6 | 1 << 14 | 10 << 16).to_le_bytes());
            }
            hub.bos = Some(bos);
        }
        let ports = hub.ports.as_mut().unwrap();
        ports[0].status = 0;
        ports[0].change = 0;
        ports[1].child_speed = speed;
        let nodes = BTreeMap::from([(0, hub), (2, hub::model::Node::leaf(speed))]);
        let (mut c, _) = hub::tests::controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = c.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(devices.len(), 2);
        let child = devices
            .iter()
            .find(|device| device.descriptor[4] != HUB_CLASS)
            .unwrap();
        assert_eq!(child.speed, speed);
        let slot = child.slot;
        let attachment = c.slots[usize::from(slot)].as_ref().unwrap().attachment;
        assert_eq!((attachment.tier, attachment.route), (1, 2));
        let parent = c.original_parent(child.id).unwrap().unwrap();
        assert_eq!(attachment.parent, Some((parent.hardware_slot(), 2)));
        assert_eq!(
            attachment.translator,
            (speed == FULL_SPEED).then_some((parent.hardware_slot(), 2))
        );
        c.set_configuration(slot, 1).unwrap();
        let (mut c, model) = attach_addressed_peer(c, slot, speed, true);
        let mut ep = endpoint(0x81, speed);
        if speed >= SUPER_SPEED {
            ep.max_packet = 1024;
            ep.companion = Some(SuperSpeedCompanion {
                max_burst: 3,
                attributes: 2,
                bytes_per_interval: 12 * 1024,
            });
        }
        c.configure(slot, &[ep], None, &mut dma).unwrap();
        let mut payload = dma.allocate(16 * 1024, 16 * 1024).unwrap();
        payload.bytes_mut().fill(0xa7);
        let length = if speed >= SUPER_SPEED { 12 * 1024 } else { 128 };
        let ticket = c
            .submit_iso(slot, ep.dci(), payload.physical(), length)
            .unwrap();
        assert!(c.completed_iso(&ticket).is_none());
        model.borrow_mut().complete(ep.dci(), 0, SUCCESS, 0);
        assert_eq!(c.completed_iso(&ticket).unwrap().unwrap().bytes, length);
        assert!(payload.bytes()[..length].iter().any(|byte| *byte != 0xa7));
        assert!(c.completed_iso(&ticket).unwrap().is_err());
    }
}

#[test]
fn queued_dma_contexts_and_schedules() {
    for speed in [FULL_SPEED, HIGH_SPEED] {
        for context_bytes in [32, 64] {
            for cfc in [false, true] {
                let mut backing = vec![0u64; 128 * 1024];
                let start = backing.as_mut_ptr() as u64;
                let mut dma =
                    // SAFETY: This speed/context fixture keeps the full stable
                    // vector for every queued ring and payload. All addresses are
                    // identity-mapped CPU pointers and no hardware user can outlive
                    // the scope.
                    unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
                let (mut controller, model) = controller(&mut dma, speed, context_bytes, cfc);
                let endpoints = [endpoint(1, speed), endpoint(0x82, speed)];
                controller.configure(1, &endpoints, None, &mut dma).unwrap();
                let out = dma.allocate(4096, 4096).unwrap();
                let input = dma.allocate(4096, 4096).unwrap();
                // SAFETY: out is the live uniquely allocated payload, with out.len
                // bytes inside the vector. Initialization precedes every
                // submission, so no model peer reads or writes it concurrently.
                unsafe {
                    core::ptr::write_bytes(out.as_ptr(), 0xa5, out.len());
                }
                let mut tickets = Vec::new();
                for n in 0..32 {
                    for endpoint in &endpoints {
                        tickets.push(
                            controller
                                .submit_iso(
                                    1,
                                    endpoint.dci(),
                                    if endpoint.is_in() {
                                        input.physical()
                                    } else {
                                        out.physical()
                                    } + n * 32,
                                    32,
                                )
                                .unwrap(),
                        );
                    }
                }
                assert_eq!(model.borrow().active.len(), 64);
                for dci in [2, 5] {
                    let fields: Vec<u32> = model
                        .borrow()
                        .active
                        .iter()
                        .filter(|(ep, _)| *ep == dci)
                        .map(|(_, td)| td.control)
                        .collect();
                    assert_eq!(fields[0] & SIA, 0);
                    assert_eq!(fields[1] & SIA, if cfc { 0 } else { SIA });
                    for n in 0..32 {
                        model.borrow_mut().complete(
                            dci,
                            0,
                            if n % 2 == 0 { SUCCESS } else { SHORT_PACKET },
                            if n % 2 == 0 { 0 } else { 4 },
                        );
                    }
                }
                for (n, ticket) in tickets.iter().enumerate() {
                    let completion = controller.completed_iso(ticket).unwrap().unwrap();
                    assert_eq!(completion.bytes, if n / 2 % 2 == 0 { 32 } else { 28 });
                    assert!(controller.completed_iso(ticket).unwrap().is_err());
                }
                assert_eq!(model.borrow().output_bytes.len(), 16 * 32 + 16 * 28);
                assert_eq!(&input.bytes()[..32], &[0x5a; 32]);
            }
        }
    }
}
