use super::*;
use crate::bus::dma::RegionAllocator;
use crate::usb::xhci::model::*;

#[test]
fn unacknowledged_configuration_never_activates_endpoints_or_reuses_poisoned_ep0() {
    for scenario in 0..3 {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive backing outlives controller and hardware model.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
            &mut dma,
            &[
                vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
            ],
        );
        if scenario == 0 {
            model.borrow_mut().halt_transfer = Some(1);
        } else {
            model.borrow_mut().silence_transfer = Some(1);
            if scenario == 2 {
                model.borrow_mut().fail = Some((STOP_ENDPOINT, 11));
            }
        }
        assert!(controller.set_configuration(1, 42).is_err());
        assert_eq!(controller.current_configuration(1), Ok(None));
        let endpoint = fixture_endpoint(3);
        assert!(
            controller
                .configure(1, &[endpoint], None, &mut dma)
                .is_err()
        );
        assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
        let request_count = model.borrow().setup.len();
        model.borrow_mut().halt_transfer = None;
        model.borrow_mut().silence_transfer = None;
        if scenario == 2 {
            let ring = controller.slots[1].as_ref().unwrap().endpoints[1]
                .as_ref()
                .unwrap()
                .ring
                .buffer
                .bytes()
                .to_vec();
            assert!(controller.set_configuration(1, 42).is_err());
            assert_eq!(model.borrow().setup.len(), request_count);
            assert_eq!(
                controller.slots[1].as_ref().unwrap().endpoints[1]
                    .as_ref()
                    .unwrap()
                    .ring
                    .buffer
                    .bytes(),
                ring
            );
        } else {
            controller.set_configuration(1, 42).unwrap();
            assert_eq!(controller.current_configuration(1), Ok(Some(42)));
        }
    }
}

#[test]
fn failed_endpoint_configuration_keeps_rings_without_exposing_or_replacing_them() {
    for missing_completion in [false, true] {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing is live/exclusive through every DMA ring.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
            &mut dma,
            &[
                vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
            ],
        );
        controller.set_configuration(1, 42).unwrap();
        if missing_completion {
            model.borrow_mut().silence = Some(CONFIGURE_ENDPOINT);
        } else {
            model.borrow_mut().fail = Some((CONFIGURE_ENDPOINT, 7));
        }
        let endpoint = fixture_endpoint(3);
        assert!(
            controller
                .configure(1, &[endpoint], None, &mut dma)
                .is_err()
        );
        let transfer = controller.slots[1].as_ref().unwrap().endpoints[3]
            .as_ref()
            .unwrap();
        assert!(!transfer.enabled);
        assert!(transfer.poisoned);
        let address = transfer.ring.buffer.physical();
        let bytes = transfer.ring.buffer.bytes().to_vec();
        let commands = model.borrow().seen.len();
        assert!(controller.submit(1, 3, address, 16).is_err());
        assert!(
            controller
                .configure(1, &[endpoint], None, &mut dma)
                .is_err()
        );
        let transfer = controller.slots[1].as_ref().unwrap().endpoints[3]
            .as_ref()
            .unwrap();
        assert_eq!(transfer.ring.buffer.physical(), address);
        assert_eq!(transfer.ring.buffer.bytes(), bytes);
        assert_eq!(model.borrow().seen.len(), commands);
    }
}

#[test]
fn acknowledged_zero_configuration_returns_to_address_state_without_endpoint_activation() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: backing remains live and exclusive through controller/model use.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
        &mut dma,
        &[
            vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
            vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
            vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
        ],
    );
    controller.set_configuration(1, 42).unwrap();
    for malformed in [
        setup(0, SET_CONFIGURATION, 0x100, 0, 0),
        setup(0, SET_CONFIGURATION, 0, 1, 0),
        setup(0, SET_CONFIGURATION, 0, 0, 1),
    ] {
        assert!(controller.control(1, malformed, &[]).is_err());
    }
    assert_eq!(controller.current_configuration(1), Ok(Some(42)));
    assert_eq!(model.borrow().setup.len(), 1);
    controller.set_configuration(1, 0).unwrap();
    assert_eq!(controller.current_configuration(1), Ok(Some(0)));
    assert_eq!(model.borrow().configuration_value, 0);
    assert!(
        controller
            .configure(1, &[fixture_endpoint(3)], None, &mut dma)
            .is_err()
    );
    assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
    assert!(model.borrow().seen.is_empty());
}

#[test]
fn refused_superspeed_plan_preserves_inventory_without_configuration_or_dma() {
    // SuperSpeed bulk endpoints of 512 bytes, which no fixup changes.
    for streams in [false, true] {
        let mut configuration = vec![
            9, 2, 0, 0, 1, 7, 0, 0x80, 50, 9, 4, 0, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 0, 2, 0,
        ];
        if streams {
            configuration.extend_from_slice(&[6, SS_ENDPOINT_COMPANION, 0, 17, 0, 0]);
        }
        configuration.extend_from_slice(&[7, 5, 2, 2, 0, 2, 0]);
        if streams {
            configuration.extend_from_slice(&[6, SS_ENDPOINT_COMPANION, 0, 0, 0, 0]);
        }
        let total = configuration.len() as u16;
        configuration[2..4].copy_from_slice(&total.to_le_bytes());
        let sanitized = configuration::sanitize(&configuration, SUPER_SPEED).unwrap();
        let mut device = configuration::tests::device(vec![configuration.clone()]);
        device.speed = SUPER_SPEED;
        configuration::select(&mut device).unwrap();
        assert_eq!(device.configuration, sanitized);
        assert_eq!(device.configurations, [configuration]);
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: backing stays exclusive/live throughout model and controller access.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, model) = unconfigured_cancellation_controller_with_configurations(
            &mut dma,
            &[
                vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
            ],
        );
        let input = controller.slots[1].as_ref().unwrap().input.bytes().to_vec();
        let shared = Rc::new(RefCell::new(controller));
        let mut found = Found::default();
        bind(&shared, device, &mut dma, &mut found);
        assert!(found.failures.is_empty());
        assert_eq!(found.unused.len(), 1);
        assert!(model.borrow().setup.is_empty() && model.borrow().seen.is_empty());
        let controller = shared.borrow();
        let slot = controller.slots[1].as_ref().unwrap();
        assert_eq!(slot.input.bytes(), input);
        assert!(slot.endpoints[2..].iter().all(Option::is_none));
        assert_eq!(slot.current_configuration, Some(0));
    }
}

#[test]
fn superspeed_companions_reach_real_32_and_64_byte_controller_contexts() {
    for speed in [SUPER_SPEED, SUPER_SPEED_PLUS] {
        for context in [32, 64] {
            let mut backing = vec![0u64; 128 * 1024];
            let start = backing.as_mut_ptr() as u64;
            // SAFETY: backing outlives every model and controller DMA object.
            let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
            let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[
                    vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
                    vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
                ],
            );
            controller.set_configuration(1, 7).unwrap();
            controller.context_bytes = context;
            let slot = controller.slots[1].as_mut().unwrap();
            slot.speed = speed;
            slot.context[0] = slot.context[0] & !(15 << 20) | u32::from(speed) << 20;
            slot.input = dma.allocate(33 * context, 64).unwrap().into();
            slot._output = dma.allocate(32 * context, 64).unwrap().into();
            model.borrow_mut().output = slot._output.physical();
            model.borrow_mut().context_bytes = context;
            model.borrow_mut().set_state(1, 1);
            controller.dcbaa.write(8, slot._output.physical());
            let endpoints = [
                Endpoint {
                    address: 0x81,
                    attributes: 2,
                    max_packet: 1024,
                    interval: 0,
                    companion: Some(SuperSpeedCompanion {
                        max_burst: 7,
                        attributes: 0,
                        bytes_per_interval: 0,
                    }),
                },
                Endpoint {
                    address: 0x02,
                    attributes: 3,
                    max_packet: 64,
                    interval: 4,
                    companion: Some(SuperSpeedCompanion {
                        max_burst: 3,
                        attributes: 0,
                        bytes_per_interval: 37,
                    }),
                },
            ];
            controller.configure(1, &endpoints, None, &mut dma).unwrap();
            let slot = controller.slots[1].as_ref().unwrap();
            for (ep, expected) in endpoints.iter().zip([
                [0, 1024 << 16 | 7 << 8 | 6 << 3 | 6, 3072],
                [3 << 16, 64 << 16 | 3 << 8 | 3 << 3 | 6, 37 << 16 | 37],
            ]) {
                let dci = usize::from(ep.dci());
                let at = (dci + 1) * context;
                assert_eq!(slot.input.read::<u32>(at), expected[0]);
                assert_eq!(slot.input.read::<u32>(at + 4), expected[1]);
                assert_eq!(slot.input.read::<u32>(at + 16), expected[2]);
                let transfer = slot.endpoints[dci].as_ref().unwrap();
                assert!(transfer.enabled);
                assert_eq!(
                    slot.input.read::<u64>(at + 8) & !15,
                    model.borrow().rings[dci]
                );
                assert_eq!(model.borrow().state(dci), ENDPOINT_RUNNING);
                // All unused/reserved words stay zero at either CSZ.
                assert!(
                    slot.input.bytes()[at + 20..at + context]
                        .iter()
                        .all(|b| *b == 0)
                );
            }
            assert_eq!(model.borrow().seen, [CONFIGURE_ENDPOINT]);
            assert_eq!(model.borrow().configuration_seen_before_endpoints, [7]);
            for ep in &endpoints {
                controller.cancel(1, ep.dci()).unwrap();
            }
        }
    }
}

#[test]
fn invalid_superspeed_companion_refuses_before_any_dma_publication() {
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: backing remains exclusive and live throughout model DMA use.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = unconfigured_cancellation_controller_with_configurations(
        &mut dma,
        &[
            vec![9, 2, 9, 0, 0, 7, 0, 0x80, 50],
            vec![9, 2, 9, 0, 0, 9, 0, 0x80, 50],
            vec![9, 2, 9, 0, 0, 42, 0, 0x80, 50],
        ],
    );
    controller.set_configuration(1, 7).unwrap();
    controller.slots[1].as_mut().unwrap().speed = SUPER_SPEED;
    let input = controller.slots[1].as_ref().unwrap().input.bytes().to_vec();
    let commands = controller.commands.buffer.bytes().to_vec();
    let good = Endpoint {
        address: 0x81,
        attributes: 2,
        max_packet: 1024,
        interval: 0,
        companion: Some(SuperSpeedCompanion {
            max_burst: 7,
            attributes: 0,
            bytes_per_interval: 0,
        }),
    };
    for companion in [
        None,
        Some(SuperSpeedCompanion {
            max_burst: 16,
            attributes: 0,
            bytes_per_interval: 0,
        }),
        Some(SuperSpeedCompanion {
            max_burst: 7,
            attributes: 17,
            bytes_per_interval: 0,
        }),
        Some(SuperSpeedCompanion {
            max_burst: 7,
            attributes: 0,
            bytes_per_interval: 1,
        }),
    ] {
        let mut bad = good;
        bad.address = 2;
        bad.companion = companion;
        // A valid endpoint first must not publish its ring before its invalid peer.
        assert!(
            controller
                .configure(1, &[good, bad], None, &mut dma)
                .is_err()
        );
        let slot = controller.slots[1].as_ref().unwrap();
        assert_eq!(slot.input.bytes(), input);
        assert_eq!(controller.commands.buffer.bytes(), commands);
        assert!(slot.endpoints[3].is_none() && slot.endpoints[4].is_none());
        assert!(model.borrow().seen.is_empty());
    }
    // The acknowledged EP0 lifecycle stays usable after descriptor refusal.
    controller.set_configuration(1, 9).unwrap();
    assert_eq!(controller.current_configuration(1), Ok(Some(9)));
}
