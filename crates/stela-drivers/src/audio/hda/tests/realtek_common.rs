// SPDX-License-Identifier: GPL-2.0-only
//! realtek common behavior tests.
use super::*;

#[test]
fn family_coefficient_masks() {
    for (id, expected) in [
        (0x10ec0887, &[(10, 0xfbff)][..]),
        (0x10ec0892, &[(4, 0x7fff), (7, 0xffdf)][..]),
        (0x10ec0897, &[(4, 0x7fff), (7, 0xffdf)][..]),
        (0x10ec0900, &[(7, 0xfffd)][..]),
        (0x10ec1220, &[(7, 0xfffd)][..]),
        (0x10ec1168, &[(10, 0xfbff), (7, 0xfffd)][..]),
    ] {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(id);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_realtek_common(&graph).unwrap();
        assert_eq!(report.codec_id, id);
        assert_eq!(report.revision_id, graph.revision_id);
        assert_eq!(report.subsystem_id, 0x10438693);
        assert_eq!(report.coefficients.len(), expected.len());
        for (change, &(index, value)) in report.coefficients.iter().zip(expected) {
            assert_eq!(
                (change.index, change.previous, change.current),
                (index, u16::MAX, value)
            );
            assert_eq!(model.borrow().coefficients[&(0x20, index)], value);
        }
        assert_eq!(model.borrow().coefficient_writes, expected.len());
        assert!(model.borrow().power_ready.contains_key(&1));
        assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 5); //No EAPD/pin/GPIO enable.
        let again = controller.initialize_realtek_common(&graph).unwrap();
        assert!(
            again
                .coefficients
                .iter()
                .all(|change| change.previous == change.current)
        );
        assert_eq!(model.borrow().coefficient_writes, expected.len());
        let endpoint = graph
            .analog_endpoints(Direction::Playback, stereo())
            .unwrap()
            .remove(0);
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        controller
            .configure_analog_route(
                &graph,
                &endpoint.route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: Some(true),
                },
            )
            .unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_realtek_common(&graph),
            Err(Error::RouteInUse)
        );
        assert_eq!(access_counts(&model), before);
        controller.write_pcm(stream, 0, &[0x5a; 256]).unwrap();
        controller.start(stream).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 8);
        assert!(controller.status(stream).unwrap().period_completed);
        controller.stop(stream).unwrap();
        assert!(model.borrow().playback.len() >= 256);
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x5a));
        controller.shutdown().unwrap();
    }
}

#[test]
fn stale_graph_rejected() {
    for fault in 0..8 {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(0x10ec0887);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let mut graph = controller.enumerate_codec(0).unwrap();
        match fault {
            0 => graph.vendor_id = 0x10ec0256,
            1 => {
                model.borrow_mut().parameters.insert((0, 0), 0x10ec0256);
            }
            2 => {
                model.borrow_mut().parameters.insert((0, 2), 0x10001);
            }
            3 => {
                model.borrow_mut().parameters.insert((0x20, 9), 1 << 6);
            }
            4 => {
                model.borrow_mut().parameters.insert((1, 4), (2 << 16) | 6);
            }
            5 => {
                model.borrow_mut().parameters.insert((1, 0x0f), 0);
            }
            6 => {
                controller.reinitialize().unwrap();
            }
            7 => {
                graph.groups[0].power_states = Some(0);
            }
            _ => unreachable!(),
        }
        let before = model.borrow().commands.len();
        assert!(controller.initialize_realtek_common(&graph).is_err());
        assert!(
            model.borrow().commands[before..]
                .iter()
                .all(|command| ((*command >> 16) & 15) >= 8)
        );
        assert!(model.borrow().coefficient_indexes.is_empty());
        assert!(!controller.routing_failed);
    }
}

#[test]
fn running_dma_blocks_configuration() {
    for uncertain in [false, true] {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(0x10ec0887);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        controller.start(stream).unwrap();
        if uncertain {
            model.borrow_mut().stream_stop_stuck = true;
            assert!(matches!(
                controller.stop(stream),
                Err(Error::Timeout(Phase::StreamStop))
            ));
        }
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_realtek_common(&graph),
            Err(if uncertain {
                Error::NeedsReset
            } else {
                Error::StreamRunning
            })
        );
        assert_eq!(access_counts(&model), before);
    }
}

#[test]
fn failed_controls_require_reset() {
    for fault in 0..6 {
        let mut fixture = Fixture::new();
        let model = realtek_desktop_model(0x10ec0887);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        match fault {
            0 => model.borrow_mut().coefficient_index_failed = true,
            1 => model.borrow_mut().coefficient_read_fault = Some(u32::MAX),
            2 => model.borrow_mut().coefficient_read_fault = Some(0x1ffff),
            3 => model.borrow_mut().reject_coefficient_write = true,
            4 => {
                model.borrow_mut().coefficient_read_fault = Some(u32::MAX);
                model.borrow_mut().coefficient_fault_after_write = true;
            }
            5 => model.borrow_mut().power_stuck = true,
            _ => unreachable!(),
        }
        assert_eq!(
            controller.initialize_realtek_common(&graph).unwrap_err(),
            if fault == 5 {
                Error::Timeout(Phase::CodecPower)
            } else {
                Error::CoefficientRejected {
                    node: 0x20,
                    index: 10,
                }
            }
        );
        assert!(controller.routing_failed);
        assert_eq!(
            model.borrow().coefficient_writes,
            usize::from(fault == 3 || fault == 4)
        );
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(
            controller.initialize_realtek_common(&graph),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        {
            let mut m = model.borrow_mut();
            m.coefficient_index_failed = false;
            m.coefficient_read_fault = None;
            m.reject_coefficient_write = false;
            m.power_stuck = false;
        }
        controller.reinitialize().unwrap();
        let fresh = controller.enumerate_codec(0).unwrap();
        controller.initialize_realtek_common(&fresh).unwrap();
    }
}
