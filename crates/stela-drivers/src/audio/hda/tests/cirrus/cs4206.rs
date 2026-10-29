// SPDX-License-Identifier: GPL-2.0-only
//! cs4206 behavior tests.
use super::*;

#[test]
fn startup_errata_and_duplex() {
    for id in [0x1013_4206, 0x1013_4207] {
        for shared in 0..8 {
            let mut fixture = Fixture::new();
            let model = device(id, shared);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_cirrus_codec(&graph).unwrap();
            assert_eq!(report.codec_id, id);
            assert_eq!(report.revision_id, 0x0010_0100);
            assert_eq!(report.subsystem_id, 0x1043_8693);
            assert_eq!(report.errata_coefficients_acknowledged, 6);
            let beep =
                7 | if shared & 1 != 0 { 8 } else { 0 } | if shared & 2 != 0 { 16 } else { 0 };
            let spdif = 10 | if shared & 4 != 0 { 0x4000 } else { 0 };
            assert_eq!(
                report.coefficients,
                vec![
                    CirrusCoefficient {
                        index: 3,
                        value: 0x146a
                    },
                    CirrusCoefficient {
                        index: 2,
                        value: 0x000a
                    },
                    CirrusCoefficient {
                        index: 4,
                        value: beep
                    },
                    CirrusCoefficient {
                        index: 1,
                        value: spdif
                    }
                ]
            );
            {
                let m = model.borrow();
                assert!(m.cirrus_errata_complete && !m.cirrus_errata_invalid);
                assert_eq!(m.cirrus_early_coefficient_reads, 0);
                let effects: Vec<_> = m
                    .coefficient_events
                    .iter()
                    .map(|(node, index, value, _)| (*node, *index, *value))
                    .collect();
                assert_eq!(
                    &effects[..6],
                    &[
                        (0x11, 8, 0x9999),
                        (0x11, 0x17, 0xa412),
                        (0x11, 1, 9),
                        (0x11, 0x17, 0x2412),
                        (0x11, 8, 0),
                        (0x11, 1, 8)
                    ]
                );
                assert_eq!(m.cirrus_errata_powered, [true; 2]);
                assert_eq!(m.route_controls[&(0x11, 0xf03)], 1);
                assert!(!m.commands.iter().any(|command| matches!(
                    (command >> 8) & 0xfff,
                    0x715 | 0x716 | 0x717 | 0x7e7
                ))); // No inferred OEM GPIO.
                if id == 0x1013_4207 {
                    assert!(m.power_ready.contains_key(&0x11));
                }
            }
            let before = access_counts(&model);
            assert_eq!(
                controller.initialize_cirrus_codec(&graph),
                Err(Error::RouteInUse)
            );
            assert_eq!(access_counts(&model), before);
            let output = graph.analog_route(Direction::Playback, 9, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 0x0d, 5).unwrap();
            let out = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let mic = controller
                .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
                .unwrap();
            controller
                .configure_analog_route(&graph, &output, out, 0, playback())
                .unwrap();
            controller
                .configure_analog_route(&graph, &input, mic, 0, capture())
                .unwrap();
            assert_eq!(model.borrow().route_controls[&(5, 0xf01)], 1); // Connection1.
            for channel in 0..2 {
                assert_eq!(model.borrow().amplifiers[&(5, false, 0, channel)], 0x1f);
                assert!(
                    !model
                        .borrow()
                        .amplifiers
                        .contains_key(&(5, false, 1, channel))
                );
            }
            assert_eq!(model.borrow().route_controls[&(9, 0xf0c)], 7); // Ordinary explicit EAPD.
            assert!(controller.poll_pin_sense(&graph, 9).unwrap().present);
            assert_eq!(model.borrow().sense_triggers, vec![9]); // Cirrus permits source trigger.
            controller.write_pcm(out, 0, &[0x42; 256]).unwrap();
            controller.fill_capture(mic, 0xa5).unwrap();
            controller.start(out).unwrap();
            controller.start(mic).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 8);
            assert!(controller.status(out).unwrap().period_completed);
            assert!(controller.status(mic).unwrap().period_completed);
            controller.stop(mic).unwrap();
            let mut samples = [0; 256];
            controller.read_pcm(mic, 0, &mut samples).unwrap();
            assert_eq!(samples, core::array::from_fn(|index| index as u8));
            controller.shutdown().unwrap();
            let m = model.borrow();
            assert!(m.playback.len() >= 256 && m.playback.iter().all(|byte| *byte == 0x42));
            for pin in [9, 0x0c, 0x0d, 0x0e, 0x12, 0x15] {
                assert_eq!(m.route_controls[&(pin, 0xf07)], 0);
            }
        }
    }
}

#[test]
fn unsupported_layout_rejected() {
    for fault in 0..8 {
        let mut fixture = Fixture::new();
        let model = device(0x1013_4206, 7);
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.parameters.insert((0, 0), 0x1013_4208);
                }
                1 => {
                    m.parameters.insert((0x11, 9), 0xf << 20);
                }
                2 => {
                    m.parameters.insert((0x11, 0x10), 23 << 8);
                }
                3 => {
                    m.parameters.insert((7, 9), (1 << 20) | 1 | (1 << 9));
                }
                4 => {
                    m.parameters.insert((8, 0x0f), 8);
                }
                5 => {
                    m.parameters.insert((0x12, 9), (4 << 20) | 1);
                }
                6 => {
                    m.pin_defaults.insert(0x15, u32::MAX);
                }
                _ => {
                    m.parameters.insert((0x11, 0x10), u32::MAX);
                }
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let before = model.borrow().commands.len();
        assert!(controller.initialize_cirrus_codec(&graph).is_err());
        assert!(controller.cirrus_codecs.is_empty());
        assert!(!controller.routing_failed);
        assert!(
            model.borrow().commands[before..]
                .iter()
                .all(|command| command & (1 << 19) != 0)
        );
    }
}

#[test]
fn startup_failure_retains_owner() {
    for fault in 0..7 {
        let mut fixture = Fixture::new();
        let model = device(0x1013_4207, 7);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => m.power_error = true,
                1 => {
                    m.reject_route_control = Some(0xf03);
                    m.reject_route_after_write = true;
                }
                2 => m.drop_reply_command = Some((0x11 << 20) | 0x49999),
                3 => m.drop_reply_command = Some((7 << 20) | 0x70500),
                4 => m.coefficient_index_failed = true,
                5 => {
                    m.coefficient_read_fault = Some(u32::MAX);
                    m.coefficient_fault_after_write = true;
                    m.coefficient_fault_node = Some(0x11);
                    m.coefficient_fault_write_threshold = 8;
                }
                _ => m.drop_reply_command = Some((0x11 << 20) | 0x4001f), // Final DMIC/beep RMW effect.
            }
        }
        assert!(controller.initialize_cirrus_codec(&graph).is_err());
        assert!(controller.routing_failed);
        assert_eq!(controller.cirrus_codecs.len(), 1);
        if fault == 2 {
            assert_eq!(model.borrow().coefficients[&(0x11, 8)], 0x9999);
        }
        if fault == 6 {
            assert_eq!(model.borrow().coefficients[&(0x11, 4)], 0x1f);
        }
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_cirrus_codec(&graph),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        {
            let mut m = model.borrow_mut();
            m.power_error = false;
            m.reject_route_control = None;
            m.drop_reply_command = None;
            m.coefficient_index_failed = false;
            m.coefficient_read_fault = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.cirrus_codecs.is_empty());
        assert_eq!(
            controller.initialize_cirrus_codec(&graph),
            Err(Error::InvalidCodecGraph)
        );
    }
}

#[test]
fn live_state_drift_quarantines_routes() {
    for fault in 0..5 {
        let mut fixture = Fixture::new();
        let model = device(0x1013_4206, 7);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_cirrus_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Playback, 9, 2).unwrap();
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
            .configure_cirrus_route(&graph, &route, stream, 0, playback())
            .unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.pin_defaults.insert(0x12, 0x4000_0100);
                }
                1 => {
                    m.parameters.insert((0x11, 0x10), 24 << 8);
                }
                2 => {
                    m.coefficients.insert((0x11, 3), 0x106a);
                }
                3 => {
                    m.route_controls.insert((0x11, 0xf03), 0);
                }
                _ => {
                    m.parameters.insert((0, 2), 0x0010_0200);
                }
            }
        }
        assert!(controller.poll_pin_sense(&graph, 9).is_err());
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        let before = model.borrow().commands.len();
        assert_eq!(controller.shutdown(), Err(Error::NeedsReset));
        assert_eq!(model.borrow().commands.len(), before);
        assert!(controller.stopped);
        assert_eq!(controller.routes.len(), 1);
        controller.reinitialize().unwrap();
        assert!(controller.cirrus_codecs.is_empty());
        assert!(controller.routes.is_empty());
    }
}

#[test]
fn shutdown_failure_still_stops_dma() {
    for stream_failure in [false, true] {
        let mut fixture = Fixture::new();
        let model = device(0x1013_4207, 0);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_cirrus_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Playback, 9, 2).unwrap();
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
            .configure_cirrus_route(&graph, &route, stream, 0, playback())
            .unwrap();
        controller.start(stream).unwrap();
        {
            let mut m = model.borrow_mut();
            if stream_failure {
                m.stream_stop_stuck = true;
            } else {
                m.reject_route_control = Some(0xf07);
            }
        }
        let before = model.borrow().commands.len();
        assert!(controller.shutdown().is_err());
        if stream_failure {
            assert_eq!(model.borrow().commands.len(), before);
            assert!(!controller.stopped);
        } else {
            assert!(controller.stopped);
            assert_eq!(model.borrow().get(CORBCTL, 1) & 2, 0);
            assert_eq!(model.borrow().get(RIRBCTL, 1) & 2, 0);
        }
        assert_eq!(controller.cirrus_codecs.len(), 1);
        {
            let mut m = model.borrow_mut();
            m.stream_stop_stuck = false;
            m.reject_route_control = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.cirrus_codecs.is_empty());
    }
}

#[test]
fn vendor_owners_are_exclusive() {
    for (initial, target) in [(0, 1), (0, 2), (0, 3), (1, 0), (2, 0)] {
        let mut fixture = Fixture::new();
        let model = device(0x1013_4206, 0);
        if initial != 0 {
            let mut m = model.borrow_mut();
            m.cirrus_model = false;
            m.parameters.insert(
                (0, 0),
                if initial == 1 {
                    0x14f1_5069
                } else {
                    0x8384_7690
                },
            );
            if initial == 2 {
                m.parameters.insert((7, 9), (3 << 20) | 1 | (1 << 8));
                m.parameters.insert((7, 0x0e), 1);
                m.connection_words.insert((7, 0), 2);
                m.parameters.insert((8, 9), (4 << 20) | 1);
                m.parameters.insert((8, 0x0c), 0x10 | (1 << 16));
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        match initial {
            0 => {
                controller.initialize_cirrus_codec(&graph).unwrap();
            }
            1 => {
                controller.initialize_conexant_codec(&graph).unwrap();
            }
            _ => {
                controller.initialize_sigmatel_codec(&graph).unwrap();
            }
        }
        model.borrow_mut().parameters.insert(
            (0, 0),
            match target {
                0 => 0x1013_4206,
                1 => 0x14f1_5069,
                2 => 0x8384_7690,
                _ => 0x10ec_0892,
            },
        );
        let new_graph = controller.enumerate_codec(0).unwrap();
        let before = access_counts(&model);
        let result = match target {
            0 => controller.initialize_cirrus_codec(&new_graph).map(|_| ()),
            1 => controller.initialize_conexant_codec(&new_graph).map(|_| ()),
            2 => controller.initialize_sigmatel_codec(&new_graph).map(|_| ()),
            _ => controller.initialize_realtek_common(&new_graph).map(|_| ()),
        };
        assert_eq!(result, Err(Error::RouteInUse));
        assert_eq!(access_counts(&model), before);
        assert_eq!(
            controller.cirrus_codecs.len()
                + controller.sigmatel_codecs.len()
                + controller.conexant_codecs.len(),
            1
        );
    }
}
