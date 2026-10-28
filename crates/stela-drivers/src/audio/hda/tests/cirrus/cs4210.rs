// SPDX-License-Identifier: GPL-2.0-only
//! cs4210 behavior tests.
use super::*;

#[test]
fn cold_startup_and_duplex() {
    for inherited in [false, true] {
        for raw_steps in [15, 63] {
            let mut fixture = Fixture::new();
            let model = cs4210_device(inherited, raw_steps);
            // The source A1 recipe is unconditional, including a different revision.
            model.borrow_mut().parameters.insert((0, 2), 0x0020_0200);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let output = graph.analog_route(Direction::Playback, 6, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 8, 3).unwrap();
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
            if raw_steps < 31 {
                let before = access_counts(&model);
                assert_eq!(
                    controller.configure_analog_route(&graph, &output, out, 0, cs4210_playback()),
                    Err(Error::UnsupportedTopology)
                );
                assert_eq!(access_counts(&model), before);
            }
            let report = controller.initialize_cirrus_codec(&graph).unwrap();
            assert_eq!(report.profile, CirrusProfile::Cs4210);
            assert_eq!(report.processing_node, 0x0b);
            assert_eq!(report.errata_coefficients_acknowledged, 5);
            assert!(report.input_amplifiers.is_empty() && report.shared_pins.is_empty());
            assert_eq!(report.output_amplifiers.len(), 1);
            let amp = report.output_amplifiers[0];
            assert_eq!(
                amp.observed_caps,
                graph.widget(2).unwrap().output_amplifier.unwrap()
            );
            assert_eq!(amp.effective_caps & 0x7f00, 31 << 8);
            assert_eq!(amp.effective_caps & !0x7f00, amp.observed_caps & !0x7f00);
            assert_eq!(
                (graph.widget(2).unwrap().output_amplifier.unwrap() >> 8) & 127,
                u32::from(raw_steps)
            );
            assert_eq!(
                report.coefficients,
                vec![
                    CirrusCoefficient { index: 1, value: 1 },
                    CirrusCoefficient { index: 2, value: 2 },
                    CirrusCoefficient {
                        index: 3,
                        value: 14
                    }
                ]
            );
            {
                let m = model.borrow();
                assert_eq!(m.cirrus_cs4210_stage, 10);
                assert!(!m.cirrus_cs4210_invalid);
                assert_eq!(m.route_control_writes[&(0x0b, 0xf03)], 2);
                assert_eq!(
                    m.coefficient_events
                        .iter()
                        .map(|(node, index, value, _)| (*node, *index, *value))
                        .collect::<Vec<_>>(),
                    vec![
                        (11, 1, 0x6e00),
                        (11, 1, 1),
                        (11, 2, 2),
                        (11, 3, 14),
                        (11, 6, 0x9999),
                        (11, 10, 0x14cb),
                        (11, 17, 0xa2d0),
                        (11, 26, 0x02a9),
                        (11, 27, 0x1006),
                        (11, 1, 1)
                    ]
                );
                assert_eq!(m.coefficients[&(11, 6)], 0x9999); // No invented closing key.
                assert_eq!(m.pin_defaults[&9], 0xb7a6_003e); // No OEM DMIC rewrite.
                assert!(!m.commands.iter().any(|command| matches!(
                    (command >> 8) & 0xfff,
                    0x715 | 0x716 | 0x717 | 0x7e7
                )));
            }
            controller
                .configure_analog_route(&graph, &output, out, 0, cs4210_playback())
                .unwrap();
            controller
                .configure_cirrus_route(&graph, &input, mic, 0, capture())
                .unwrap();
            assert_eq!(model.borrow().route_controls[&(3, 0xf01)], 1);
            for channel in 0..2 {
                assert_eq!(model.borrow().amplifiers[&(2, true, 0, channel)], 31);
                assert_eq!(model.borrow().amplifiers[&(3, false, 1, channel)], 31);
            }
            controller.write_pcm(out, 0, &[0x39; 256]).unwrap();
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
            assert!(
                model.borrow().playback.len() >= 256
                    && model.borrow().playback.iter().all(|byte| *byte == 0x39)
            );
            for pin in 5..=10 {
                assert_eq!(model.borrow().route_controls[&(pin, 0xf07)], 0);
            }
        }
    }
}

#[test]
fn speaker_boost_preserves_high_bits() {
    for pin in [5, 6] {
        let mut fixture = Fixture::new();
        let model = cs4210_device(false, 63);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_cirrus_codec(&graph).unwrap();
        assert_eq!(
            controller.set_cirrus_cs4210_speaker_boost(&graph, 2),
            Err(Error::UnsupportedTopology)
        );
        let output = graph.analog_route(Direction::Playback, pin, 2).unwrap();
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
            .configure_analog_route(&graph, &output, stream, 0, cs4210_playback())
            .unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.set_cirrus_cs4210_speaker_boost(&graph, 4),
            Err(Error::InvalidFormat)
        );
        assert_eq!(access_counts(&model), before);
        assert!(!controller.routing_failed);
        controller.write_pcm(stream, 0, &[0x72; 256]).unwrap();
        controller.start(stream).unwrap();
        if pin == 5 {
            assert_eq!(
                controller.set_cirrus_cs4210_speaker_boost(&graph, 2),
                Err(Error::UnsupportedTopology)
            );
            assert!(!controller.routing_failed);
        } else {
            for code in 0..4 {
                model
                    .borrow_mut()
                    .coefficients
                    .insert((11, 4), 0xf5a0 | u16::from(code));
                let before = model.borrow().coefficient_events.len();
                let same = controller
                    .set_cirrus_cs4210_speaker_boost(&graph, code)
                    .unwrap();
                assert!(!same.changed);
                assert_eq!(same.gain_centibels, 900 + 300 * u16::from(code));
                assert_eq!(model.borrow().coefficient_events.len(), before);
                let next = (code + 1) & 3;
                let changed = controller
                    .set_cirrus_cs4210_speaker_boost(&graph, next)
                    .unwrap();
                assert!(changed.changed);
                assert_eq!(changed.coefficient, 0xf5a0 | u16::from(next));
                assert_eq!(model.borrow().coefficients[&(11, 4)], changed.coefficient);
                assert_eq!(model.borrow().coefficient_events.len(), before + 1);
            }
        }
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 8);
        assert!(controller.status(stream).unwrap().period_completed);
        controller.shutdown().unwrap();
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x72));
    }
}

#[test]
fn invalid_fixed_controls_rejected() {
    for fault in 0..7 {
        let mut fixture = Fixture::new();
        let model = cs4210_device(false, 63);
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.parameters.insert((0, 0), 0x1013_4213);
                }
                1 => {
                    m.parameters.insert((11, 0x10), 27 << 8);
                }
                2 => {
                    m.parameters.insert((11, 9), 0xf << 20);
                }
                3 => {
                    m.parameters.insert((2, 9), 1);
                }
                4 => {
                    m.parameters.insert((2, 0x12), u32::MAX);
                }
                5 => {
                    m.parameters.insert((3, 9), 0xf << 20);
                }
                _ => {
                    m.pin_defaults.insert(6, u32::MAX);
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
        assert!(model.borrow().coefficient_events.is_empty());
    }
}

#[test]
fn startup_failure_requires_reset() {
    for fault in 0..5 {
        let mut fixture = Fixture::new();
        let model = cs4210_device(false, 63);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.coefficient_read_fault = Some(u32::MAX);
                    m.coefficient_fault_after_write = true;
                    m.coefficient_fault_write_threshold = 10;
                }
                1 => {
                    m.drop_reply_command = Some((11 << 20) | 0x40001);
                    m.drop_reply_min_coefficient_writes = 10;
                }
                2 => {
                    m.reject_route_control = Some(0xf03);
                    m.reject_route_node = Some(11);
                    m.reject_route_after_write = true;
                    m.reject_route_write_threshold = 2;
                }
                3 => {
                    m.drop_reply_command = Some((11 << 20) | 0x41006);
                }
                _ => {
                    m.coefficient_index_reply = Some((11, u32::MAX));
                }
            }
        }
        assert!(controller.initialize_cirrus_codec(&graph).is_err());
        assert_eq!(controller.cirrus_codecs.len(), 1);
        assert!(controller.routing_failed);
        if fault < 2 {
            assert_eq!(model.borrow().cirrus_cs4210_stage, 10);
        }
        if fault == 2 {
            assert_eq!(model.borrow().route_control_writes[&(11, 0xf03)], 2);
        }
        if fault == 3 {
            assert_eq!(model.borrow().coefficients[&(11, 0x1b)], 0x1006);
        }
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_cirrus_codec(&graph),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        {
            let mut m = model.borrow_mut();
            m.coefficient_read_fault = None;
            m.drop_reply_command = None;
            m.reject_route_control = None;
            m.coefficient_index_reply = None;
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
fn live_control_drift_quarantines_routes() {
    for inherited in [false, true] {
        for fault in 0..5 {
            let mut fixture = Fixture::new();
            let model = cs4210_device(inherited, 63);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_cirrus_codec(&graph).unwrap();
            let output = graph.analog_route(Direction::Playback, 6, 2).unwrap();
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
                .configure_analog_route(&graph, &output, stream, 0, cs4210_playback())
                .unwrap();
            {
                let mut m = model.borrow_mut();
                match fault {
                    0 => {
                        m.parameters
                            .insert((if inherited { 1 } else { 2 }, 0x12), 0x8003_3e1f);
                    }
                    1 => {
                        m.pin_defaults.insert(6, 0x9021_0010);
                    }
                    2 => {
                        m.route_controls.insert((11, 0xf03), 0);
                    }
                    3 => {
                        m.coefficients.insert((11, 2), 3);
                    }
                    _ => {
                        m.parameters.insert((2, 9), 1 | (1 << 2));
                    }
                }
            }
            assert!(
                controller
                    .set_cirrus_cs4210_speaker_boost(&graph, 1)
                    .is_err(),
                "inherited={inherited} fault={fault}"
            );
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
        }
    }
}

#[test]
fn speaker_boost_failure_retains_owner() {
    for lost_ack in [false, true] {
        let mut fixture = Fixture::new();
        let model = cs4210_device(false, 63);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_cirrus_codec(&graph).unwrap();
        let output = graph.analog_route(Direction::Playback, 6, 2).unwrap();
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
            .configure_analog_route(&graph, &output, stream, 0, cs4210_playback())
            .unwrap();
        controller.start(stream).unwrap();
        {
            let mut m = model.borrow_mut();
            if lost_ack {
                m.drop_reply_command = Some((11 << 20) | 0x4d5a3);
            } else {
                m.coefficient_read_fault = Some(u32::MAX);
                m.coefficient_fault_after_write = true;
                m.coefficient_fault_write_threshold = 11;
            }
        }
        assert!(
            controller
                .set_cirrus_cs4210_speaker_boost(&graph, 3)
                .is_err()
        );
        assert_eq!(model.borrow().coefficients[&(11, 4)], 0xd5a3);
        assert_eq!(controller.routes.len(), 1);
        assert_eq!(controller.cirrus_codecs.len(), 1);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        {
            let mut m = model.borrow_mut();
            m.drop_reply_command = None;
            m.coefficient_read_fault = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty() && controller.cirrus_codecs.is_empty());
    }
}
