// SPDX-License-Identifier: GPL-2.0-only
//! cs4208 behavior tests.
use super::*;

#[test]
fn cs4208_actual_vendor_startup_and_effective_stereo_gain_preserve_raw_graph_with_duplex_pcm() {
    for inherited in [false, true] {
        for converter in [0x18, 0x1b, 0x1c] {
            let mut fixture = Fixture::new();
            let model = cs4208_device(inherited, false);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_cirrus_codec(&graph).unwrap();
            assert_eq!(report.profile, CirrusProfile::Cs4208);
            assert_eq!(report.processing_node, 0x24);
            assert_eq!(report.errata_coefficients_acknowledged, 0);
            assert!(report.shared_pins.is_empty());
            assert_eq!(
                report.coefficients,
                vec![
                    CirrusCoefficient {
                        index: 0x33,
                        value: 1
                    },
                    CirrusCoefficient {
                        index: 0x34,
                        value: 0x1c01
                    }
                ]
            );
            assert_eq!(report.input_amplifiers.len(), 3);
            for amp in &report.input_amplifiers {
                assert_eq!(
                    amp.observed_caps,
                    graph.widget(amp.node).unwrap().input_amplifier.unwrap()
                );
                assert_eq!(amp.effective_caps & 0x7f, 2);
                assert_eq!(amp.effective_caps & !0x7f, amp.observed_caps & !0x7f);
                assert_eq!(amp.effective_channels, 2);
            }
            assert_eq!(graph.widget(0x18).unwrap().channels(), 1);
            assert_eq!(
                model
                    .borrow()
                    .coefficient_events
                    .iter()
                    .map(|(node, index, value, _)| (*node, *index, *value))
                    .collect::<Vec<_>>(),
                vec![(0x24, 0x33, 1), (0x24, 0x34, 0x1c01)]
            );
            assert!(!model.borrow().commands.iter().any(|command| matches!(
                (command >> 8) & 0xfff,
                0x715 | 0x716 | 0x717 | 0x7e7
            ) || (matches!(
                (command >> 20) & 127,
                7 | 8
            ) && (command >> 8)
                & 0xfff
                == 0x705)));
            let output = graph.analog_route(Direction::Playback, 0x10, 2).unwrap();
            let input = graph
                .analog_route(Direction::Capture, 0x0d, converter)
                .unwrap();
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
            if converter == 0x18 {
                let before = access_counts(&model);
                assert_eq!(
                    controller.configure_analog_route(&graph, &input, mic, 1, capture()),
                    Err(Error::InvalidFormat)
                );
                assert_eq!(access_counts(&model), before);
                assert!(!controller.routing_failed);
            }
            controller
                .configure_analog_route(&graph, &output, out, 0, playback())
                .unwrap();
            controller
                .configure_analog_route(&graph, &input, mic, 0, capture())
                .unwrap();
            assert_eq!(model.borrow().route_controls[&(converter, 0xf01)], 1);
            for channel in 0..2 {
                assert_eq!(
                    model.borrow().amplifiers[&(converter, false, 1, channel)],
                    2
                ); // Normal selected input1, no CS420x quirk.
                assert_eq!(model.borrow().amplifiers[&(0x10, true, 0, channel)], 0x3f); // Unrelated HP output range unchanged.
                assert_eq!(model.borrow().amplifiers[&(0x0d, false, 0, channel)], 0x1f);
            }
            assert_eq!(graph.widget(0x18).unwrap().channels(), 1);
            controller.write_pcm(out, 0, &[0x48; 256]).unwrap();
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
                    && model.borrow().playback.iter().all(|byte| *byte == 0x48)
            );
            for pin in [0x0c, 0x0d, 0x10] {
                assert_eq!(model.borrow().route_controls[&(pin, 0xf07)], 0);
            }
        }
    }
}

#[test]
fn cs4208_mono_advertised_input_pin_uses_two_actual_amp_channels_and_checks_right_failure() {
    for right_failure in [false, true] {
        let mut fixture = Fixture::new();
        let model = cs4208_device(false, true);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Capture, 0x18, 0x1b).unwrap();
        let stream = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.configure_analog_route(&graph, &route, stream, 0, capture()),
            Err(Error::UnsupportedTopology)
        );
        assert_eq!(access_counts(&model), before); // Source correction requires explicit owned startup.
        controller.initialize_cirrus_codec(&graph).unwrap();
        if right_failure {
            model.borrow_mut().reject_amplifier_channel = Some((0x18, 1));
        }
        let result = controller.configure_analog_route(&graph, &route, stream, 0, capture());
        if right_failure {
            assert_eq!(result, Err(Error::RouteRejected));
            assert_eq!(model.borrow().amplifiers[&(0x18, false, 0, 1)], 0x82);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            assert_eq!(controller.cirrus_codecs.len(), 1);
            model.borrow_mut().reject_amplifier_channel = None;
            controller.reinitialize().unwrap();
            assert!(controller.cirrus_codecs.is_empty());
        } else {
            result.unwrap();
            for channel in 0..2 {
                assert_eq!(model.borrow().amplifiers[&(0x18, false, 0, channel)], 2);
            }
            controller.fill_capture(stream, 0xa5).unwrap();
            controller.start(stream).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 8);
            controller.stop(stream).unwrap();
            let mut samples = [0; 256];
            controller.read_pcm(stream, 0, &mut samples).unwrap();
            assert_eq!(samples, core::array::from_fn(|index| index as u8));
            controller.shutdown().unwrap();
            assert_eq!(model.borrow().route_controls[&(0x18, 0xf07)], 0);
        }
        assert_eq!(graph.widget(0x18).unwrap().channels(), 1);
    }
}

#[test]
fn cs4208_missing_fixed_input_authority_and_inexpressible_gain_refuse_before_effects() {
    for fault in 0..6 {
        let mut fixture = Fixture::new();
        let model = cs4208_device(false, false);
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.parameters.insert((0, 0), 0x1013_4209);
                }
                1 => {
                    m.parameters.insert((0x24, 0x10), 52 << 8);
                }
                2 => {
                    m.parameters.insert((0x18, 9), (1 << 20) | (1 << 8));
                }
                3 => {
                    m.parameters.insert((0x1b, 0x0d), u32::MAX);
                }
                4 => {
                    m.parameters.insert((0x1c, 0x0d), 0x8000_0100);
                }
                _ => {
                    m.parameters.insert((0x1c, 9), 0xf << 20);
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
fn cs4208_late_index_coefficient_and_ack_failures_retain_real_startup_effects_until_reset() {
    for fault in 0..4 {
        let mut fixture = Fixture::new();
        let model = cs4208_device(false, false);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.reject_route_control = Some(0xf03);
                    m.reject_route_after_write = true;
                }
                1 => m.coefficient_index_failed = true,
                2 => {
                    m.coefficient_read_fault = Some(u32::MAX);
                    m.coefficient_fault_after_write = true;
                    m.coefficient_fault_node = Some(0x24);
                    m.coefficient_fault_write_threshold = 2;
                }
                _ => m.drop_reply_command = Some((0x24 << 20) | 0x41c01),
            }
        }
        assert!(controller.initialize_cirrus_codec(&graph).is_err());
        assert!(controller.routing_failed);
        assert_eq!(controller.cirrus_codecs.len(), 1);
        if fault == 1 {
            assert_eq!(model.borrow().coefficients[&(0x24, 0x33)], 1);
        }
        if fault >= 2 {
            assert_eq!(model.borrow().coefficients[&(0x24, 0x34)], 0x1c01);
        }
        {
            let mut m = model.borrow_mut();
            m.reject_route_control = None;
            m.coefficient_index_failed = false;
            m.coefficient_read_fault = None;
            m.drop_reply_command = None;
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
fn cs4208_live_raw_input_amp_stereo_and_coefficient_changes_quarantine_configured_pcm() {
    for fault in 0..4 {
        let inherited = fault == 1;
        let mut fixture = Fixture::new();
        let model = cs4208_device(inherited, false);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_cirrus_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Capture, 0x0d, 0x18).unwrap();
        let stream = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller
            .configure_analog_route(&graph, &route, stream, 0, capture())
            .unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 | 1 => {
                    m.parameters
                        .insert((if inherited { 1 } else { 0x1b }, 0x0d), 0x8000_1f03);
                }
                2 => {
                    let caps = m.parameters[&(0x18, 9)];
                    m.parameters.insert((0x18, 9), caps | 1);
                }
                _ => {
                    m.coefficients.insert((0x24, 0x34), 0x1c02);
                }
            }
        }
        assert!(controller.poll_pin_sense(&graph, 0x10).is_err());
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
