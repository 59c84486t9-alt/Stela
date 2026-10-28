// SPDX-License-Identifier: GPL-2.0-only
//! realtek dual headphone behavior tests.
use super::*;

#[test]
fn single_route_depop_timing() {
    for (id, coefficient_zero, boot_depop) in [
        (0x10ec0285, 0, true),
        (0x10ec0285, 0x10, false),
        (0x10ec0295, 0, true),
    ] {
        for first in [false, true] {
            for second in [false, true] {
                let mut fixture = Fixture::new();
                let model = realtek_two_sense_model(id, first, second);
                model
                    .borrow_mut()
                    .coefficients
                    .insert((0x20, 0), coefficient_zero);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
                let stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                let began = model.borrow().clock.now_us();
                let report = controller
                    .configure_realtek_alc285_295_headphones(
                        &graph,
                        headphone_binding(&route, stream),
                        None,
                    )
                    .unwrap();
                assert_eq!(report.boot_depop_performed, boot_depop);
                assert_eq!(
                    report.coefficient_zero,
                    if id == 0x10ec0285 {
                        Some(coefficient_zero)
                    } else {
                        None
                    }
                );
                assert_eq!(report.headphone_pins, [4, 0x16]);
                assert_eq!(report.initial_senses[0].present, first);
                assert_eq!(
                    report.initial_senses[1].raw,
                    if second { 0x8000_0123 } else { 0x123 }
                );
                assert_eq!(controller.routes.len(), 1);
                assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
                {
                    let m = model.borrow();
                    let sequences: Vec<_> = m
                        .coefficient_events
                        .iter()
                        .filter(|(node, _, _, _)| *node == 0x58)
                        .collect();
                    if boot_depop {
                        assert_eq!(
                            sequences
                                .iter()
                                .map(|event| (event.1, event.2))
                                .collect::<Vec<_>>(),
                            [
                                (0, 0x1888),
                                (0, 0x7880),
                                (0x0f, 0xf049),
                                (3, 0xa5cf),
                                (0, 0xf888),
                                (0, 0x7888)
                            ]
                        );
                        assert!(sequences[1].3 >= sequences[0].3 + 140_000);
                        assert!(sequences[5].3 >= sequences[4].3 + 100_000);
                        assert_eq!(m.coefficients[&(0x20, 0x38)], 0xab7f);
                        assert_eq!(m.coefficients[&(0x20, 0x0d)], 0xb7ff);
                        assert_eq!(m.coefficients[&(0x20, 0x36)], 0x8aff);
                    } else {
                        assert!(sequences.is_empty());
                    }
                    let sense = m
                        .command_times
                        .iter()
                        .find(|(command, _)| {
                            (command >> 20) & 127 == 4 && (command >> 8) & 0xfff == 0xf09
                        })
                        .unwrap()
                        .1;
                    assert!(sense >= began + if boot_depop { 320_000 } else { 30_000 });
                    let pin16_writes: Vec<_> = m
                        .command_times
                        .iter()
                        .filter(|(command, _)| {
                            (command >> 20) & 127 == 0x16
                                && ((command >> 8) & 0xfff == 0x707 || (command >> 16) & 15 == 3)
                        })
                        .collect();
                    assert_eq!(pin16_writes.len(), if second { 2 } else { 0 });
                    if second {
                        assert!(pin16_writes[0].1 >= sense + 2_000);
                        assert!(pin16_writes[1].1 >= pin16_writes[0].1 + 75_000);
                    }
                    let power: Vec<_> = m
                        .coefficient_events
                        .iter()
                        .filter(|(node, _, _, _)| *node == 0x57)
                        .collect();
                    assert_eq!(power.len(), if first || second { 2 } else { 0 });
                    if first || second {
                        assert_eq!((power[0].2, power[1].2), (0xab01, 0xab04));
                        assert!(power[1].3 >= power[0].3 + 150_000);
                    }
                }
                let second_stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                let reuse = graph.analog_route(Direction::Playback, 0x16, 8).unwrap();
                let before = access_counts(&model);
                assert_eq!(
                    controller.configure_analog_route(
                        &graph,
                        &reuse,
                        second_stream,
                        0,
                        PinOptions::Playback {
                            headphone: false,
                            eapd: None
                        }
                    ),
                    Err(Error::RouteInUse)
                );
                // A pin is not a converter, even while its controls are
                // reserved. Check that typed refusal separately from a
                // genuine attempt to reuse the primary route's owned DAC.
                assert_eq!(
                    controller.bind_converter(&graph, 0x16, second_stream, 0),
                    Err(Error::UnsupportedTopology)
                );
                assert_eq!(
                    controller.bind_converter(&graph, route.converter(), second_stream, 0),
                    Err(Error::RouteInUse)
                );
                assert_eq!(access_counts(&model), before);
                controller.write_pcm(stream, 0, &[0x7c; 256]).unwrap();
                controller.start(stream).unwrap();
                model.borrow_mut().dma_step_bytes = 128;
                advance(&model, 4);
                assert!(controller.status(stream).unwrap().period_completed);
                controller.stop(stream).unwrap();
                assert!(model.borrow().playback.len() >= 256);
                assert!(model.borrow().playback.iter().all(|byte| *byte == 0x7c));
                controller.reinitialize().unwrap();
                assert!(controller.codec_controls.is_empty());
                let before = access_counts(&model);
                assert_eq!(
                    controller.configure_realtek_alc285_295_headphones(
                        &graph,
                        headphone_binding(&route, stream),
                        None
                    ),
                    Err(Error::InvalidCodecGraph)
                );
                assert_eq!(access_counts(&model), before);
            }
        }
    }
}

#[test]
fn optional_second_route() {
    let mut fixture = Fixture::new();
    let model = realtek_two_sense_model(0x10ec0295, true, true);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let first = graph.analog_route(Direction::Playback, 4, 2).unwrap();
    let second = graph.analog_route(Direction::Playback, 0x16, 8).unwrap();
    let playback = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let other = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let mut second_binding = headphone_binding(&second, other);
    second_binding.options = PinOptions::Playback {
        headphone: false,
        eapd: None,
    };
    let report = controller
        .configure_realtek_alc285_295_headphones(
            &graph,
            headphone_binding(&first, playback),
            Some(second_binding),
        )
        .unwrap();
    assert!(report.initial_senses[1].present);
    assert_eq!(controller.routes.len(), 2);
    assert!(controller.codec_controls.is_empty());
    assert_eq!(model.borrow().bindings[&8], (other.tag() << 4));
    assert_eq!(model.borrow().route_controls[&(0x16, 0xf07)], 0x40);
    controller.write_pcm(playback, 0, &[0x31; 256]).unwrap();
    controller.write_pcm(other, 0, &[0x31; 256]).unwrap();
    controller.start(playback).unwrap();
    controller.start(other).unwrap();
    model.borrow_mut().dma_step_bytes = 128;
    advance(&model, 4);
    controller.stop(playback).unwrap();
    controller.stop(other).unwrap();
    assert!(model.borrow().playback.len() >= 512);
    assert!(model.borrow().playback.iter().all(|byte| *byte == 0x31));
    controller.shutdown().unwrap();
}

#[test]
fn failed_depop_requires_reset() {
    for stage in 0..9 {
        let mut fixture = Fixture::new();
        let model = realtek_two_sense_model(0x10ec0295, true, true);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        {
            let mut m = model.borrow_mut();
            if stage == 0 {
                m.depop_delay_us = None;
            } else if stage <= 6 {
                m.coefficient_read_fault = Some(u32::MAX);
                m.coefficient_fault_node = Some(0x58);
                m.coefficient_fault_after_write = true;
                m.coefficient_fault_write_threshold = stage;
            } else if stage == 7 {
                m.coefficient_index_reply = Some((0x58, u32::MAX));
            } else {
                m.reject_coefficient_node = Some(0x58);
            }
        }
        let began = model.borrow().clock.now_us();
        let error = controller
            .configure_realtek_alc285_295_headphones(
                &graph,
                headphone_binding(&route, stream),
                None,
            )
            .unwrap_err();
        assert_eq!(
            error,
            if stage == 0 {
                Error::Timeout(Phase::CodecDepop)
            } else {
                Error::CoefficientRejected {
                    node: 0x58,
                    index: if stage == 3 {
                        0x0f
                    } else if stage == 4 {
                        3
                    } else {
                        0
                    },
                }
            }
        );
        if stage == 0 {
            let elapsed = model.borrow().clock.now_us() - began;
            assert!((1_140_000..1_145_000).contains(&elapsed));
        }
        assert!(controller.routing_failed);
        assert!(controller.routes.is_empty() && controller.codec_controls.is_empty());
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(
            controller.configure_realtek_alc285_295_headphones(
                &graph,
                headphone_binding(&route, stream),
                None
            ),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        if stage == 0 {
            model.borrow_mut().depop_delay_us = Some(0);
            controller.reinitialize().unwrap();
            let fresh = controller.enumerate_codec(0).unwrap();
            let route = fresh.analog_route(Direction::Playback, 4, 2).unwrap();
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
                .configure_realtek_alc285_295_headphones(
                    &fresh,
                    headphone_binding(&route, stream),
                    None,
                )
                .unwrap();
            assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
            controller.start(stream).unwrap();
            model.borrow_mut().stream_stop_stuck = true;
            assert_eq!(
                controller.reinitialize(),
                Err(Error::Timeout(Phase::StreamStop))
            );
            assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
            model.borrow_mut().stream_stop_stuck = false;
            controller.reinitialize().unwrap();
            assert!(controller.codec_controls.is_empty());
        }
    }
}

#[test]
fn pin_capability_validation() {
    for case in 0..5 {
        let mut fixture = Fixture::new();
        let model = realtek_two_sense_model(0x10ec0295, false, case != 4);
        if case >= 2 {
            let mut m = model.borrow_mut();
            m.parameters.insert((0x16, 0x0c), 4); // Sensing only, no output capability.
            m.parameters.insert((0x16, 9), (4 << 20) | 1); // No amplifier.
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        if case == 0 {
            model.borrow_mut().parameters.insert((0x16, 9), u32::MAX);
        }
        if case == 1 {
            model.borrow_mut().parameters.insert((0x16, 0x0c), 0x1d);
        }
        if case == 3 {
            model.borrow_mut().pin_senses.insert(0x16, u32::MAX);
        }
        let result = controller.configure_realtek_alc285_295_headphones(
            &graph,
            headphone_binding(&route, stream),
            None,
        );
        if case < 2 {
            assert_eq!(result, Err(Error::InvalidCodecGraph));
            assert!(model.borrow().coefficient_events.is_empty());
            assert!(!controller.routing_failed);
        } else if case < 4 {
            assert_eq!(result, Err(Error::UnsupportedTopology));
            assert!(controller.routing_failed);
            assert!(
                !model
                    .borrow()
                    .command_times
                    .iter()
                    .any(|(command, _)| (command >> 20) & 127 == 0x16
                        && ((command >> 8) & 0xfff == 0x707 || (command >> 16) & 15 == 3))
            );
        } else {
            assert_eq!(result.unwrap().initial_senses[1].raw, 0x123);
            assert_eq!(controller.codec_controls, [(stream, 0, 0x16)]);
        }
    }
}

#[test]
fn partial_second_route_retains_owner() {
    for conflict in [true, false] {
        let mut fixture = Fixture::new();
        let model = realtek_two_sense_model(0x10ec0295, false, false);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let first = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let second = graph.analog_route(Direction::Playback, 0x16, 8).unwrap();
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let other = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let mut binding = headphone_binding(&second, if conflict { stream } else { other });
        binding.options = PinOptions::Playback {
            headphone: false,
            eapd: None,
        };
        if !conflict {
            let mut m = model.borrow_mut();
            m.reject_route_control = Some(0xf07);
            m.reject_route_node = Some(0x16);
        }
        let before = access_counts(&model);
        let result = controller.configure_realtek_alc285_295_headphones(
            &graph,
            headphone_binding(&first, stream),
            Some(binding),
        );
        if conflict {
            assert_eq!(result, Err(Error::RouteInUse));
            assert_eq!(access_counts(&model), before);
            assert!(!controller.routing_failed);
        } else {
            assert_eq!(result, Err(Error::RouteRejected));
            assert!(controller.routing_failed);
            assert_eq!(controller.routes, [(stream, first.clone())]);
            assert!(controller.codec_controls.is_empty());
            let before = access_counts(&model);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            assert_eq!(controller.start(other), Err(Error::NeedsReset));
            assert_eq!(access_counts(&model), before);
        }
    }
}
