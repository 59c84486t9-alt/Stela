// SPDX-License-Identifier: GPL-2.0-only
//! analog routes behavior tests.
use super::*;

#[test]
fn firmware_pin_candidates_are_real_format_checked_paths_without_electrical_inference() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    model.borrow_mut().pin_defaults.insert(5, 0x01a1_9020);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let before = access_counts(&model);
    let output = graph
        .analog_endpoints(Direction::Playback, stereo())
        .unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].route.nodes(), &[4, 7, 6, 2]);
    assert_eq!(output[0].configuration.device(), PinDevice::LineOut);
    assert_eq!(output[0].configuration.connection(), PinConnection::Jack);
    assert_eq!(output[0].configuration.association(), 1);
    let input = graph
        .analog_endpoints(Direction::Capture, stereo())
        .unwrap();
    assert_eq!(input.len(), 1);
    assert_eq!(input[0].route.nodes(), &[3, 5]);
    assert_eq!(input[0].configuration.device(), PinDevice::Microphone);
    assert_eq!(input[0].configuration.color(), 9);
    assert_eq!(input[0].configuration.connector(), 1);
    assert_eq!(input[0].configuration.location(), 1);
    assert!(matches!(
        graph.analog_endpoints(
            Direction::Capture,
            PcmFormat {
                rate: 192_000,
                ..stereo()
            }
        ),
        Err(Error::UnsupportedTopology)
    ));
    assert_eq!(access_counts(&model), before);
    let mut changed = graph.clone();
    changed.groups[0]
        .widgets
        .iter_mut()
        .find(|widget| widget.node == 4)
        .unwrap()
        .pin_default = Some(0x4000_0000);
    assert!(matches!(
        changed.analog_endpoints(Direction::Playback, stereo()),
        Err(Error::UnsupportedTopology)
    ));
    let metadata = PinConfiguration { raw: u32::MAX };
    assert_eq!(metadata.device(), PinDevice::Other);
    assert_eq!(metadata.sequence(), 15);
    assert!(metadata.no_presence_detection());
}

#[test]
fn polled_pin_sense_uses_real_verbs_trigger_and_full_width_measurement_without_routing_writes() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    model.borrow_mut().parameters.insert((4, 0x0c), 0x1001f);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    for value in [0, 0x8000_0020, u32::MAX] {
        model.borrow_mut().pin_senses.insert(4, value);
        let sense = controller.poll_pin_sense(&graph, 4).unwrap();
        assert_eq!(sense.raw, value);
        assert_eq!(sense.present, value & (1 << 31) != 0);
        assert_eq!(
            sense.impedance_code,
            if value == u32::MAX {
                None
            } else {
                Some(value & 0x7fff_ffff)
            }
        );
    }
    let m = model.borrow();
    assert_eq!(m.sense_triggers, [4, 4, 4]);
    assert!(m.power_ready.is_empty());
    assert!(m.amplifiers.is_empty());
    assert_eq!(m.route_controls.len(), 1); //Only initial model EAPD, no routing.
    drop(m);
    let mut no_detect = graph.clone();
    no_detect.groups[0]
        .widgets
        .iter_mut()
        .find(|widget| widget.node == 4)
        .unwrap()
        .pin_default = Some(0x0101_4110);
    let before = access_counts(&model);
    assert_eq!(
        controller.poll_pin_sense(&no_detect, 4),
        Err(Error::UnsupportedTopology)
    );
    assert_eq!(access_counts(&model), before);
    controller.reinitialize().unwrap();
    let before = access_counts(&model);
    assert_eq!(
        controller.poll_pin_sense(&graph, 4),
        Err(Error::InvalidCodecGraph)
    );
    assert_eq!(access_counts(&model), before);
}

#[test]
fn analog_routes_program_real_command_rings_power_mixers_pins_and_both_directions() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
    let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
    assert_eq!(output.nodes(), &[4, 7, 6, 2]);
    assert_eq!(input.nodes(), &[3, 5]);
    let playback = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let capture = controller
        .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
        .unwrap();
    controller
        .configure_analog_route(
            &graph,
            &output,
            playback,
            0,
            PinOptions::Playback {
                headphone: true,
                eapd: Some(true),
            },
        )
        .unwrap();
    controller
        .configure_analog_route(
            &graph,
            &input,
            capture,
            0,
            PinOptions::Capture {
                vref: Vref::EightyPercent,
            },
        )
        .unwrap();
    let m = model.borrow();
    assert_eq!(m.route_controls[&(4, 0xf07)], 0xc0);
    assert_eq!(m.route_controls[&(4, 0xf0c)], 7);
    assert_eq!(m.route_controls[&(5, 0xf07)], 0x24);
    assert_eq!(m.route_controls[&(7, 0xf01)], 0);
    for channel in 0..2 {
        assert_eq!(m.amplifiers[&(2, true, 0, channel)], 0x1f);
        assert_eq!(m.amplifiers[&(6, false, 0, channel)], 0x1f);
        assert_eq!(m.amplifiers[&(6, false, 1, channel)], 0x9f);
        assert_eq!(m.amplifiers[&(5, false, 0, channel)], 0x1f);
    }
    assert!(m.power_ready.contains_key(&1));
    assert!(m.power_ready.contains_key(&2));
    assert!(
        m.commands
            .iter()
            .filter(|command| (**command >> 8) & 0xfff == 0xf05)
            .count()
            > 3
    );
    assert_eq!(m.bindings[&2], playback.tag() << 4);
    assert_eq!(m.bindings[&3], capture.tag() << 4);
}

#[test]
fn analog_route_preflight_refuses_unsupported_electrical_caps_before_any_verb() {
    for failure in 0..7 {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let mut graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let playback = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let mut options = PinOptions::Playback {
            headphone: false,
            eapd: None,
        };
        match failure {
            0 => {
                options = PinOptions::Playback {
                    headphone: true,
                    eapd: None,
                };
                graph.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 4)
                    .unwrap()
                    .pin_capabilities = Some(0x10);
            }
            1 => {
                options = PinOptions::Playback {
                    headphone: false,
                    eapd: Some(true),
                };
                graph.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 4)
                    .unwrap()
                    .pin_capabilities = Some(0x10);
            }
            2 => graph.groups[0].power_states = Some(0),
            3 => {
                graph.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 6)
                    .unwrap()
                    .input_amplifier = Some(0x1f1f)
            }
            4 => {
                graph.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 6)
                    .unwrap()
                    .output_amplifier = Some(0x8000_0001)
            }
            5 => {
                graph.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 7)
                    .unwrap()
                    .capabilities |= 1 << 13
            }
            _ => {
                options = PinOptions::Capture {
                    vref: Vref::HighImpedance,
                }
            }
        }
        let count = model.borrow().commands.len();
        assert!(
            controller
                .configure_analog_route(&graph, &route, playback, 0, options)
                .is_err()
        );
        assert_eq!(model.borrow().commands.len(), count);
        assert!(!controller.routing_failed);
    }
}

#[test]
fn analog_route_cycles_digital_and_cross_group_endpoints_refuse_explicitly() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    for variant in 0..4 {
        let mut altered = graph.clone();
        match variant {
            0 => {
                altered.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 2)
                    .unwrap()
                    .capabilities |= 1 << 9
            }
            1 => {
                altered.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 6)
                    .unwrap()
                    .connections = vec![4, 7];
                altered.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 7)
                    .unwrap()
                    .connections = vec![6];
            }
            2 => {
                altered.groups[0]
                    .widgets
                    .iter_mut()
                    .find(|w| w.node == 4)
                    .unwrap()
                    .connections = vec![3]
            }
            _ => {
                let removed = altered.groups[0].widgets.remove(0);
                let mut extra = altered.groups[0].clone();
                extra.node = 8;
                extra.widgets = vec![removed];
                altered.groups.push(extra);
            }
        }
        assert!(altered.analog_route(Direction::Playback, 4, 2).is_err());
    }
}

#[test]
fn analog_route_hardware_failures_poison_future_configuration_and_start() {
    for failure in 0..6 {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let playback = controller
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
            match failure {
                0 => m.power_stuck = true,
                1 => m.power_error = true,
                2 => m.reject_route_control = Some(0xf01),
                3 => m.reject_route_control = Some(0xf07),
                4 => m.reject_route_control = Some(0xf0c),
                _ => m.reject_amplifier = true,
            }
        }
        let result = controller.configure_analog_route(
            &graph,
            &route,
            playback,
            0,
            PinOptions::Playback {
                headphone: false,
                eapd: Some(true),
            },
        );
        assert_eq!(
            result,
            Err(if failure == 0 {
                Error::Timeout(Phase::CodecPower)
            } else {
                Error::RouteRejected
            })
        );
        assert_eq!(controller.start(playback), Err(Error::NeedsReset));
        assert_eq!(
            controller.configure_analog_route(
                &graph,
                &route,
                playback,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: None
                }
            ),
            Err(Error::NeedsReset)
        );
        controller.shutdown().unwrap();
    }
}

#[test]
fn analog_routes_reserve_widgets_and_require_every_stream_stopped() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
    let first = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let second = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let options = PinOptions::Playback {
        headphone: false,
        eapd: None,
    };
    controller
        .configure_analog_route(&graph, &route, first, 0, options)
        .unwrap();
    let count = model.borrow().commands.len();
    let original_binding = model.borrow().bindings[&2];
    assert_eq!(
        controller.bind_converter(&graph, 2, second, 0),
        Err(Error::RouteInUse)
    );
    assert_eq!(
        controller.bind_converter(&graph, 2, first, 0),
        Err(Error::RouteInUse)
    );
    assert_eq!(model.borrow().bindings[&2], original_binding);
    assert_eq!(model.borrow().commands.len(), count);
    assert_eq!(
        controller.configure_analog_route(&graph, &route, second, 0, options),
        Err(Error::RouteInUse)
    );
    assert_eq!(
        controller.configure_analog_route(&graph, &route, first, 0, options),
        Err(Error::RouteInUse)
    );
    controller.start(first).unwrap();
    assert_eq!(
        controller.configure_analog_route(&graph, &route, second, 0, options),
        Err(Error::StreamRunning)
    );
    assert_eq!(model.borrow().commands.len(), count);
    controller.stop(first).unwrap();
}

#[test]
fn capture_bias_choices_and_stopped_buffer_fill_observe_capability_and_dma_ownership() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let mut graph = controller.enumerate_codec(0).unwrap();
    let route = graph.analog_route(Direction::Capture, 5, 3).unwrap();
    let capture = controller
        .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
        .unwrap();
    let playback = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    graph.groups[0]
        .widgets
        .iter_mut()
        .find(|w| w.node == 5)
        .unwrap()
        .pin_capabilities = Some(0x20);
    let count = model.borrow().commands.len();
    assert_eq!(
        controller.configure_analog_route(
            &graph,
            &route,
            capture,
            0,
            PinOptions::Capture { vref: Vref::Half }
        ),
        Err(Error::InvalidPinControl)
    );
    assert_eq!(model.borrow().commands.len(), count);
    controller
        .configure_analog_route(
            &graph,
            &route,
            capture,
            0,
            PinOptions::Capture {
                vref: Vref::HighImpedance,
            },
        )
        .unwrap();
    assert_eq!(model.borrow().route_controls[&(5, 0xf07)], 0x20);
    controller.fill_capture(capture, 0xa5).unwrap();
    let mut bytes = [0; 256];
    controller.read_pcm(capture, 0, &mut bytes).unwrap();
    assert_eq!(bytes, [0xa5; 256]);
    assert_eq!(
        controller.fill_capture(playback, 0xa5),
        Err(Error::InvalidStream)
    );
    model.borrow_mut().dma_step_bytes = 64;
    controller.start(capture).unwrap();
    assert_eq!(
        controller.fill_capture(capture, 0),
        Err(Error::StreamRunning)
    );
    for _ in 0..8 {
        controller.timer.relax();
        let _ = controller.position(capture).unwrap();
    }
    controller.stop(capture).unwrap();
    controller.read_pcm(capture, 0, &mut bytes).unwrap();
    assert_ne!(bytes, [0xa5; 256]);
}

#[test]
fn zero_widget_power_states_inherit_function_group_but_zero_group_refuses() {
    for group_states in [1, 0] {
        let mut fixture = Fixture::new();
        let model = analog_model();
        model
            .borrow_mut()
            .parameters
            .insert((1, 0x0f), group_states);
        model.borrow_mut().parameters.insert((2, 0x0f), 0);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        assert_eq!(graph.widget(2).unwrap().power_states, Some(group_states));
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
        let before = model.borrow().commands.len();
        let result = controller.configure_analog_route(
            &graph,
            &route,
            stream,
            0,
            PinOptions::Playback {
                headphone: false,
                eapd: None,
            },
        );
        if group_states == 0 {
            assert_eq!(result, Err(Error::UnsupportedTopology));
            assert_eq!(model.borrow().commands.len(), before);
        } else {
            result.unwrap();
            assert!(model.borrow().power_ready.contains_key(&2));
        }
    }
}

#[test]
fn uncertain_stream_stop_blocks_other_routes_before_codec_or_mmio_writes() {
    for dma_error in [false, true] {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let first = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let second = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        controller.start(first).unwrap();
        model.borrow_mut().stream_stop_stuck = true;
        if dma_error {
            model.borrow_mut().bytes[stream_base(first.descriptor_index()) + SD_STS] =
                SD_DESC_ERROR;
            assert_eq!(
                controller.status(first),
                Err(Error::StreamDma {
                    status: SD_DESC_ERROR
                })
            );
        } else {
            assert_eq!(
                controller.stop(first),
                Err(Error::Timeout(Phase::StreamStop))
            );
        }
        assert_ne!(
            model.borrow().bytes[stream_base(first.descriptor_index()) + SD_CTL] & SD_RUN,
            0
        );
        let commands = model.borrow().commands.len();
        let writes = model.borrow().writes.len();
        assert_eq!(
            controller.configure_analog_route(
                &graph,
                &route,
                second,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: None
                }
            ),
            Err(Error::NeedsReset)
        );
        assert_eq!(model.borrow().commands.len(), commands);
        assert_eq!(model.borrow().writes.len(), writes);
    }
}
