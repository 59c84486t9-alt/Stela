// SPDX-License-Identifier: GPL-2.0-only
//! routing behavior tests.
use super::*;

#[test]
fn eapd_inventory() {
    for count in 0..=4 {
        let mut fixture = Fixture::new();
        let model = device(0x14f1_5098, count);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_conexant_codec(&graph).unwrap();
        assert_eq!(report.codec_id, 0x14f1_5098);
        assert_eq!(report.revision_id, 0x0010_0100);
        assert_eq!(report.subsystem_id, 0x1043_8693);
        assert_eq!(report.function_group, 1);
        assert!(!report.single_adc_amplifier);
        assert_eq!(report.eapd.len(), count);
        let expected = if count > 2 {
            ConexantEapdMode::Dynamic
        } else {
            ConexantEapdMode::Global
        };
        assert_eq!(report.eapd_mode, expected);
        for (_, value) in &report.eapd {
            assert_eq!(*value, if count > 2 { 5 } else { 2 });
        }
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_conexant_codec(&graph),
            Err(Error::RouteInUse)
        );
        assert_eq!(access_counts(&model), before);
        controller
            .set_conexant_outputs_enabled(&graph, false)
            .unwrap();
        for (node, _) in &report.eapd {
            assert_eq!(model.borrow().route_controls[&(*node, 0xf0c)], 0);
        }
        controller
            .set_conexant_outputs_enabled(&graph, true)
            .unwrap();
        controller.shutdown().unwrap();
        for (node, _) in report.eapd {
            assert_eq!(model.borrow().route_controls[&(node, 0xf0c)], 0);
        }
    }
}

#[test]
fn selected_adc_amp_indices() {
    for codec in [0x14f1_5045, 0x14f1_5047, 0x14f1_5098] {
        let mut fixture = Fixture::new();
        let model = device(codec, 3);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_conexant_codec(&graph).unwrap();
        assert_eq!(report.single_adc_amplifier, codec == 0x14f1_5045);
        let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
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
            .configure_conexant_route(&graph, &output, playback, 0, playback_options())
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
        {
            let m = model.borrow();
            assert_eq!(m.route_controls[&(3, 0xf01)], 1);
            assert_eq!(m.route_controls[&(4, 0xf01)], 1);
            for channel in 0..2 {
                assert_eq!(m.amplifiers[&(4, true, 0, channel)], 0x1f);
                assert!(!m.amplifiers.contains_key(&(4, true, 1, channel)));
                let index = u8::from(codec != 0x14f1_5045);
                assert_eq!(m.amplifiers[&(3, false, index, channel)], 0x1f);
                assert!(!m.amplifiers.contains_key(&(3, false, 1 - index, channel)));
            }
        }
        // Dynamic initialization and analog routing do not own EAPD policy.
        assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 5);
        controller
            .set_conexant_outputs_enabled(&graph, true)
            .unwrap();
        assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 2);
        controller.write_pcm(playback, 0, &[0x5a; 256]).unwrap();
        controller.fill_capture(capture, 0xa5).unwrap();
        controller.start(capture).unwrap();
        controller.start(playback).unwrap();
        controller
            .set_conexant_outputs_enabled(&graph, false)
            .unwrap();
        assert!(controller.status(playback).unwrap().running);
        controller
            .set_conexant_outputs_enabled(&graph, true)
            .unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 16);
        assert!(controller.status(playback).unwrap().period_completed);
        assert!(controller.status(capture).unwrap().period_completed);
        controller.stop(capture).unwrap();
        let mut actual = [0; 256];
        controller.read_pcm(capture, 0, &mut actual).unwrap();
        assert_eq!(actual, core::array::from_fn(|index| index as u8));
        controller.shutdown().unwrap();
        let m = model.borrow();
        assert!(m.playback.len() >= 256);
        assert!(m.playback.iter().all(|byte| *byte == 0x5a));
        for node in [4, 5, 8] {
            assert_eq!(m.route_controls[&(node, 0xf0c)], 0);
        }
        assert_eq!(
            m.get(stream_base(playback.descriptor_index()) + SD_CTL, 1) & u32::from(SD_RUN),
            0
        );
        assert_eq!(m.get(CORBCTL, 1) & u32::from(COMMAND_RUN), 0);
    }
}

#[test]
fn stale_metadata_rejected() {
    for case in 0..9 {
        let mut fixture = Fixture::new();
        let model = device(
            if case == 0 { 0x14f1_1f86 } else { 0x14f1_5047 },
            if case == 1 { 5 } else { 3 },
        );
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        {
            let mut m = model.borrow_mut();
            match case {
                2 => {
                    m.parameters.insert((0, 0), 0x14f1_5098);
                }
                3 => {
                    m.parameters.insert((0, 2), u32::MAX);
                }
                4 => {
                    m.parameters.insert((0, 4), (2 << 16) | 1);
                }
                5 => {
                    m.parameters.insert((1, 5), 2);
                }
                6 => {
                    m.parameters.insert((1, 4), (2 << 16) | 8);
                }
                7 => {
                    m.parameters.insert((2, 9), 4 << 20);
                }
                8 => {
                    m.parameters.insert((8, 0x0c), u32::MAX);
                }
                _ => (),
            }
        }
        let before = model.borrow().commands.len();
        assert!(controller.initialize_conexant_codec(&graph).is_err());
        assert!(controller.conexant_codecs.is_empty());
        let m = model.borrow();
        assert!(
            m.commands[before..]
                .iter()
                .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
        );
    }
}

#[test]
fn route_options_preflight() {
    let mut fixture = Fixture::new();
    let model = device(0x14f1_5098, 3);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_conexant_codec(&graph).unwrap();
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
    for eapd in [Some(true), Some(false)] {
        let before = model.borrow().commands.len();
        assert_eq!(
            controller.configure_analog_route(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd
                }
            ),
            Err(Error::InvalidPinControl)
        );
        assert!(
            model.borrow().commands[before..]
                .iter()
                .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
        );
        assert!(!controller.routing_failed);
    }
    model.borrow_mut().parameters.insert((8, 0x0c), 0x10);
    assert_eq!(
        controller.set_conexant_outputs_enabled(&graph, true),
        Err(Error::InvalidCodecGraph)
    );
    assert!(controller.routes.is_empty());
}

#[test]
fn partial_initialization_requires_reset() {
    for case in 0..4 {
        let mut fixture = Fixture::new();
        let model = device(0x14f1_5045, if case == 0 { 2 } else { 3 });
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
            let mut m = model.borrow_mut();
            m.reject_route_control = Some(0xf0c);
            m.reject_route_node = Some(5);
        } else if case == 1 {
            model.borrow_mut().reject_route_control = Some(0xf0c);
        }
        if case < 2 {
            assert_eq!(
                controller.initialize_conexant_codec(&graph),
                Err(Error::RouteRejected)
            );
        } else {
            controller.initialize_conexant_codec(&graph).unwrap();
            if case == 2 {
                model.borrow_mut().reject_route_control = Some(0xf0c);
                assert_eq!(
                    controller.set_conexant_outputs_enabled(&graph, true),
                    Err(Error::RouteRejected)
                );
            } else {
                model.borrow_mut().reject_amplifier = true;
                assert_eq!(
                    controller.configure_conexant_route(
                        &graph,
                        &route,
                        stream,
                        0,
                        playback_options()
                    ),
                    Err(Error::RouteRejected)
                );
            }
        }
        assert_eq!(controller.conexant_codecs.len(), 1);
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        model.borrow_mut().reject_route_control = None;
        model.borrow_mut().reject_amplifier = false;
        controller.reinitialize().unwrap();
        assert!(controller.conexant_codecs.is_empty());
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_conexant_codec(&graph),
            Err(Error::InvalidCodecGraph)
        );
        assert_eq!(access_counts(&model), before);
    }
}

#[test]
fn shutdown_failure_keeps_amplifiers() {
    for case in 0..3 {
        let mut fixture = Fixture::new();
        let model = device(0x14f1_5098, 3);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_conexant_codec(&graph).unwrap();
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
        controller
            .configure_conexant_route(&graph, &route, stream, 0, playback_options())
            .unwrap();
        controller.start(stream).unwrap();
        let before = model.borrow().commands.len();
        {
            let mut m = model.borrow_mut();
            match case {
                0 => m.stream_stop_stuck = true,
                1 => m.command_stop_stuck = true,
                _ => {
                    m.reject_route_control = Some(0xf0c);
                    m.reject_route_node = Some(5);
                }
            }
        }
        assert!(controller.shutdown().is_err());
        assert_eq!(controller.conexant_codecs.len(), 1);
        assert_eq!(controller.routes.len(), 1);
        if case == 0 {
            assert!(model.borrow().commands[before..].is_empty());
            assert!(!controller.stopped);
        } else if case == 2 {
            assert!(controller.stopped);
        }
        {
            let mut m = model.borrow_mut();
            m.stream_stop_stuck = false;
            m.command_stop_stuck = false;
            m.reject_route_control = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.conexant_codecs.is_empty());
        assert!(controller.routes.is_empty());
    }
}

#[test]
fn reset_disables_amplifiers() {
    let mut fixture = Fixture::new();
    let model = device(0x14f1_5047, 2);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_conexant_codec(&graph).unwrap();
    assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 2);
    controller.reinitialize().unwrap();
    for node in [4, 5] {
        assert_eq!(model.borrow().route_controls[&(node, 0xf0c)], 0);
    }
    assert!(controller.conexant_codecs.is_empty());
    let before = access_counts(&model);
    assert_eq!(
        controller.set_conexant_outputs_enabled(&graph, true),
        Err(Error::InvalidCodecGraph)
    );
    assert_eq!(access_counts(&model), before);
}

#[test]
fn initial_power_failure_quarantines_routes() {
    for power_fault in [true, false] {
        let mut fixture = Fixture::new();
        let model = device(0x14f1_5098, 3);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        if power_fault {
            model.borrow_mut().power_stuck = true;
            assert_eq!(
                controller.initialize_conexant_codec(&graph),
                Err(Error::Timeout(crate::audio::Phase::CodecPower))
            );
            assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 5);
        } else {
            controller.initialize_conexant_codec(&graph).unwrap();
            // The master's first SET may take effect, but its response
            // is lost. Never treat the unchanged software state as proof
            // that hardware was untouched or send another unsafe verb.
            model.borrow_mut().drop_reply_command =
                Some(Verb::short(0, 4, 0x70c, 2).unwrap().raw());
            assert_eq!(
                controller.set_conexant_outputs_enabled(&graph, true),
                Err(Error::Timeout(crate::audio::Phase::Verb))
            );
            assert_eq!(model.borrow().route_controls[&(4, 0xf0c)], 2);
            // The Conexant bus reset retried, then single commands.
            assert!(controller.single_command);
        }
        assert_eq!(controller.conexant_codecs.len(), 1);
        let before = access_counts(&model);
        assert_eq!(
            controller.set_conexant_outputs_enabled(&graph, true),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        {
            let mut m = model.borrow_mut();
            m.power_stuck = false;
            m.drop_reply_command = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.conexant_codecs.is_empty());
    }
}

#[test]
fn failed_restart_rejects_stale_shutdown() {
    let mut fixture = Fixture::new();
    let model = device(0x14f1_5098, 3);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_conexant_codec(&graph).unwrap();
    controller.shutdown().unwrap();
    assert!(controller.stopped);
    {
        let mut m = model.borrow_mut();
        // Initial stop is still acknowledged. Only the later restart
        // produces unreadable RUN controls and rejects cleanup stops.
        m.command_started_once = false;
        m.command_start_read_failure = Some(CORBCTL);
        m.command_stop_stuck = true;
    }
    assert_eq!(
        controller.reinitialize(),
        Err(Error::Timeout(crate::audio::Phase::CommandStart))
    );
    assert!(!controller.stopped);
    let token = controller.token;
    assert_eq!(
        controller.reinitialize(),
        Err(Error::Timeout(crate::audio::Phase::CommandStop))
    );
    assert_eq!(controller.token, token);
    assert_eq!(controller.conexant_codecs.len(), 1);
    {
        let mut m = model.borrow_mut();
        m.command_start_read_failure = None;
        m.command_stop_stuck = false;
    }
    controller.reinitialize().unwrap();
    assert!(controller.conexant_codecs.is_empty());
}

#[test]
fn lost_controls_block_start() {
    for master_call in [true, false] {
        for changed_vendor in [true, false] {
            let mut fixture = Fixture::new();
            let model = device(0x14f1_5045, 3);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_conexant_codec(&graph).unwrap();
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
            controller
                .configure_analog_route(&graph, &route, playback, 0, playback_options())
                .unwrap();
            let capture = controller
                .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
                .unwrap();
            let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
            if changed_vendor {
                model.borrow_mut().parameters.insert((0, 0), 0x14f1_5098);
            } else {
                model.borrow_mut().parameters.insert((8, 0x0c), 0x10);
            }
            let before = model.borrow().commands.len();
            let result = if master_call {
                controller.set_conexant_outputs_enabled(&graph, true)
            } else {
                controller.configure_analog_route(
                    &graph,
                    &input,
                    capture,
                    0,
                    PinOptions::Capture {
                        vref: Vref::EightyPercent,
                    },
                )
            };
            assert_eq!(result, Err(Error::InvalidCodecGraph));
            assert!(
                model.borrow().commands[before..]
                    .iter()
                    .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
            );
            let before = access_counts(&model);
            assert_eq!(controller.start(playback), Err(Error::NeedsReset));
            assert_eq!(controller.start(capture), Err(Error::NeedsReset));
            assert_eq!(access_counts(&model), before);
            assert_eq!(controller.routes.len(), 1);
            assert_eq!(controller.conexant_codecs.len(), 1);
            let before = model.borrow().commands.len();
            assert_eq!(controller.shutdown(), Err(Error::NeedsReset));
            assert!(controller.stopped);
            assert_eq!(model.borrow().commands.len(), before);
        }
    }
}
