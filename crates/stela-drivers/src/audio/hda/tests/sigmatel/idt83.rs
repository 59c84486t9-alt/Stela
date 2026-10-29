// SPDX-License-Identifier: GPL-2.0-only
//! idt83 behavior tests.
use super::*;

#[test]
fn family_jack_power_and_duplex() {
    let mut ids = vec![
        0x111d_7604,
        0x111d_76d4,
        0x111d_7605,
        0x111d_76d5,
        0x111d_76d1,
        0x111d_76d9,
        0x111d_76df,
        0x111d_76e0,
        0x111d_76e3,
        0x111d_76e5,
    ];
    ids.extend(0x111d_7666..=0x111d_7669);
    ids.extend(0x111d_76e7..=0x111d_76f3);
    assert_eq!(ids.len(), 27);
    for id in ids {
        let mut fixture = Fixture::new();
        let model = idt83_device(id);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_sigmatel_codec(&graph).unwrap();
        assert_eq!(report.profile, SigmatelProfile::Idt92hd83xxx);
        assert_eq!(report.selector_node, None);
        assert_eq!(report.volume_knob, None);
        let power = report.idt83.unwrap();
        assert_eq!(power.amplifier_mode_acknowledged, 4);
        assert_eq!(power.power_map, 8);
        assert_eq!(power.ports.len(), 7);
        for (index, port) in power.ports.iter().enumerate() {
            assert_eq!(usize::from(port.node), 0x0a + index);
            assert_eq!(port.powered, index != 3);
            assert_eq!(port.sense.is_some(), index < 2);
        }
        assert_eq!(model.borrow().idt83_amplifier_mode, Some(4));
        assert_eq!(model.borrow().idt83_power_map, 8);
        assert_eq!(
            report.gpio,
            SigmatelGpio {
                mask: 0x5a,
                direction: 0x3c,
                data: 0xa5
            }
        );
        assert!(model.borrow().sense_triggers.is_empty());
        assert!(
            !model
                .borrow()
                .commands
                .iter()
                .any(|command| (command >> 8) & 0xfff == 0xf88)
        );
        let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
        let input = graph.analog_route(Direction::Capture, 0x0b, 3).unwrap();
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
        assert_eq!(
            controller.configure_analog_route(
                &graph,
                &output,
                playback,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd: Some(true)
                }
            ),
            Err(Error::InvalidPinControl)
        );
        controller
            .configure_analog_route(&graph, &output, playback, 0, idt83_playback())
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
        controller.write_pcm(playback, 0, &[0x83; 256]).unwrap();
        controller.fill_capture(capture, 0xa5).unwrap();
        controller.start(capture).unwrap();
        controller.start(playback).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 8);
        assert!(controller.status(playback).unwrap().period_completed);
        assert!(controller.status(capture).unwrap().period_completed);
        model.borrow_mut().pin_senses.insert(0x0a, 0);
        assert!(!controller.poll_pin_sense(&graph, 0x0a).unwrap().present);
        assert_eq!(model.borrow().idt83_power_map, 9);
        assert!(controller.status(playback).unwrap().running);
        assert!(controller.status(capture).unwrap().running);
        controller.stop(playback).unwrap();
        let before = access_counts(&model);
        assert_eq!(controller.start(playback), Err(Error::UnsupportedTopology));
        assert_eq!(access_counts(&model), before);
        model.borrow_mut().pin_senses.insert(0x0a, 0x8000_0042);
        assert!(controller.poll_pin_sense(&graph, 0x0a).unwrap().present);
        assert_eq!(model.borrow().idt83_power_map, 8);
        controller.start(playback).unwrap();
        controller.stop(capture).unwrap();
        let mut samples = [0; 256];
        controller.read_pcm(capture, 0, &mut samples).unwrap();
        assert_eq!(samples, core::array::from_fn(|index| index as u8));
        controller.shutdown().unwrap();
        let m = model.borrow();
        assert!(m.playback.len() >= 256 && m.playback.iter().all(|byte| *byte == 0x83));
        assert_eq!(m.idt83_power_map, 8); // Held-D0 shutdown does not invent map-off/PM.
        for pin in 0x0a..=0x10 {
            assert_eq!(m.route_controls[&(pin, 0xf07)], 0);
        }
    }
}

#[test]
fn powered_off_route_and_refresh() {
    let mut fixture = Fixture::new();
    let model = idt83_device(0x111d_7604);
    model.borrow_mut().pin_senses.insert(0x0a, 0);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    assert_eq!(
        controller
            .initialize_sigmatel_codec(&graph)
            .unwrap()
            .idt83
            .unwrap()
            .power_map,
        9
    );
    let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
    let playback = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    assert_eq!(
        controller.configure_analog_route(&graph, &output, playback, 0, idt83_playback()),
        Err(Error::UnsupportedTopology)
    );
    assert!(!controller.routing_failed);
    assert!(controller.routes.is_empty());
    model.borrow_mut().pin_senses.insert(0x0b, 0);
    assert_eq!(
        controller
            .refresh_idt83_power_map(&graph)
            .unwrap()
            .power_map,
        11
    );
    assert!(!controller.poll_pin_sense(&graph, 0x0c).unwrap().present);
    assert_eq!(model.borrow().idt83_power_map, 11); // Fixed pin stays on.
    assert_eq!(
        controller.poll_pin_sense(&graph, 0x0e),
        Err(Error::UnsupportedTopology)
    );
    assert_eq!(
        controller.poll_pin_sense(&graph, 0x0f),
        Err(Error::UnsupportedTopology)
    );
    assert!(!controller.routing_failed);
    model.borrow_mut().pin_senses.insert(0x0a, 0xffff_ffff); // Valid raw all-ones measurement.
    assert!(controller.poll_pin_sense(&graph, 0x0a).unwrap().present);
    assert_eq!(model.borrow().idt83_power_map, 10);
    controller
        .configure_sigmatel_route(&graph, &output, playback, 0, idt83_playback())
        .unwrap();
    controller.shutdown().unwrap();
}

#[test]
fn invalid_port_map_rejected() {
    for fault in 0..7 {
        let mut fixture = Fixture::new();
        let model = idt83_device(0x111d_7604);
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.parameters.insert((0, 0), 0x111d_7603);
                }
                1 => {
                    m.parameters.insert((0x10, 9), 0xf << 20);
                }
                2 => {
                    m.parameters.insert((0x10, 0x0c), 0);
                }
                3 => {
                    m.parameters.insert((0x10, 9), (4 << 20) | 1 | (1 << 9));
                }
                4 => {
                    m.idt83_power_map = 0x80;
                }
                5 => {
                    m.idt83_power_map = u32::MAX;
                }
                _ => {
                    m.pin_defaults.insert(0x10, u32::MAX);
                }
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        if fault == 6 {
            model.borrow_mut().pin_defaults.insert(0x10, 0x0101_0010);
        }
        let before = model.borrow().commands.len();
        assert!(controller.initialize_sigmatel_codec(&graph).is_err());
        if matches!(fault, 4 | 5) {
            // D0 is needed before vendor map reads; an invalid map
            // therefore keeps the earlier D0/GPIO transaction owner.
            assert_eq!(controller.sigmatel_codecs.len(), 1);
            assert!(controller.routing_failed);
            assert_eq!(model.borrow().idt83_amplifier_mode, None);
            assert!(
                !model.borrow().commands[before..]
                    .iter()
                    .any(|command| (command >> 8) & 0xfff == 0x7ec)
            );
        } else {
            assert!(controller.sigmatel_codecs.is_empty());
            assert!(!controller.routing_failed);
            assert!(
                model.borrow().commands[before..]
                    .iter()
                    .all(|command| command & (1 << 19) != 0)
            );
        }
    }
}

#[test]
fn cold_map_failure_requires_reset() {
    for fault in 0..4 {
        let mut fixture = Fixture::new();
        let model = idt83_device(0x111d_76f3);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => m.idt83_amplifier_reply = u32::MAX,
                1 => m.drop_reply_command = Some((1 << 20) | 0x78804),
                2 => {
                    m.reject_route_control = Some(0xfec);
                    m.reject_route_after_write = true;
                }
                _ => m.drop_reply_command = Some((1 << 20) | 0x7ec08),
            }
        }
        assert!(controller.initialize_sigmatel_codec(&graph).is_err());
        assert_eq!(model.borrow().idt83_amplifier_mode, Some(4));
        if fault >= 2 {
            assert_eq!(model.borrow().idt83_power_map, 8);
        }
        assert!(controller.routing_failed);
        assert_eq!(controller.sigmatel_codecs.len(), 1);
        let before = access_counts(&model);
        assert_eq!(
            controller.refresh_idt83_power_map(&graph),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        {
            let mut m = model.borrow_mut();
            m.idt83_amplifier_reply = 0;
            m.drop_reply_command = None;
            m.reject_route_control = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.sigmatel_codecs.is_empty());
        assert_eq!(
            controller.initialize_sigmatel_codec(&graph),
            Err(Error::InvalidCodecGraph)
        );
    }
}

#[test]
fn live_map_drift_quarantines_routes() {
    for fault in 0..4 {
        let mut fixture = Fixture::new();
        let model = idt83_device(0x111d_76e8);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
        let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
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
            .configure_analog_route(&graph, &output, playback, 0, idt83_playback())
            .unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => m.idt83_power_map = 9,
                1 => m.idt83_power_map = 0x80,
                2 => {
                    m.pin_defaults.insert(0x0e, 0x4000_0100);
                }
                _ => {
                    m.parameters.insert((0x10, 0x0c), 0x20);
                }
            }
        }
        assert_eq!(
            controller.refresh_idt83_power_map(&graph),
            Err(if fault < 2 {
                Error::RouteRejected
            } else {
                Error::InvalidCodecGraph
            })
        );
        let before = access_counts(&model);
        assert_eq!(controller.start(playback), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        let before = model.borrow().commands.len();
        assert_eq!(controller.shutdown(), Err(Error::NeedsReset));
        assert_eq!(model.borrow().commands.len(), before);
        assert!(controller.stopped);
        assert_eq!(controller.routes.len(), 1);
        controller.reinitialize().unwrap();
        assert!(controller.sigmatel_codecs.is_empty());
        assert!(controller.routes.is_empty());
    }
}

#[test]
fn failed_jack_power_retains_owner() {
    for lost_ack in [false, true] {
        let mut fixture = Fixture::new();
        let model = idt83_device(0x111d_7605);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
        let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
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
            .configure_analog_route(&graph, &output, playback, 0, idt83_playback())
            .unwrap();
        controller.start(playback).unwrap();
        {
            let mut m = model.borrow_mut();
            m.pin_senses.insert(0x0a, 0);
            if lost_ack {
                m.drop_reply_command = Some((1 << 20) | 0x7ec09);
            } else {
                m.reject_route_control = Some(0xfec);
                m.reject_route_after_write = true;
                m.reject_route_write_threshold = 2;
            }
        }
        assert!(controller.poll_pin_sense(&graph, 0x0a).is_err());
        assert_eq!(model.borrow().idt83_power_map, 9); // Write took physical effect.
        assert_eq!(controller.routes.len(), 1);
        assert_eq!(controller.sigmatel_codecs.len(), 1);
        assert_eq!(controller.start(playback), Err(Error::NeedsReset));
        {
            let mut m = model.borrow_mut();
            m.drop_reply_command = None;
            m.reject_route_control = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty());
        assert!(controller.sigmatel_codecs.is_empty());
    }
}
