// SPDX-License-Identifier: GPL-2.0-only
//! idt73 behavior tests.
use super::*;

#[test]
fn family_startup_and_duplex() {
    let mut ids: Vec<_> = (0x111d_7674..=0x111d_7676).collect();
    ids.extend(0x111d_76c0..=0x111d_76ce);
    assert_eq!(ids.len(), 18);
    for id in ids {
        let mut fixture = Fixture::new();
        let model = idt73_device(id);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_sigmatel_codec(&graph).unwrap();
        assert_eq!(report.profile, SigmatelProfile::Idt92hd73xx);
        assert_eq!(report.volume_knob, Some((0x1f, 0xff)));
        assert_eq!(report.capture_output_amplifier, None);
        assert!(report.idt83.is_none());
        assert_eq!(
            report.gpio,
            SigmatelGpio {
                data: 0xa5,
                mask: 0x5b,
                direction: 0x3d
            }
        );
        let power = report.idt73.unwrap();
        assert_eq!(power.power_map, 0x88);
        assert_eq!(power.ports.len(), 8);
        assert_eq!(power.ports[7].node, 0x11);
        assert!(!power.ports[7].powered && power.ports[7].sense.is_some());
        assert_eq!(model.borrow().idt83_amplifier_mode, None); // No83xxx SET788.
        {
            let m = model.borrow();
            let at = |verb| {
                m.command_times
                    .iter()
                    .find(|(command, _)| (command >> 8) & 0xfff == verb)
                    .unwrap()
                    .1
            };
            assert!(at(0x715) >= at(0x717) + 1000);
            assert!(at(0x715) < at(0x70f) && at(0x70f) < at(0x7ec));
            assert!(m.sense_triggers.is_empty());
        }
        let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
        let input = graph.analog_route(Direction::Capture, 0x0b, 3).unwrap();
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
        assert_eq!(
            controller.configure_analog_route(
                &graph,
                &output,
                out,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd: Some(true)
                }
            ),
            Err(Error::InvalidPinControl)
        );
        controller
            .configure_analog_route(&graph, &output, out, 0, idt83_playback())
            .unwrap();
        controller
            .configure_sigmatel_route(
                &graph,
                &input,
                mic,
                0,
                PinOptions::Capture {
                    vref: Vref::EightyPercent,
                },
            )
            .unwrap();
        controller.write_pcm(out, 0, &[0x63; 256]).unwrap();
        controller.fill_capture(mic, 0xa5).unwrap();
        controller.start(out).unwrap();
        controller.start(mic).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 8);
        assert!(
            controller.status(out).unwrap().period_completed
                && controller.status(mic).unwrap().period_completed
        );
        model.borrow_mut().pin_senses.insert(0x0a, 0);
        assert_eq!(
            controller
                .refresh_idt73_power_map(&graph)
                .unwrap()
                .power_map,
            0x89
        );
        controller.stop(out).unwrap();
        let before = access_counts(&model);
        assert_eq!(controller.start(out), Err(Error::UnsupportedTopology));
        assert_eq!(access_counts(&model), before);
        model.borrow_mut().pin_senses.insert(0x0a, 0x8000_0042);
        assert!(controller.poll_pin_sense(&graph, 0x0a).unwrap().present);
        assert_eq!(model.borrow().idt83_power_map, 0x88);
        controller.start(out).unwrap();
        assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0xa5);
        controller.stop(mic).unwrap();
        let mut samples = [0; 256];
        controller.read_pcm(mic, 0, &mut samples).unwrap();
        assert_eq!(samples, core::array::from_fn(|index| index as u8));
        controller.shutdown().unwrap();
        {
            let m = model.borrow();
            assert_eq!(m.route_controls[&(1, 0xf15)], 0xa4);
            assert_eq!(m.route_controls[&(1, 0xf16)], 0x5b);
            assert_eq!(m.route_controls[&(1, 0xf17)], 0x3d);
            for pin in 0x0a..=0x11 {
                assert_eq!(m.route_controls[&(pin, 0xf07)], 0);
            }
            assert!(m.playback.len() >= 256 && m.playback.iter().all(|byte| *byte == 0x63));
            assert!(m.sense_triggers.is_empty());
        }
    }
}

#[test]
fn unclaimed_gpio_preserved() {
    for transition in 0..3 {
        let mut fixture = Fixture::new();
        let model = idt73_device(0x111d_76c2);
        if transition == 1 {
            let mut m = model.borrow_mut();
            m.route_controls.insert((1, 0xf15), 0xa6);
            m.idt73_gpio_input_after_write = Some(1);
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_sigmatel_codec(&graph).unwrap();
        assert_eq!(report.gpio.data, 0xa5); // Readback, including a changing input.

        let route = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
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
            .configure_analog_route(&graph, &route, stream, 0, idt83_playback())
            .unwrap();
        controller.write_pcm(stream, 0, &[0xc7; 256]).unwrap();
        controller.start(stream).unwrap();
        {
            let mut m = model.borrow_mut();
            // Owned bit0 remains valid; input bit1 and other controls
            // change independently after the source startup snapshot.
            m.route_controls.insert((1, 0xf15), 0xa7);
            m.route_controls.insert((1, 0xf16), 0xdb);
            m.route_controls.insert((1, 0xf17), 0x7d);
            m.dma_step_bytes = 128;
        }
        assert!(controller.poll_pin_sense(&graph, 0x0a).unwrap().present);
        assert_eq!(
            controller
                .refresh_idt73_power_map(&graph)
                .unwrap()
                .power_map,
            0x88
        );
        assert!(!controller.routing_failed);
        advance(&model, 8);
        assert!(controller.status(stream).unwrap().period_completed);
        assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0xa7);
        if transition == 2 {
            model.borrow_mut().idt73_gpio_input_after_write = Some(2);
        }
        controller.shutdown().unwrap();
        let m = model.borrow();
        assert_eq!(
            m.route_controls[&(1, 0xf15)],
            if transition == 2 { 0xa4 } else { 0xa6 }
        );
        assert_eq!(m.route_controls[&(1, 0xf16)], 0xdb);
        assert_eq!(m.route_controls[&(1, 0xf17)], 0x7d);
        assert!(m.playback.len() >= 256 && m.playback.iter().all(|byte| *byte == 0xc7));
    }
}

#[test]
fn missing_fixed_controls_rejected() {
    for fault in 0..8 {
        let mut fixture = Fixture::new();
        let model = idt73_device(0x111d_7674);
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.parameters.insert((0, 0), 0x111d_7673);
                }
                1 => {
                    m.parameters.insert((1, 0x11), 0);
                }
                2 => {
                    m.parameters.insert((1, 0x11), 9);
                }
                3 => {
                    m.parameters.insert((0x1f, 9), 0xf << 20);
                }
                4 => {
                    m.parameters.insert((0x1f, 0x13), 0x7e);
                }
                5 => {
                    m.parameters.insert((0x11, 9), (4 << 20) | (1 << 9));
                }
                6 => {
                    m.parameters.insert((0x11, 0x0c), u32::MAX);
                }
                _ => {
                    m.pin_defaults.insert(0x11, u32::MAX);
                }
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let before = model.borrow().commands.len();
        assert!(
            controller.initialize_sigmatel_codec(&graph).is_err(),
            "fault={fault}"
        );
        assert!(controller.sigmatel_codecs.is_empty() && !controller.routing_failed);
        assert!(
            model.borrow().commands[before..]
                .iter()
                .all(|command| command & (1 << 19) != 0)
        );
    }
}

#[test]
fn late_startup_failure_requires_reset() {
    for fault in 0..6 {
        let mut fixture = Fixture::new();
        let model = idt73_device(0x111d_76ce);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.reject_route_control = Some(0xf15);
                    m.reject_route_after_write = true;
                }
                1 => {
                    m.drop_reply_command = Some((1 << 20) | 0x715a5);
                }
                2 => {
                    m.reject_route_control = Some(0xf0f);
                }
                3 => {
                    m.drop_reply_command = Some((0x1f << 20) | 0x70fff);
                }
                4 => {
                    m.reject_route_control = Some(0xfec);
                    m.reject_route_after_write = true;
                }
                _ => {
                    m.drop_reply_command = Some((1 << 20) | 0x7ec88);
                }
            }
        }
        assert!(controller.initialize_sigmatel_codec(&graph).is_err());
        assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0xa5);
        if fault >= 2 {
            assert_eq!(model.borrow().route_controls[&(0x1f, 0xf0f)], 0xff);
        }
        if fault >= 4 {
            assert_eq!(model.borrow().idt83_power_map, 0x88);
        }
        assert_eq!(controller.sigmatel_codecs.len(), 1);
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_sigmatel_codec(&graph),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        {
            let mut m = model.borrow_mut();
            m.reject_route_control = None;
            m.drop_reply_command = None;
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
fn live_control_drift_quarantines_routes() {
    for fault in 0..9 {
        let mut fixture = Fixture::new();
        let model = idt73_device(0x111d_76c1);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
        let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
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
            .configure_analog_route(&graph, &output, stream, 0, idt83_playback())
            .unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.route_controls.insert((1, 0xf15), 0xa4);
                }
                1 => {
                    m.route_controls.insert((1, 0xf16), 0x5a);
                }
                2 => {
                    m.route_controls.insert((1, 0xf17), 0x3c);
                }
                3 => {
                    m.parameters.insert((1, 0x11), 7);
                }
                4 => {
                    m.parameters.insert((0x1f, 0x13), 0xff);
                }
                5 => {
                    m.route_controls.insert((0x1f, 0xf0f), 0x7f);
                }
                6 => {
                    m.idt83_power_map = 0x08;
                }
                7 => {
                    m.pin_defaults.insert(0x11, 0x4000_0100);
                }
                _ => {
                    m.parameters.insert((0x11, 0x0c), 0x10);
                }
            }
        }
        assert!(
            controller.refresh_idt73_power_map(&graph).is_err(),
            "fault={fault}"
        );
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        let before = model.borrow().commands.len();
        assert_eq!(controller.shutdown(), Err(Error::NeedsReset));
        assert_eq!(model.borrow().commands.len(), before);
        assert!(controller.stopped && controller.routes.len() == 1);
        controller.reinitialize().unwrap();
        assert!(controller.sigmatel_codecs.is_empty() && controller.routes.is_empty());
    }
}

#[test]
fn failed_quiet_stops_command_dma() {
    for stream_stuck in [false, true] {
        let mut fixture = Fixture::new();
        let model = idt73_device(0x111d_7675);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
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
            .configure_analog_route(&graph, &route, stream, 0, idt83_playback())
            .unwrap();
        controller.start(stream).unwrap();
        {
            let mut m = model.borrow_mut();
            if stream_stuck {
                m.stream_stop_stuck = true;
            } else {
                m.reject_route_control = Some(0xf15);
                m.reject_route_after_write = true;
                m.reject_route_write_threshold = 2;
            }
        }
        let before = model.borrow().commands.len();
        assert!(controller.shutdown().is_err());
        if stream_stuck {
            assert_eq!(model.borrow().commands.len(), before);
            assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0xa5);
            assert!(!controller.stopped);
        } else {
            assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0xa4);
            assert_eq!(model.borrow().get(CORBCTL, 1) & 2, 0);
            assert_eq!(model.borrow().get(RIRBCTL, 1) & 2, 0);
            assert!(controller.stopped);
        }
        assert_eq!(controller.sigmatel_codecs.len(), 1);
        {
            let mut m = model.borrow_mut();
            m.stream_stop_stuck = false;
            m.reject_route_control = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.sigmatel_codecs.is_empty());
    }
}

#[test]
fn failed_map_update_keeps_owner() {
    for lost_ack in [false, true] {
        let mut fixture = Fixture::new();
        let model = idt73_device(0x111d_76c0);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
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
            .configure_analog_route(&graph, &route, stream, 0, idt83_playback())
            .unwrap();
        controller.start(stream).unwrap();
        {
            let mut m = model.borrow_mut();
            m.pin_senses.insert(0x0a, 0);
            if lost_ack {
                m.drop_reply_command = Some((1 << 20) | 0x7ec89);
            } else {
                m.reject_route_control = Some(0xfec);
                m.reject_route_after_write = true;
                m.reject_route_write_threshold = 2;
            }
        }
        assert!(controller.poll_pin_sense(&graph, 0x0a).is_err());
        assert_eq!(model.borrow().idt83_power_map, 0x89);
        assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0xa5);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(controller.sigmatel_codecs.len(), 1);
        assert_eq!(controller.routes.len(), 1);
        {
            let mut m = model.borrow_mut();
            m.reject_route_control = None;
            m.drop_reply_command = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.sigmatel_codecs.is_empty() && controller.routes.is_empty());
    }
}
