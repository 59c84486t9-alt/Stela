// SPDX-License-Identifier: GPL-2.0-only
//! stac922x behavior tests.
use super::*;

#[test]
fn knob_capture_range_and_duplex() {
    for id in [
        0x8384_7882,
        0x8384_7680,
        0x8384_7880,
        0x8384_7681,
        0x8384_7682,
        0x8384_7683,
    ] {
        for inherited in [false, true] {
            let mut fixture = Fixture::new();
            let model = stac922x_device(id, inherited);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_sigmatel_codec(&graph).unwrap();
            assert_eq!(report.profile, SigmatelProfile::Stac922x);
            assert_eq!(report.selector_node, None);
            assert_eq!(report.volume_knob, Some((0x16, 0xff)));
            assert_eq!(report.capture_output_amplifier, Some((0x12, 0x0027_0200)));
            assert_eq!(report.eapd, None);
            assert_eq!(report.master_amplifier, None);
            assert_eq!(model.borrow().route_controls[&(0x16, 0xf0f)], 0xff);
            // No board-specific GPIO0 or Intel-Mac GPIO0/1 grant.
            assert_eq!(report.gpio.data, 0xa5);
            assert_eq!(report.gpio.mask, 0x5a);
            assert_eq!(report.gpio.direction, 0x3c);
            let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
            assert_eq!(input.nodes(), &[3, 0x12, 5]);
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
                .configure_analog_route(
                    &graph,
                    &output,
                    playback,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None,
                    },
                )
                .unwrap();
            let before = model.borrow().commands.len();
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
                let physical: Vec<_> = m.commands[before..]
                    .iter()
                    .filter(|command| {
                        (**command >> 20) & 127 == 0x12 && (**command >> 16) & 15 == 3
                    })
                    .collect();
                assert_eq!(physical.len(), 1); // No invented bit7 pre-mute.
                assert_eq!(*physical[0] as u16, 0xb000); // Both channels, gain0.
                for channel in 0..2 {
                    assert_eq!(m.amplifiers[&(0x12, true, 0, channel)], 0);
                }
            }
            assert_eq!(
                graph.widget(0x12).unwrap().output_amplifier,
                Some(0x8000_1f1f)
            );
            assert_eq!(
                graph.widget(0x12).unwrap().capabilities & 8 != 0,
                !inherited
            );
            assert!(controller.poll_pin_sense(&graph, 5).unwrap().present);
            assert!(model.borrow().sense_triggers.is_empty());
            controller.write_pcm(playback, 0, &[0x22; 256]).unwrap();
            controller.fill_capture(capture, 0xa5).unwrap();
            controller.start(capture).unwrap();
            controller.start(playback).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 8);
            assert!(controller.status(playback).unwrap().period_completed);
            assert!(controller.status(capture).unwrap().period_completed);
            controller.stop(capture).unwrap();
            let mut samples = [0; 256];
            controller.read_pcm(capture, 0, &mut samples).unwrap();
            assert_eq!(samples, core::array::from_fn(|index| index as u8));
            controller.shutdown().unwrap();
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x22));
            assert!(model.borrow().playback.len() >= 256);
            for pin in [4, 5, 8] {
                assert_eq!(model.borrow().route_controls[&(pin, 0xf07)], 0);
            }
        }
    }
}

#[test]
fn invalid_knob_rejected() {
    for fault in 0..7 {
        let mut fixture = Fixture::new();
        let model = stac922x_device(0x8384_7680, false);
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => {
                    m.parameters.insert((0, 0), 0x8384_7684);
                }
                1 => {
                    m.parameters.insert((0x16, 9), 0xf << 20);
                }
                2 => {
                    m.parameters.insert((0x16, 0x13), 0x1f);
                }
                3 => {
                    m.parameters.insert((0x16, 0x13), u32::MAX);
                }
                4 => {
                    m.parameters.insert((0x12, 9), (3 << 20) | 1 | (1 << 8));
                }
                5 => {
                    m.parameters.insert((0x12, 0x12), u32::MAX);
                }
                _ => {
                    m.parameters.insert((0x12, 0x0e), 0);
                }
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let before = model.borrow().commands.len();
        assert!(controller.initialize_sigmatel_codec(&graph).is_err());
        assert!(controller.sigmatel_codecs.is_empty());
        assert!(!controller.routing_failed);
        assert!(
            model.borrow().commands[before..]
                .iter()
                .all(|command| command & (1 << 19) != 0)
        );
    }
}

#[test]
fn failed_capture_requires_reset() {
    for fault in 0..3 {
        let mut fixture = Fixture::new();
        let model = stac922x_device(0x8384_7882, false);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        if fault == 0 {
            let mut m = model.borrow_mut();
            m.reject_route_control = Some(0xf0f);
            m.reject_route_after_write = true;
        } else if fault == 1 {
            model.borrow_mut().drop_reply_command = Some((0x16 << 20) | 0x70fff);
        }
        if fault < 2 {
            assert!(controller.initialize_sigmatel_codec(&graph).is_err());
            assert_eq!(model.borrow().route_controls[&(0x16, 0xf0f)], 0xff);
        } else {
            controller.initialize_sigmatel_codec(&graph).unwrap();
            let route = graph.analog_route(Direction::Capture, 5, 3).unwrap();
            let stream = controller
                .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
                .unwrap();
            model.borrow_mut().reject_amplifier_channel = Some((0x12, 1));
            assert_eq!(
                controller.configure_analog_route(
                    &graph,
                    &route,
                    stream,
                    0,
                    PinOptions::Capture {
                        vref: Vref::EightyPercent
                    }
                ),
                Err(Error::RouteRejected)
            );
            assert_eq!(model.borrow().amplifiers[&(0x12, true, 0, 1)], 0);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        }
        assert!(controller.routing_failed);
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
            m.reject_amplifier_channel = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.sigmatel_codecs.is_empty());
        assert!(controller.routes.is_empty());
        assert_eq!(
            controller.initialize_sigmatel_codec(&graph),
            Err(Error::InvalidCodecGraph)
        );
    }
}

#[test]
fn live_amp_drift_quarantines_pcm() {
    for fault in 0..3 {
        let mut fixture = Fixture::new();
        let inherited = fault == 2;
        let model = stac922x_device(0x8384_7683, inherited);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Capture, 5, 3).unwrap();
        let stream = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller
            .configure_analog_route(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Capture {
                    vref: Vref::EightyPercent,
                },
            )
            .unwrap();
        model.borrow_mut().parameters.insert(
            if fault == 0 {
                (0x16, 0x13)
            } else if inherited {
                (1, 0x12)
            } else {
                (0x12, 0x12)
            },
            if fault == 0 { 0x7f } else { 0x8000_1f0f },
        );
        assert_eq!(
            controller.poll_pin_sense(&graph, 5),
            Err(Error::InvalidCodecGraph)
        );
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        let before = model.borrow().commands.len();
        assert_eq!(controller.shutdown(), Err(Error::NeedsReset));
        assert!(controller.stopped);
        assert_eq!(model.borrow().commands.len(), before);
        assert_eq!(controller.routes.len(), 1);
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty());
        assert!(controller.sigmatel_codecs.is_empty());
    }
}
