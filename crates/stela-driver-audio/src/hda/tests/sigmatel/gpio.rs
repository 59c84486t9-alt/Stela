// SPDX-License-Identifier: GPL-2.0-only
//! gpio behavior tests.
use super::*;

#[test]
fn startup_gpio_and_duplex() {
    for id in [
        0x8384_7690,
        0x8384_7632,
        0x8384_7633,
        0x8384_7634,
        0x8384_7635,
        0x8384_7636,
        0x8384_7637,
    ] {
        let mut fixture = Fixture::new();
        let model = device(id);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_sigmatel_codec(&graph).unwrap();
        assert_eq!(report.codec_id, id);
        assert_eq!(report.revision_id, 0x0010_0100);
        assert_eq!(report.subsystem_id, 0x1043_8693);
        assert_eq!(
            report.gpio,
            SigmatelGpio {
                mask: 0x5a,
                direction: 0x3c,
                data: 0xa5
            }
        );
        {
            let m = model.borrow();
            assert_eq!(m.route_controls[&(1, 0xfe7)], 0);
            assert_eq!(m.route_controls[&(1, 0xf15)], 0xa5);
            assert_eq!(m.route_controls[&(1, 0xf16)], 0x5a);
            assert_eq!(m.route_controls[&(1, 0xf17)], 0x3c);
            let dir = m
                .command_times
                .iter()
                .find(|(cmd, _)| (*cmd >> 8) & 0xfff == 0x717)
                .unwrap()
                .1;
            let data = m
                .command_times
                .iter()
                .find(|(cmd, _)| (*cmd >> 8) & 0xfff == 0x715)
                .unwrap()
                .1;
            assert!(data - dir >= 1000);
            if id == 0x8384_7690 {
                assert_eq!(report.profile, SigmatelProfile::Stac9200);
                assert_eq!(report.eapd, Some((8, 2)));
                assert_eq!(m.route_controls[&(7, 0xf01)], 0);
                assert_eq!(m.route_controls[&(8, 0xf0c)], 2);
            } else {
                assert_eq!(report.profile, SigmatelProfile::Stac925x);
                assert_eq!(report.master_amplifier, Some((0x0e, 0x80)));
                for channel in 0..2 {
                    assert_eq!(m.amplifiers[&(0x0e, true, 0, channel)], 0x80);
                }
            }
        }
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_sigmatel_codec(&graph),
            Err(Error::RouteInUse)
        );
        assert_eq!(access_counts(&model), before);
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
        if id != 0x8384_7690 {
            for channel in 0..2 {
                assert_eq!(model.borrow().amplifiers[&(0x0e, true, 0, channel)], 0x1f);
            }
        }
        let sense = controller.poll_pin_sense(&graph, 5).unwrap();
        assert!(sense.present);
        assert_eq!(sense.impedance_code, Some(0x5a));
        assert!(model.borrow().sense_triggers.is_empty());
        controller.write_pcm(playback, 0, &[0x92; 256]).unwrap();
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
        let m = model.borrow();
        assert!(m.playback.len() >= 256);
        assert!(m.playback.iter().all(|byte| *byte == 0x92));
        for pin in [4, 5, 8] {
            assert_eq!(m.route_controls[&(pin, 0xf07)], 0);
        }
    }
}

#[test]
fn startup_failure_keeps_owner() {
    for id in [0x8384_7690, 0x8384_7632] {
        for fault in 0..9 {
            let mut fixture = Fixture::new();
            let model = device(id);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            if fault < 8 {
                let mut m = model.borrow_mut();
                m.reject_route_after_write = matches!(fault, 1..=3);
                match fault {
                    0 => m.power_stuck = true,
                    1 => m.reject_route_control = Some(0xf16),
                    2 => m.reject_route_control = Some(0xf17),
                    3 => m.reject_route_control = Some(0xf15),
                    4 => m.reject_route_control = Some(0xf01),
                    5 => {
                        if id == 0x8384_7690 {
                            m.reject_route_control = Some(0xf0c);
                        } else {
                            m.reject_amplifier = true;
                        }
                    }
                    6 => m.reject_route_control = Some(0xf15),
                    _ => m.drop_reply_command = Some((1 << 20) | (0x7e7 << 8)),
                }
            }
            let result = controller.initialize_sigmatel_codec(&graph);
            if fault < 8 {
                assert!(result.is_err());
            } else {
                result.unwrap();
                model.borrow_mut().reject_route_control = Some(0xf07);
                assert_eq!(controller.shutdown(), Err(Error::RouteRejected));
                assert!(controller.stopped);
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
                m.power_stuck = false;
                m.reject_route_control = None;
                m.reject_route_after_write = false;
                m.drop_reply_command = None;
                m.reject_amplifier = false;
            }
            controller.reinitialize().unwrap();
            assert!(controller.sigmatel_codecs.is_empty());
            assert_eq!(
                controller.initialize_sigmatel_codec(&graph),
                Err(Error::InvalidCodecGraph)
            );
        }
    }
}

#[test]
fn invalid_gpio_controls_rejected() {
    for fault in 0..6 {
        let mut fixture = Fixture::new();
        let model = device(if fault == 0 {
            0x111d_76b0
        } else if fault == 5 {
            0x8384_7632
        } else {
            0x8384_7690
        });
        if fault == 1 {
            model.borrow_mut().parameters.insert((8, 0x0c), 0x18);
        }
        if fault == 2 {
            model.borrow_mut().parameters.insert((1, 0x11), 9);
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        if fault == 3 {
            model.borrow_mut().parameters.insert((0, 2), u32::MAX);
        }
        if fault == 4 {
            model.borrow_mut().parameters.insert((7, 9), 0xf << 20);
        }
        if fault == 5 {
            model.borrow_mut().parameters.insert((1, 0x12), 0x0000_1f1f);
        }
        let before = model.borrow().commands.len();
        assert!(controller.initialize_sigmatel_codec(&graph).is_err());
        assert!(controller.sigmatel_codecs.is_empty());
        assert!(
            model.borrow().commands[before..]
                .iter()
                .all(|cmd| (*cmd >> 8) & 0xfff >= 0xf00)
        );
    }
}

#[test]
fn lost_identity_blocks_reuse() {
    for quiet_failure in [false, true] {
        let mut fixture = Fixture::new();
        let model = device(0x8384_7690);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
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
            .configure_analog_route(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd: None,
                },
            )
            .unwrap();
        if quiet_failure {
            controller.start(stream).unwrap();
            model.borrow_mut().stream_stop_stuck = true;
            let before = model.borrow().commands.len();
            assert!(controller.shutdown().is_err());
            assert_eq!(model.borrow().commands.len(), before);
            assert!(!controller.stopped);
            model.borrow_mut().stream_stop_stuck = false;
        } else {
            model.borrow_mut().parameters.insert((8, 0x0c), 0x18);
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
        }
        assert_eq!(controller.routes.len(), 1);
        assert_eq!(controller.sigmatel_codecs.len(), 1);
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty());
        assert!(controller.sigmatel_codecs.is_empty());
    }
}

#[test]
fn unclaimed_gpio_levels_preserved() {
    for active_undeclared in [false, true] {
        let mut fixture = Fixture::new();
        let model = device(0x8384_7690);
        {
            let mut m = model.borrow_mut();
            m.parameters.insert((1, 0x11), 0);
            for verb in [0xf15, 0xf16, 0xf17] {
                m.route_controls.insert((1, verb), 0);
            }
            if active_undeclared {
                m.route_controls.insert((1, 0xf15), 1);
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let before = model.borrow().commands.len();
        let result = controller.initialize_sigmatel_codec(&graph);
        if active_undeclared {
            assert_eq!(result, Err(Error::RouteRejected));
            assert_eq!(controller.sigmatel_codecs.len(), 1);
            assert!(controller.routing_failed);
            assert!(
                !model.borrow().commands[before..]
                    .iter()
                    .any(|cmd| (*cmd >> 8) & 0xfff == 0x7e7)
            );
        } else {
            assert_eq!(
                result.unwrap().gpio,
                SigmatelGpio {
                    mask: 0,
                    direction: 0,
                    data: 0
                }
            );
            assert_eq!(model.borrow().route_controls[&(1, 0xf15)], 0);
            controller.shutdown().unwrap();
        }
    }
}

#[test]
fn vendor_owners_are_exclusive() {
    for initial_sigmatel in [false, true] {
        let mut fixture = Fixture::new();
        let model = device(if initial_sigmatel {
            0x8384_7690
        } else {
            0x14f1_5047
        });
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        if initial_sigmatel {
            controller.initialize_sigmatel_codec(&graph).unwrap();
        } else {
            controller.initialize_conexant_codec(&graph).unwrap();
        }
        model.borrow_mut().parameters.insert(
            (0, 0),
            if initial_sigmatel {
                0x14f1_5047
            } else {
                0x8384_7690
            },
        );
        let new_graph = controller.enumerate_codec(0).unwrap();
        let before = access_counts(&model);
        if initial_sigmatel {
            assert_eq!(
                controller.initialize_conexant_codec(&new_graph),
                Err(Error::RouteInUse)
            );
            assert!(controller.conexant_codecs.is_empty());
        } else {
            assert_eq!(
                controller.initialize_sigmatel_codec(&new_graph),
                Err(Error::RouteInUse)
            );
            assert!(controller.sigmatel_codecs.is_empty());
        }
        assert_eq!(access_counts(&model), before);
        assert_eq!(
            controller.conexant_codecs.len() + controller.sigmatel_codecs.len(),
            1
        );
    }
}
