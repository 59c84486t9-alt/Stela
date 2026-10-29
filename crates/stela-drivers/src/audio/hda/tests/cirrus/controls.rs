// SPDX-License-Identifier: GPL-2.0-only
//! Cirrus codec control tests.
use super::*;
// Exercises Cirrus controls through the shared command-ring/DMA model.
mod cs4213 {
    use super::*;

    pub(super) fn device(inherited: bool, raw_steps: u8) -> Rc<RefCell<Model>> {
        let model = cs4210_device(inherited, raw_steps);
        let mut m = model.borrow_mut();
        m.cirrus_cs4210_model = false;
        m.parameters.insert((0, 0), 0x1013_4213);
        m.parameters.insert((1, 4), (2 << 16) | 8);
        // CS4213 has no SPDIF and its vendor node9 has no coefficient recipe.
        m.parameters.insert((9, 9), 0xf << 20);
        m.parameters.remove(&(9, 0x10));
        drop(m);
        model
    }

    #[test]
    fn cs4213_dac_range_and_duplex() {
        for inherited in [false, true] {
            for raw_steps in [15, 63] {
                let mut fixture = Fixture::new();
                let model = device(inherited, raw_steps);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                let report = controller.initialize_cirrus_codec(&graph).unwrap();
                assert_eq!(report.profile, CirrusProfile::Cs4213);
                assert_eq!(report.processing_node, 9);
                assert!(report.coefficients.is_empty());
                assert_eq!(report.errata_coefficients_acknowledged, 0);
                assert_eq!(report.output_amplifiers[0].effective_caps & 0x7f00, 31 << 8);
                assert_eq!(
                    graph.widget(2).unwrap().output_amplifier.unwrap() >> 8 & 127,
                    u32::from(raw_steps)
                );
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
                let output = graph.analog_route(Direction::Playback, 6, 2).unwrap();
                let input = graph.analog_route(Direction::Capture, 8, 3).unwrap();
                controller
                    .configure_analog_route(&graph, &output, out, 0, cs4210_playback())
                    .unwrap();
                controller
                    .configure_cirrus_route(&graph, &input, mic, 0, capture())
                    .unwrap();
                for channel in 0..2 {
                    assert_eq!(model.borrow().amplifiers[&(2, true, 0, channel)], 31);
                    assert_eq!(model.borrow().amplifiers[&(3, false, 1, channel)], 31);
                }
                controller.write_pcm(out, 0, &[0x71; 256]).unwrap();
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
                assert!(m.playback.len() >= 256 && m.playback.iter().all(|byte| *byte == 0x71));
                assert!(m.coefficient_events.is_empty());
                assert!(!m.commands.iter().any(|command| {
                    let node = (command >> 20) & 0x7f;
                    let verb = (command >> 8) & 0xfff;
                    node == 9
                        && (verb == 0x703
                            || verb == 0xf03
                            || (verb == 0xf00 && command & 255 == 0x10)
                            || matches!((command >> 16) & 15, 4 | 5 | 12 | 13))
                }));
            }
        }
    }

    #[test]
    fn cs4213_invalid_profile_blocks_routes() {
        let mut fixture = Fixture::new();
        let model = device(false, 63);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_cirrus_codec(&graph).unwrap();
        model.borrow_mut().parameters.insert((2, 0x12), 0x8003_3f1e);
        assert_eq!(
            controller.poll_cirrus_pin_sense(&graph, 5),
            Err(Error::InvalidCodecGraph)
        );
        assert!(controller.routing_failed);
        assert!(controller.cirrus_codecs[0].authority_lost());
        assert!(controller.shutdown().is_err());
        controller.reinitialize().unwrap();
        assert!(controller.cirrus_codecs.is_empty());
        model.borrow_mut().parameters.insert((0, 0), 0x1013_4214);
        let graph = controller.enumerate_codec(0).unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_cirrus_codec(&graph),
            Err(Error::UnsupportedTopology)
        );
        assert_eq!(access_counts(&model), before);
    }
}

mod power {
    use super::*;

    fn device(cs4210: bool) -> Rc<RefCell<Model>> {
        let model = if cs4210 {
            cs4210_device(false, 63)
        } else {
            cs4213::device(false, 63)
        };
        let mut m = model.borrow_mut();
        m.codec_power_model = true;
        m.parameters.insert((1, 0x0f), 9);
        for node in [2, 3] {
            *m.parameters.get_mut(&(node, 9)).unwrap() |= 1 << 10;
            m.parameters.insert((node, 0x0f), 9);
        }
        drop(m);
        model
    }

    #[test]
    fn cs421x_d3hot_replays_pcm() {
        for cs4210 in [false, true] {
            let mut fixture = Fixture::new();
            let model = device(cs4210);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_cirrus_codec(&graph).unwrap();
            // The cold errata model has now verified the first complete recipe.
            // Subsequent source init is checked independently from command logs.
            model.borrow_mut().cirrus_cs4210_model = false;
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
            let output = graph.analog_route(Direction::Playback, 6, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 8, 3).unwrap();
            controller
                .configure_cirrus_route(&graph, &output, out, 0, cs4210_playback())
                .unwrap();
            controller
                .configure_cirrus_route(&graph, &input, mic, 0, capture())
                .unwrap();
            if cs4210 {
                controller
                    .set_cirrus_cs4210_speaker_boost(&graph, 3)
                    .unwrap();
            }
            controller.write_pcm(out, 0, &[0x4b; 256]).unwrap();
            for _ in 0..2 {
                controller.start(out).unwrap();
                let before = access_counts(&model);
                assert_eq!(
                    controller.suspend_cirrus_cs421x(&graph),
                    Err(Error::StreamRunning)
                );
                assert_eq!(access_counts(&model), before);
                controller.stop(out).unwrap();
                let first = model.borrow().commands.len();
                controller.suspend_cirrus_cs421x(&graph).unwrap();
                {
                    let m = model.borrow();
                    for node in [1, 2, 3] {
                        assert_eq!(m.codec_actual_power[&node], 3);
                    }
                    let writes: Vec<_> = m.commands[first..]
                        .iter()
                        .filter(|command| (*command >> 8) & 0xfff == 0x705)
                        .map(|command| (((command >> 20) & 127) as u8, (command & 255) as u8))
                        .collect();
                    assert_eq!(writes, vec![(2, 3), (3, 3), (1, 3)]);
                    let commands = &m.commands[first..];
                    let power_position = |node| {
                        commands
                            .iter()
                            .position(|command| {
                                (command >> 20) & 127 == node
                                    && (command >> 8) & 0xfff == 0x705
                                    && command & 255 == 3
                            })
                            .unwrap()
                    };
                    let dac_d3 = power_position(2);
                    let adc_d3 = power_position(3);
                    let afg_d3 = power_position(1);
                    let last_pin_quiet = commands
                        .iter()
                        .rposition(|command| (command >> 8) & 0xfff == 0x707 && command & 255 == 0)
                        .unwrap();
                    let last_pin_ack = commands
                        .iter()
                        .rposition(|command| (command >> 8) & 0xfff == 0xf07)
                        .unwrap();
                    assert!(
                        last_pin_quiet < last_pin_ack
                            && last_pin_ack < dac_d3
                            && dac_d3 < adc_d3
                            && adc_d3 < afg_d3
                    );
                    if cs4210 {
                        let pdref = commands
                            .iter()
                            .position(|command| {
                                (command >> 20) & 127 == 11
                                    && (command >> 16) & 15 == 4
                                    && command & 0xffff == 5
                            })
                            .unwrap();
                        let adc_ack = commands[..pdref]
                            .iter()
                            .rposition(|command| {
                                (command >> 20) & 127 == 3 && (command >> 8) & 0xfff == 0xf05
                            })
                            .unwrap();
                        assert!(adc_d3 < adc_ack && adc_ack < pdref && pdref < afg_d3);
                    }

                    if cs4210 {
                        assert_eq!(m.coefficients[&(11, 1)] & 4, 4);
                    }
                    for pin in [5, 6, 7, 8] {
                        assert_eq!(m.route_controls[&(pin, 0xf07)], 0);
                    }
                }
                let before = access_counts(&model);
                assert_eq!(controller.start(out), Err(Error::NeedsReset));
                assert_eq!(access_counts(&model), before);
                let resume_first = model.borrow().commands.len();
                let coefficient_first = model.borrow().coefficient_events.len();
                controller.resume_cirrus_cs421x(&graph).unwrap();
                {
                    let m = model.borrow();
                    let commands = &m.commands[resume_first..];
                    let afg_d0 = commands
                        .iter()
                        .position(|command| {
                            (command >> 20) & 127 == 1
                                && (command >> 8) & 0xfff == 0x705
                                && command & 255 == 0
                        })
                        .unwrap();
                    let dac_d0 = commands
                        .iter()
                        .position(|command| {
                            (command >> 20) & 127 == 2
                                && (command >> 8) & 0xfff == 0x705
                                && command & 255 == 0
                        })
                        .unwrap();
                    let rebind = commands
                        .iter()
                        .position(|command| (command >> 8) & 0xfff == 0x706)
                        .unwrap();
                    assert!(afg_d0 < dac_d0 && dac_d0 < rebind);
                    let coefficients: Vec<_> = m.coefficient_events[coefficient_first..]
                        .iter()
                        .map(|(node, index, value, _)| (*node, *index, *value))
                        .collect();
                    if cs4210 {
                        assert_eq!(
                            coefficients,
                            vec![
                                (11, 1, 5),
                                (11, 1, 1),
                                (11, 2, 2),
                                (11, 3, 14),
                                (11, 6, 0x9999),
                                (11, 10, 0x14cb),
                                (11, 17, 0xa2d0),
                                (11, 26, 0x02a9),
                                (11, 27, 0x1006),
                                (11, 1, 1),
                                (11, 4, 0xd5a3)
                            ]
                        );
                        let first_coefficient = commands
                            .iter()
                            .position(|command| {
                                (command >> 20) & 127 == 11 && (command >> 16) & 15 == 4
                            })
                            .unwrap();
                        let last_startup = commands[..dac_d0]
                            .iter()
                            .rposition(|command| {
                                (command >> 20) & 127 == 11 && (command >> 16) & 15 == 4
                            })
                            .unwrap();
                        assert!(
                            afg_d0 < first_coefficient
                                && first_coefficient < last_startup
                                && last_startup < dac_d0
                        );
                    } else {
                        assert!(coefficients.is_empty());
                    }
                }
                assert_eq!(controller.routes.len(), 2);
                if cs4210 {
                    assert_eq!(model.borrow().coefficients[&(11, 4)] & 3, 3);
                }
                controller.fill_capture(mic, 0xa5).unwrap();
                controller.start(out).unwrap();
                controller.start(mic).unwrap();
                model.borrow_mut().dma_step_bytes = 128;
                advance(&model, 8);
                assert!(controller.status(out).unwrap().period_completed);
                assert!(controller.status(mic).unwrap().period_completed);
                controller.stop(out).unwrap();
                controller.stop(mic).unwrap();
                let mut captured = [0xa5; 256];
                controller.read_pcm(mic, 0, &mut captured).unwrap();
                assert_eq!(captured, core::array::from_fn(|index| index as u8));
            }
            controller.shutdown().unwrap();
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x4b));
        }
    }

    #[test]
    fn cs421x_power_ownership_preflight() {
        for capture_only in [false, true] {
            let mut fixture = Fixture::new();
            let model = device(false);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_cirrus_codec(&graph).unwrap();
            let out = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            if capture_only {
                let mic = controller
                    .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
                    .unwrap();
                let input = graph.analog_route(Direction::Capture, 8, 3).unwrap();
                controller
                    .configure_cirrus_route(&graph, &input, mic, 0, capture())
                    .unwrap();
            }
            // A firmware/native binding outside the route set must
            // refuse before any quiet/power effect, independent of the ledger.
            model.borrow_mut().bindings.insert(2, (out.tag() << 4) | 1);
            assert_eq!(
                controller.suspend_cirrus_cs421x(&graph),
                Err(Error::RouteInUse)
            );
            assert!(!controller.cirrus_codecs[0].suspended());
            model.borrow_mut().bindings.insert(2, 0);
            controller.suspend_cirrus_cs421x(&graph).unwrap();
            let before = access_counts(&model);
            assert_eq!(
                controller.bind_converter(&graph, 2, out, 0),
                Err(Error::NeedsReset)
            );
            assert_eq!(access_counts(&model), before);
            controller.resume_cirrus_cs421x(&graph).unwrap();
            controller.shutdown().unwrap();
        }
    }

    #[test]
    fn cs421x_power_failure_retains_routes() {
        for fail_resume in [false, true] {
            let mut fixture = Fixture::new();
            let model = device(false);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_cirrus_codec(&graph).unwrap();
            let out = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let route = graph.analog_route(Direction::Playback, 6, 2).unwrap();
            controller
                .configure_cirrus_route(&graph, &route, out, 0, cs4210_playback())
                .unwrap();
            if fail_resume {
                controller.suspend_cirrus_cs421x(&graph).unwrap();
                model.borrow_mut().reject_route_control = Some(0xf07);
                model.borrow_mut().reject_route_node = Some(6);
                assert!(controller.resume_cirrus_cs421x(&graph).is_err());
            } else {
                model.borrow_mut().power_stuck = true;
                assert_eq!(
                    controller.suspend_cirrus_cs421x(&graph),
                    Err(Error::Timeout(Phase::CodecPower))
                );
            }
            assert_eq!(controller.routes, vec![(out, route)]);
            assert!(controller.routing_failed && controller.cirrus_codecs[0].authority_lost());
            assert_eq!(controller.start(out), Err(Error::NeedsReset));
            model.borrow_mut().power_stuck = false;
            model.borrow_mut().reject_route_control = None;
            controller.reinitialize().unwrap();
            assert!(controller.routes.is_empty() && controller.cirrus_codecs.is_empty());
        }
    }
    // Shared PCI/codec composition regression.
    #[test]
    fn cs421x_suspended_pcm_owner_survives_failed_controller_reset() {
        for cs4210 in [false, true] {
            let mut fixture = Fixture::new();
            let model = device(cs4210);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_cirrus_codec(&graph).unwrap();
            model.borrow_mut().cirrus_cs4210_model = false;
            let output = graph.analog_route(Direction::Playback, 6, 2).unwrap();
            let out = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            controller
                .configure_analog_route(&graph, &output, out, 0, cs4210_playback())
                .unwrap();
            controller.suspend_cirrus_cs421x(&graph).unwrap();
            let pcm = controller.stream(out).unwrap().buffer.physical();
            let before = access_counts(&model);
            assert_eq!(controller.start(out), Err(Error::NeedsReset));
            assert_eq!(access_counts(&model), before);
            model.borrow_mut().reset_exit_stuck = true;
            assert!(controller.reinitialize().is_err());
            assert_eq!(controller.cirrus_codecs.len(), 1);
            assert_eq!(controller.routes, vec![(out, output)]);
            assert_eq!(controller.converter_bindings.len(), 1);
            assert_eq!(
                controller.streams[usize::from(out.descriptor_index())]
                    .as_ref()
                    .unwrap()
                    .buffer
                    .physical(),
                pcm
            );
            model.borrow_mut().reset_exit_stuck = false;
            controller.reinitialize().unwrap();
            assert!(controller.cirrus_codecs.is_empty() && controller.routes.is_empty());
            assert!(controller.converter_bindings.is_empty());
            assert!(controller.start(out).is_err());
        }
    }
}
