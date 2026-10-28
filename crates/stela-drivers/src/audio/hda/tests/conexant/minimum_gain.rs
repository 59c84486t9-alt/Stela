// SPDX-License-Identifier: GPL-2.0-only
//! minimum gain behavior tests.
use super::*;

#[test]
fn conexant_cx20561_actual_minimum_gain_mute_preserves_mono_stereo_and_hardware_mute() {
    for converter in [0x10, 0x11] {
        for channels in [1, 2] {
            for hardware_mute in [false, true] {
                let mut fixture = Fixture::new();
                let model = minimum_mute_device(0x14f1_5051, converter, channels, hardware_mute);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                controller.initialize_conexant_codec(&graph).unwrap();
                let route = graph
                    .analog_route(Direction::Playback, 4, converter)
                    .unwrap();
                let stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        PcmFormat {
                            channels,
                            ..stereo()
                        },
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                let before = model.borrow().commands.len();
                controller
                    .configure_analog_route(&graph, &route, stream, 0, playback_options())
                    .unwrap();
                {
                    let m = model.borrow();
                    let gains: Vec<_> = m.commands[before..]
                        .iter()
                        .filter(|cmd| {
                            (**cmd >> 20) & 127 == u32::from(converter) && (**cmd >> 16) & 15 == 3
                        })
                        .map(|cmd| *cmd as u8)
                        .collect();
                    assert_eq!(
                        gains,
                        if hardware_mute {
                            vec![0x9f, 0x1f]
                        } else {
                            vec![0, 0x1f]
                        }
                    );
                    for channel in 0..channels {
                        assert_eq!(m.amplifiers[&(converter, true, 0, channel)], 0x1f);
                    }
                }
                controller.write_pcm(stream, 0, &[0x51; 256]).unwrap();
                controller.start(stream).unwrap();
                controller
                    .set_conexant_cx20561_converter_muted(&graph, converter, true)
                    .unwrap();
                for channel in 0..channels {
                    assert_eq!(
                        model.borrow().amplifiers[&(converter, true, 0, channel)],
                        if hardware_mute { 0x9f } else { 0 }
                    );
                }
                assert!(controller.status(stream).unwrap().running);
                controller
                    .set_conexant_cx20561_converter_muted(&graph, converter, false)
                    .unwrap();
                for channel in 0..channels {
                    assert_eq!(
                        model.borrow().amplifiers[&(converter, true, 0, channel)],
                        0x1f
                    );
                }
                model.borrow_mut().dma_step_bytes = 128;
                advance(&model, 8);
                assert!(controller.status(stream).unwrap().period_completed);
                controller.shutdown().unwrap();
                assert!(model.borrow().playback.len() >= 256);
                assert!(model.borrow().playback.iter().all(|byte| *byte == 0x51));
            }
        }
    }
}

#[test]
fn conexant_minimum_mute_policy_does_not_leak_to_other_codecs_or_nonowned_dacs() {
    let mut fixture = Fixture::new();
    let model = minimum_mute_device(0x14f1_5047, 0x10, 2, false);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_conexant_codec(&graph).unwrap();
    let route = graph.analog_route(Direction::Playback, 4, 0x10).unwrap();
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
    controller
        .configure_analog_route(&graph, &route, stream, 0, playback_options())
        .unwrap();
    let m = model.borrow();
    let gains: Vec<_> = m.commands[before..]
        .iter()
        .filter(|cmd| (**cmd >> 20) & 127 == 0x10 && (**cmd >> 16) & 15 == 3)
        .map(|cmd| *cmd as u8)
        .collect();
    assert_eq!(gains, vec![0x1f]);
    drop(m);
    let before = access_counts(&model);
    assert_eq!(
        controller.set_conexant_cx20561_converter_muted(&graph, 0x10, true),
        Err(Error::UnsupportedTopology)
    );
    assert_eq!(access_counts(&model), before);

    let mut fixture = Fixture::new();
    let model = minimum_mute_device(0x14f1_5051, 0x10, 2, false);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_conexant_codec(&graph).unwrap();
    let before = access_counts(&model);
    assert_eq!(
        controller.set_conexant_cx20561_converter_muted(&graph, 0x11, true),
        Err(Error::RouteInUse)
    );
    assert_eq!(access_counts(&model), before);
    assert_eq!(
        controller.set_conexant_cx20561_converter_muted(&graph, 2, true),
        Err(Error::UnsupportedTopology)
    );
}

#[test]
fn conexant_minimum_mute_rejected_physical_gain_or_live_amp_authority_quarantines_routes() {
    for changed_caps in [false, true] {
        let mut fixture = Fixture::new();
        let model = minimum_mute_device(0x14f1_5051, 0x10, 2, false);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_conexant_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 0x10).unwrap();
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
            .configure_analog_route(&graph, &route, stream, 0, playback_options())
            .unwrap();
        if changed_caps {
            model
                .borrow_mut()
                .parameters
                .insert((0x10, 0x12), 0x0000_1f0f);
        } else {
            model.borrow_mut().reject_amplifier = true;
        }
        assert_eq!(
            controller.set_conexant_cx20561_converter_muted(&graph, 0x10, true),
            Err(if changed_caps {
                Error::InvalidCodecGraph
            } else {
                Error::RouteRejected
            })
        );
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        assert_eq!(controller.routes.len(), 1);
        assert_eq!(controller.conexant_codecs.len(), 1);
        model.borrow_mut().reject_amplifier = false;
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty());
    }
}

#[test]
fn conexant_minimum_mute_inherits_live_group_caps_and_refuses_an_unusable_zero_db_code() {
    for refusal in 0..3 {
        let mut fixture = Fixture::new();
        let model = minimum_mute_device(0x14f1_5051, 0x10, 2, false);
        {
            let mut m = model.borrow_mut();
            m.parameters
                .insert((0x10, 9), if refusal == 2 { 1 } else { 1 | (1 << 2) }); // FG amp inheritance.
            m.parameters.insert(
                (1, 0x12),
                if refusal == 1 {
                    0x0000_1f00
                } else {
                    0x0000_1f1f
                },
            );
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_conexant_codec(&graph).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 0x10).unwrap();
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let before = access_counts(&model);
        let result =
            controller.configure_analog_route(&graph, &route, stream, 0, playback_options());
        if refusal != 0 {
            assert_eq!(result, Err(Error::UnsupportedTopology));
            assert_eq!(access_counts(&model), before);
            assert!(!controller.routing_failed);
        } else {
            result.unwrap();
            let before = model.borrow().commands.len();
            controller
                .set_conexant_cx20561_converter_muted(&graph, 0x10, true)
                .unwrap();
            assert_eq!(model.borrow().amplifiers[&(0x10, true, 0, 0)], 0);
            assert!(model.borrow().commands[before..].contains(&((1 << 20) | 0xf0012)));
            model.borrow_mut().parameters.insert((1, 0x12), u32::MAX);
            assert_eq!(
                controller.set_conexant_cx20561_converter_muted(&graph, 0x10, false),
                Err(Error::InvalidCodecGraph)
            );
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        }
    }
}
