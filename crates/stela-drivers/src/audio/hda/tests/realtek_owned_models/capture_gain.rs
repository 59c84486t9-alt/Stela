// SPDX-License-Identifier: GPL-2.0-only
//! capture gain controller-model tests.
use super::*;

fn adc_model(id: u32) -> Rc<RefCell<Model>> {
    let model = family_model(id);
    {
        let mut m = model.borrow_mut();
        m.parameters.insert((3, 0x0e), 2);
        m.connection_words.insert((3, 0), 4 | (5 << 8));
        // Linux alc_alloc_spec's single_adc_amp: connection one is
        // selected, while only physical ADC amplifier zero exists.
        m.adc_amp_index_zero.push(3);
    }
    model
}
fn capture(
    controller: &mut Host,
    fixture: &mut Fixture,
    graph: &CodecGraph,
    channels: u8,
) -> StreamId {
    let route = graph.analog_route(Direction::Capture, 5, 3).unwrap();
    let stream = controller
        .allocate_stream(
            Direction::Capture,
            PcmFormat {
                channels,
                ..stereo()
            },
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    controller
        .configure_realtek_route(
            graph,
            &route,
            stream,
            0,
            PinOptions::Capture {
                vref: Vref::EightyPercent,
            },
        )
        .unwrap();
    stream
}

#[test]
fn all_family_capture_gain_uses_adc_zero_during_real_duplex_dma() {
    for &id in IDS {
        let mut fixture = Fixture::new();
        let model = adc_model(id);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_realtek_codec(&graph).unwrap();
        let input = capture(&mut controller, &mut fixture, &graph, 2);
        let output_route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let output = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        controller
            .configure_realtek_route(&graph, &output_route, output, 0, playback())
            .unwrap();
        controller.write_pcm(output, 0, &[0x5a; 256]).unwrap();
        assert_eq!(model.borrow().route_controls[&(3, 0xf01)], 1);
        // A different input's state must not be touched by a volume change.
        model.borrow_mut().amplifiers.insert((3, false, 1, 0), 0x93);
        model.borrow_mut().amplifiers.insert((3, false, 1, 1), 0x94);
        for _ in 0..2 {
            controller.start(input).unwrap();
            controller.start(output).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 8);
            controller
                .set_realtek_capture_gain(&graph, input, 3, 7, true)
                .unwrap();
            let observed = controller.realtek_capture_gain(&graph, input, 3).unwrap();
            assert_eq!(observed.input_index, 0);
            assert_eq!(observed.capabilities, 0x8000_1f1f);
            assert_eq!(
                observed.levels,
                [AmplifierLevel {
                    gain: 7,
                    muted: true
                }; 2]
            );
            controller
                .set_realtek_capture_gain(&graph, input, 3, 9, false)
                .unwrap();
            assert!(controller.status(input).unwrap().running);
            assert!(controller.status(output).unwrap().running);
            controller.stop(input).unwrap();
            controller.stop(output).unwrap();
        }
        assert_eq!(model.borrow().amplifiers[&(3, false, 1, 0)], 0x93);
        assert_eq!(model.borrow().amplifiers[&(3, false, 1, 1)], 0x94);
        assert_eq!(model.borrow().amplifiers[&(3, false, 0, 0)], 9);
        assert_eq!(model.borrow().amplifiers[&(3, false, 0, 1)], 9);
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x5a));
        let mut bytes = [0u8; 64];
        controller.read_pcm(input, 0, &mut bytes).unwrap();
        assert!(bytes.iter().any(|byte| *byte != 0));
        controller.shutdown().unwrap();
        controller.reinitialize().unwrap();
        let fresh = controller.enumerate_codec(0).unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.set_realtek_capture_gain(&fresh, input, 3, 1, false),
            Err(Error::InvalidStream)
        );
        assert_eq!(access_counts(&model), before);
    }
}

#[test]
fn selected_mixer_input_isolated_and_mono_adc_has_one_amplifier_channel() {
    for mixer in [false, true] {
        let mut fixture = Fixture::new();
        let model = adc_model(0x10ec_0887);
        {
            let mut m = model.borrow_mut();
            *m.parameters.get_mut(&(3, 9)).unwrap() &= !1;
            if mixer {
                m.parameters.insert((3, 0x0e), 1);
                m.connection_words.insert((3, 0), 6);
                m.connection_words.insert((6, 0), 4 | (5 << 8));
            }
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_realtek_codec(&graph).unwrap();
        let stream = capture(&mut controller, &mut fixture, &graph, 1);
        let node = if mixer { 6 } else { 3 };
        let index = u8::from(mixer);
        let old = model.borrow().amplifiers.clone();
        controller
            .set_realtek_capture_gain(&graph, stream, node, 11, true)
            .unwrap();
        let observed = controller
            .realtek_capture_gain(&graph, stream, node)
            .unwrap();
        assert_eq!(observed.input_index, index);
        assert_eq!(observed.levels.len(), if mixer { 2 } else { 1 });
        for (key, value) in old {
            if key.0 != node || key.1 || key.2 != index || (!mixer && key.3 == 1) {
                assert_eq!(model.borrow().amplifiers[&key], value);
            }
        }
        assert_eq!(model.borrow().amplifiers[&(node, false, index, 0)], 0x8b);
        if mixer {
            assert_eq!(model.borrow().amplifiers[&(node, false, index, 1)], 0x8b);
        }
    }
}

#[test]
fn mono_mixer_with_one_stereo_source_has_two_input_amplifier_channels() {
    let mut fixture = Fixture::new();
    let model = adc_model(0x10ec_0887);
    {
        let mut m = model.borrow_mut();
        *m.parameters.get_mut(&(3, 9)).unwrap() &= !1;
        *m.parameters.get_mut(&(6, 9)).unwrap() &= !1;
        m.parameters.insert((3, 0x0e), 1);
        m.connection_words.insert((3, 0), 6);
        m.parameters.insert((6, 0x0e), 1);
        m.connection_words.insert((6, 0), 5);
    }
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_realtek_codec(&graph).unwrap();
    let stream = capture(&mut controller, &mut fixture, &graph, 1);
    controller
        .set_realtek_capture_gain(&graph, stream, 6, 4, false)
        .unwrap();
    assert_eq!(
        controller
            .realtek_capture_gain(&graph, stream, 6)
            .unwrap()
            .levels,
        [AmplifierLevel {
            gain: 4,
            muted: false
        }; 2]
    );
}

#[test]
fn terminal_capture_pin_gain_does_not_claim_its_output_selector() {
    let mut fixture = Fixture::new();
    let model = adc_model(0x10ec_0887);
    {
        let mut m = model.borrow_mut();
        *m.parameters.get_mut(&(5, 9)).unwrap() |= 1 << 8;
        m.parameters.insert((5, 0x0e), 2);
        m.connection_words.insert((5, 0), 2 | (3 << 8));
        m.route_controls.insert((5, 0xf01), 1);
    }
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_realtek_codec(&graph).unwrap();
    let stream = capture(&mut controller, &mut fixture, &graph, 2);
    controller
        .set_realtek_capture_gain(&graph, stream, 5, 8, false)
        .unwrap();
    let observed = controller.realtek_capture_gain(&graph, stream, 5).unwrap();
    assert_eq!(observed.input_index, 0);
    assert_eq!(
        observed.levels,
        [AmplifierLevel {
            gain: 8,
            muted: false
        }; 2]
    );
    assert_eq!(model.borrow().route_controls[&(5, 0xf01)], 1);
}

#[test]
fn gain_and_real_mute_capabilities_are_required_without_hidden_effects() {
    let mut fixture = Fixture::new();
    let model = adc_model(0x10ec_0887);
    {
        let mut m = model.borrow_mut();
        *m.parameters.get_mut(&(3, 9)).unwrap() |= 1 << 3;
        m.parameters.insert((3, 0x0d), 0x0000_0703);
    }
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_realtek_codec(&graph).unwrap();
    let stream = capture(&mut controller, &mut fixture, &graph, 2);
    let old = model.borrow().amplifiers.clone();
    assert_eq!(
        controller.set_realtek_capture_gain(&graph, stream, 3, 8, false),
        Err(Error::InvalidConfiguration)
    );
    assert_eq!(
        controller.set_realtek_capture_gain(&graph, stream, 3, 7, true),
        Err(Error::UnsupportedTopology)
    );
    assert_eq!(model.borrow().amplifiers, old);
    assert!(!controller.routing_failed);
    controller
        .set_realtek_capture_gain(&graph, stream, 3, 7, false)
        .unwrap();
    let observed = controller.realtek_capture_gain(&graph, stream, 3).unwrap();
    assert_eq!(observed.capabilities, 0x703);
    assert_eq!(
        observed.levels,
        [AmplifierLevel {
            gain: 7,
            muted: false
        }; 2]
    );
}

#[test]
fn wrong_stream_and_unreserved_nodes_refuse_before_live_codec_access() {
    let mut fixture = Fixture::new();
    let model = adc_model(0x10ec_0887);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_realtek_codec(&graph).unwrap();
    let stream = capture(&mut controller, &mut fixture, &graph, 2);
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
        .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
        .unwrap();
    let before = access_counts(&model);
    assert_eq!(
        controller.realtek_capture_gain(&graph, playback, 3),
        Err(Error::InvalidStream)
    );
    assert_eq!(
        controller.set_realtek_capture_gain(&graph, other, 3, 1, false),
        Err(Error::RouteInUse)
    );
    assert_eq!(
        controller.set_realtek_capture_gain(&graph, stream, 2, 1, false),
        Err(Error::RouteInUse)
    );
    assert_eq!(access_counts(&model), before);
}

#[test]
fn failed_channel_or_lost_selector_retains_dma_and_requires_real_reset() {
    for fault in 0..3 {
        let mut fixture = Fixture::new();
        let model = adc_model(0x10ec_0887);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_realtek_codec(&graph).unwrap();
        let stream = capture(&mut controller, &mut fixture, &graph, 2);
        controller.start(stream).unwrap();
        let before = model.borrow().amplifiers.clone();
        if fault == 2 {
            model.borrow_mut().route_controls.insert((3, 0xf01), 0);
        } else {
            model.borrow_mut().reject_amplifier_channel = Some((3, 1));
        }
        if fault == 1 {
            assert_eq!(
                controller.realtek_capture_gain(&graph, stream, 3),
                Err(Error::RouteRejected)
            );
        } else {
            assert_eq!(
                controller.set_realtek_capture_gain(&graph, stream, 3, 6, true),
                Err(Error::RouteRejected)
            );
        }
        if fault == 2 {
            assert_eq!(model.borrow().amplifiers, before);
        } else if fault == 0 {
            // Real writes happened, but one uncertain channel prevents
            // success and does not free or repurpose the active PCM DMA.
            assert_eq!(model.borrow().amplifiers[&(3, false, 0, 0)], 0x86);
            assert_eq!(model.borrow().amplifiers[&(3, false, 0, 1)], 0x86);
        }
        assert!(
            controller.streams[usize::from(stream.descriptor_index())]
                .as_ref()
                .unwrap()
                .running
        );
        assert_eq!(controller.routes.len(), 1);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(
            model.borrow().bytes[stream_base(stream.descriptor_index()) + SD_CTL] & SD_RUN,
            SD_RUN
        );
        controller.stop(stream).unwrap();
        model.borrow_mut().reject_amplifier_channel = None;
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty());
        assert!(controller.realtek_codecs.is_empty());
    }
}

#[test]
fn live_amp_capability_drift_cannot_authorize_a_set() {
    let mut fixture = Fixture::new();
    let model = adc_model(0x10ec_0887);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    controller.initialize_realtek_codec(&graph).unwrap();
    let stream = capture(&mut controller, &mut fixture, &graph, 2);
    let before = model.borrow().amplifiers.clone();
    model.borrow_mut().parameters.insert((1, 0x0d), 0x8000_7f7f);
    assert_eq!(
        controller.set_realtek_capture_gain(&graph, stream, 3, 50, false),
        Err(Error::InvalidCodecGraph)
    );
    assert_eq!(model.borrow().amplifiers, before);
    assert!(controller.routing_failed);
}

#[test]
#[ignore = "requires unchanged-source HDA capture gain oracle trace"]
fn realtek_capture_gain_matches_original_linux_path_and_amp_verbs() {
    extern crate std;
    use sha2::{Digest, Sha256};
    let trace = std::fs::read_to_string(
        std::env::var("STELA_HDA_CAPTURE_GAIN_ORACLE")
            .expect("set STELA_HDA_CAPTURE_GAIN_ORACLE to source trace.txt"),
    )
    .unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "9a49c02afe4dc61a11daacea065d8d67433807f1b8a4c7bd738daabf9106666b"
    );
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some("linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8")
    );
    let mut writes = Vec::new();
    let mut selected = [u32::MAX; 2];
    let mut source_selection = 0;
    let mut source_channels = 0;
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        let values: Vec<u32> = fields[1..].iter().map(|v| v.parse().unwrap()).collect();
        match fields[0] {
            "P" => {
                let [single, mixer, index, result, volume, mute] = values[..] else {
                    panic!("source path row")
                };
                assert_eq!(result, 0);
                assert_eq!(volume, mute);
                if single == 1 && index == 1 {
                    selected[mixer as usize] = (volume >> 19) & 15;
                }
                source_selection += 1;
            }
            "S" => {
                assert_eq!(values.len(), 5);
                source_channels += 1;
            }
            "W" => {
                let row: [u32; 5] = values.try_into().unwrap();
                writes.push(row);
            }
            other => panic!("source record {other}"),
        }
    }
    assert_eq!(
        (source_selection, source_channels, writes.len()),
        (64, 24, 4096)
    );
    assert_eq!(selected, [0, 1]);
    let mut native_operations = 0;
    for mixer in [false, true] {
        let mut fixture = Fixture::new();
        let model = adc_model(0x10ec_0887);
        if mixer {
            let mut m = model.borrow_mut();
            m.parameters.insert((3, 0x0e), 1);
            m.connection_words.insert((3, 0), 6);
            m.connection_words.insert((6, 0), 4 | (5 << 8));
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_realtek_codec(&graph).unwrap();
        let stream = capture(&mut controller, &mut fixture, &graph, 2);
        controller.start(stream).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 8);
        let node = if mixer { 6 } else { 3 };
        for &[index, value, write, left, right] in &writes {
            if index != selected[usize::from(mixer)] || value & 127 > 31 {
                continue;
            }
            let first = model.borrow().commands.len();
            controller
                .set_realtek_capture_gain(
                    &graph,
                    stream,
                    node,
                    (value & 127) as u8,
                    value & 128 != 0,
                )
                .unwrap();
            let observed = controller
                .realtek_capture_gain(&graph, stream, node)
                .unwrap();
            assert_eq!(u32::from(observed.input_index), index);
            assert_eq!(
                observed.levels,
                [AmplifierLevel {
                    gain: (value & 127) as u8,
                    muted: value & 128 != 0
                }; 2]
            );
            let commands: Vec<_> = model.borrow().commands[first..]
                .iter()
                .copied()
                .filter(|v| (v >> 20) & 127 == u32::from(node) && matches!((v >> 16) & 15, 3 | 11))
                .map(|v| v & 0xfffff)
                .collect();
            // Physical NID differs for ADC and mixer; every direction,
            // channel, verb, selected input and level bit must match.
            assert_eq!(
                commands,
                [write, left, right, left, right].map(|v| v & 0xfffff)
            );
            native_operations += 1;
        }
        assert!(controller.status(stream).unwrap().running);
        controller.stop(stream).unwrap();
        let mut bytes = [0u8; 64];
        controller.read_pcm(stream, 0, &mut bytes).unwrap();
        assert!(bytes.iter().any(|byte| *byte != 0));
        controller.shutdown().unwrap();
    }
    assert_eq!(native_operations, 128);
}
