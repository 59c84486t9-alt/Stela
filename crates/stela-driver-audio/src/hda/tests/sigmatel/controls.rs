// SPDX-License-Identifier: GPL-2.0-only
//! Sigmatel codec control tests.
use super::*;
// Exercises SigmaTel controls through the shared command-ring/DMA model.
mod idt95 {
    use super::*;

    fn device() -> Rc<RefCell<Model>> {
        let model = idt83_device(0x111d_7695);
        let mut m = model.borrow_mut();
        // Only the four source 92HD95 ports are physical analog pins.
        m.parameters.insert((1, 4), (2 << 16) | 12);
        for node in 0x0e..=0x10 {
            m.parameters.remove(&(node, 9));
        }
        drop(m);
        model
    }

    #[test]
    fn idt95_port_map_and_duplex() {
        let mut fixture = Fixture::new();
        let model = device();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let report = controller.initialize_sigmatel_codec(&graph).unwrap();
        assert_eq!(report.profile, SigmatelProfile::Idt92hd95);
        assert!(report.idt83.is_none() && report.idt73.is_none());
        let power = report.idt95.unwrap();
        assert_eq!(power.power_map, 8);
        assert_eq!(
            power.ports.iter().map(|port| port.node).collect::<Vec<_>>(),
            vec![0x0a, 0x0b, 0x0c, 0x0d]
        );
        assert_eq!(model.borrow().idt83_amplifier_mode, None);
        assert_eq!(
            report.gpio,
            SigmatelGpio {
                mask: 0x5a,
                direction: 0x3c,
                data: 0xa5
            }
        );
        assert!(model.borrow().sense_triggers.is_empty());
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
        let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
        let input = graph.analog_route(Direction::Capture, 0x0b, 3).unwrap();
        controller
            .configure_sigmatel_route(&graph, &output, out, 0, idt83_playback())
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
        controller.write_pcm(out, 0, &[0x95; 256]).unwrap();
        controller.start(out).unwrap();
        controller.start(mic).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 8);
        assert!(controller.status(out).unwrap().period_completed);
        assert!(controller.status(mic).unwrap().period_completed);
        model.borrow_mut().pin_senses.insert(0x0a, 0);
        assert!(
            !controller
                .poll_sigmatel_pin_sense(&graph, 0x0a)
                .unwrap()
                .present
        );
        assert_eq!(model.borrow().idt83_power_map, 9);
        controller.stop(out).unwrap();
        let before = access_counts(&model);
        assert_eq!(controller.start(out), Err(Error::UnsupportedTopology));
        assert_eq!(access_counts(&model), before);
        model.borrow_mut().pin_senses.insert(0x0a, 0x8000_0042);
        assert_eq!(
            controller
                .refresh_idt95_power_map(&graph)
                .unwrap()
                .power_map,
            8
        );
        controller.start(out).unwrap();
        controller.stop(mic).unwrap();
        let mut samples = [0; 256];
        controller.read_pcm(mic, 0, &mut samples).unwrap();
        assert_eq!(samples, core::array::from_fn(|index| index as u8));
        controller.shutdown().unwrap();
        assert!(model.borrow().playback.len() >= 256);
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x95));
    }

    #[test]
    fn idt95_invalid_port_state_quarantines_routes() {
        for defaults in [false, true] {
            let mut fixture = Fixture::new();
            let model = device();
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_sigmatel_codec(&graph).unwrap();
            if defaults {
                model.borrow_mut().pin_defaults.insert(0x0c, 0x4000_0030);
            } else {
                model.borrow_mut().idt83_power_map ^= 1;
            }
            assert!(controller.refresh_idt95_power_map(&graph).is_err());
            assert!(controller.routing_failed && controller.sigmatel_codecs[0].authority_lost());
            assert!(controller.shutdown().is_err());
            controller.reinitialize().unwrap();
            assert!(controller.sigmatel_codecs.is_empty());
        }
        let mut fixture = Fixture::new();
        let model = device();
        model.borrow_mut().parameters.insert((0, 0), 0x111d_7696);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.initialize_sigmatel_codec(&graph),
            Err(Error::UnsupportedTopology)
        );
        assert_eq!(access_counts(&model), before);
    }
    // Canonical dispatch and failed reset
    // must keep the same IDT port/PCM permission, not just a vendor handle.
    #[test]
    fn idt95_failed_reset_keeps_port() {
        let mut fixture = Fixture::new();
        let model = device();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.initialize_sigmatel_codec(&graph).unwrap();
        let output = graph.analog_route(Direction::Playback, 0x0a, 2).unwrap();
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
            .configure_analog_route(&graph, &output, out, 0, idt83_playback())
            .unwrap();
        controller.start(out).unwrap();
        controller.stop(out).unwrap();
        model.borrow_mut().pin_senses.insert(0x0a, 0);
        assert!(!controller.poll_pin_sense(&graph, 0x0a).unwrap().present);
        assert_eq!(model.borrow().idt83_power_map, 9);
        let before = access_counts(&model);
        assert_eq!(controller.start(out), Err(Error::UnsupportedTopology));
        assert_eq!(access_counts(&model), before);
        let pcm = controller.stream(out).unwrap().buffer.physical();
        model.borrow_mut().reset_enter_stuck = true;
        assert!(controller.reinitialize().is_err());
        assert_eq!(controller.sigmatel_codecs.len(), 1);
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
        model.borrow_mut().reset_enter_stuck = false;
        controller.reinitialize().unwrap();
        assert!(controller.sigmatel_codecs.is_empty() && controller.routes.is_empty());
        assert!(controller.converter_bindings.is_empty());
        assert_eq!(
            controller.poll_pin_sense(&graph, 0x0a),
            Err(Error::InvalidCodecGraph)
        );
    }
}

mod stac9872 {
    use super::*;

    fn device(id: u32) -> Rc<RefCell<Model>> {
        let model = analog_model();
        let mut m = model.borrow_mut();
        m.parameters.insert((0, 0), id);
        m.parameters.insert((1, 4), (2 << 16) | 20);
        m.parameters.insert((1, 0x11), 8);
        for node in 8..=0x15 {
            m.parameters.insert((node, 9), 0xf << 20);
        }
        for node in [0x0a, 0x0d, 0x14] {
            m.parameters.insert((node, 9), (4 << 20) | 1);
            m.parameters.insert((node, 0x0c), 0x20 | 0x3700);
            m.pin_defaults.insert(node, 0x03a1_0020);
        }
        m.parameters
            .insert((0x15, 9), (3 << 20) | 1 | (1 << 2) | (1 << 3) | (1 << 8));
        m.parameters.insert((0x15, 0x12), 0x8000_1f1f);
        m.parameters.insert((0x15, 0x0e), 4);
        m.connection_words
            .insert((0x15, 0), 0x0a | (0x0d << 8) | (0x14 << 16) | (2 << 24));
        m.parameters.insert((3, 0x0e), 1);
        m.connection_words.insert((3, 0), 0x15);
        drop(m);
        model
    }

    #[test]
    fn stac9872_exact_ids_source_selector_amp_and_real_native_duplex() {
        for id in [0x8384_7661, 0x8384_7662, 0x8384_7664] {
            let mut fixture = Fixture::new();
            let model = device(id);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_sigmatel_codec(&graph).unwrap();
            assert_eq!(report.profile, SigmatelProfile::Stac9872);
            assert_eq!(report.selector_node, Some(0x15));
            assert_eq!(report.master_amplifier, Some((0x15, 0)));
            assert_eq!(model.borrow().route_controls[&(0x15, 0xf01)], 1);
            for channel in 0..2 {
                assert_eq!(model.borrow().amplifiers[&(0x15, true, 0, channel)], 0);
            }
            assert!(report.idt83.is_none() && report.idt73.is_none() && report.idt95.is_none());
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
            let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 0x0d, 3).unwrap();
            controller
                .configure_sigmatel_route(
                    &graph,
                    &output,
                    out,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None,
                    },
                )
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
            controller.write_pcm(out, 0, &[0x72; 256]).unwrap();
            controller.fill_capture(mic, 0xa5).unwrap();
            controller.start(out).unwrap();
            controller.start(mic).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 8);
            assert!(controller.status(out).unwrap().period_completed);
            assert!(controller.status(mic).unwrap().period_completed);
            controller.stop(mic).unwrap();
            let mut samples = [0xa5; 256];
            controller.read_pcm(mic, 0, &mut samples).unwrap();
            assert_eq!(samples, core::array::from_fn(|index| index as u8));
            controller.shutdown().unwrap();
            assert!(model.borrow().playback.len() >= 256);
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x72));
        }
    }

    #[test]
    fn stac9872_amp_failure_keeps_owner() {
        for live_loss in [false, true] {
            let mut fixture = Fixture::new();
            let model = device(0x8384_7662);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            if live_loss {
                controller.initialize_sigmatel_codec(&graph).unwrap();
                model
                    .borrow_mut()
                    .parameters
                    .insert((0x15, 0x12), 0x8000_1e1e);
                assert!(controller.poll_sigmatel_pin_sense(&graph, 0x0d).is_err());
                assert!(controller.sigmatel_codecs[0].authority_lost());
            } else {
                model.borrow_mut().reject_amplifier_channel = Some((0x15, 1));
                assert!(controller.initialize_sigmatel_codec(&graph).is_err());
            }
            assert!(controller.routing_failed);
            assert_eq!(controller.sigmatel_codecs.len(), 1);
            model.borrow_mut().reject_amplifier_channel = None;
            controller.reinitialize().unwrap();
            assert!(controller.sigmatel_codecs.is_empty());
        }
    }
}
