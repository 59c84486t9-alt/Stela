// SPDX-License-Identifier: GPL-2.0-only
// Included in hda::tests: real CORB/RIRB, codec controls and cyclic PCM DMA.
mod unsolicited_models {
    extern crate std;
    use super::*;

    fn jack_model() -> Rc<RefCell<Model>> {
        let model = analog_model();
        {
            let mut m = model.borrow_mut();
            for node in [4, 5] {
                *m.parameters.get_mut(&(node, 9)).unwrap() |= 1 << 7;
                *m.parameters.get_mut(&(node, 0x0c)).unwrap() |= 1 << 2;
                m.pin_defaults
                    .insert(node, if node == 4 { 0x0221_4010 } else { 0x02a1_9011 });
            }
        }
        model
    }
    fn event(controller: &mut Controller<ModelRegisters, ModelClock>) -> UnsolicitedResponse {
        let Some(UnsolicitedEvent::Response(event)) = controller.next_unsolicited().unwrap() else {
            panic!("expected actual unsolicited response");
        };
        event
    }
    #[test]
    fn actual_jack_subscription_interleaves_rirb_events_and_live_pcm_without_fake_sense() {
        let mut fixture = Fixture::new();
        let model = jack_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let id = controller.enable_jack_notifications(&graph, 4).unwrap();
        assert_eq!(model.borrow().route_controls[&(4, 0xf08)], 0x81);
        assert_ne!(model.borrow().get(GCTL, 4) & GCTL_UNSOL, 0);
        assert_eq!(model.borrow().get(INTCTL, 4), 0); // explicit polling, no fabricated IRQ registration
        let stream = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        controller
            .configure_analog_route(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: Some(true),
                },
            )
            .unwrap();
        controller.write_pcm(stream, 0, &[0x35; 256]).unwrap();
        controller.start(stream).unwrap();
        model.borrow_mut().emit((1 << 26) | 1, RESPONSE_UNSOL);
        assert_eq!(
            controller.verb(Verb::short(0, 0, 0xf00, 0).unwrap()),
            Ok(graph.vendor_id)
        );
        let observed = event(&mut controller);
        assert_eq!(
            (
                observed.codec,
                observed.tag,
                observed.response,
                observed.extra,
                observed.subscription
            ),
            (0, 1, (1 << 26) | 1, RESPONSE_UNSOL, Some(id))
        );
        model.borrow_mut().pin_senses.insert(4, 0); // raw event says changed; actual current sense is absent
        assert!(!controller.poll_pin_sense(&graph, 4).unwrap().present);
        advance(&model, 6);
        assert!(controller.status(stream).unwrap().running);
        assert_eq!(controller.routes.len(), 1);
        controller.shutdown().unwrap();
        assert_eq!(model.borrow().route_controls[&(4, 0xf08)], 0);
        assert_eq!(model.borrow().get(GCTL, 4) & GCTL_UNSOL, 0);
        assert_eq!(model.borrow().get(CORBCTL, 1) & u32::from(COMMAND_RUN), 0);
    }

    #[test]
    fn actual_unsolicited_dma_wrap_and_bounded_loss_preserve_event_order() {
        let mut fixture = Fixture::new();
        let model = jack_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let id = controller.enable_jack_notifications(&graph, 4).unwrap();
        for value in 0..600 {
            let raw = (1 << 26) | value;
            model.borrow_mut().emit(raw, RESPONSE_UNSOL);
            assert_eq!(event(&mut controller).response, raw);
        }
        // Drain the real RIRB on every command while deliberately withholding
        // consumer delivery. This fills software storage without overrunning DMA.
        for value in 0..70 {
            model.borrow_mut().emit((1 << 26) | value, RESPONSE_UNSOL);
            controller
                .verb(Verb::short(0, 0, 0xf00, 0).unwrap())
                .unwrap();
        }
        for value in 0..10 {
            assert_eq!(event(&mut controller).response, (1 << 26) | value);
        }
        model.borrow_mut().emit((1 << 26) | 99, RESPONSE_UNSOL);
        controller
            .verb(Verb::short(0, 0, 0xf00, 0).unwrap())
            .unwrap();
        for value in 10..64 {
            assert_eq!(event(&mut controller).response, (1 << 26) | value);
        }
        assert_eq!(
            controller.next_unsolicited(),
            Ok(Some(UnsolicitedEvent::Overflow { at_least: 7 }))
        );
        assert_eq!(controller.next_unsolicited(), Ok(None));
        // Foreign and unregistered tags are retained as raw observations; they
        // never acquire an invented pin or codec authority.
        model.borrow_mut().emit((63 << 26) | 3, RESPONSE_UNSOL | 14);
        let foreign = event(&mut controller);
        assert_eq!(
            (foreign.codec, foreign.tag, foreign.subscription),
            (14, 63, None)
        );
        controller.disable_jack_notifications(id).unwrap();
    }

    #[test]
    fn jack_tags_are_never_reused_and_reset_stales_handles_before_mmio() {
        let mut fixture = Fixture::new();
        let model = jack_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let first = controller.enable_jack_notifications(&graph, 4).unwrap();
        controller.disable_jack_notifications(first).unwrap();
        controller.disable_jack_notifications(first).unwrap(); // exact acknowledged duplicate is inert
        let second = controller.enable_jack_notifications(&graph, 5).unwrap();
        assert_ne!(first, second);
        assert_eq!(model.borrow().route_controls[&(5, 0xf08)], 0x82);
        model.borrow_mut().emit(1 << 26, RESPONSE_UNSOL);
        assert_eq!(event(&mut controller).subscription, Some(first)); // historical source, no new pin
        controller.reinitialize().unwrap();
        let before = access_counts(&model);
        assert_eq!(
            controller.disable_jack_notifications(second),
            Err(Error::InvalidJackNotification)
        );
        assert_eq!(
            controller.enable_jack_notifications(&graph, 4),
            Err(Error::InvalidCodecGraph)
        );
        assert_eq!(access_counts(&model), before);
        assert_eq!(controller.next_unsolicited(), Ok(None));
        let graph = controller.enumerate_codec(0).unwrap();
        let fresh = controller.enable_jack_notifications(&graph, 4).unwrap();
        assert_ne!(fresh, first);
        assert_eq!(model.borrow().route_controls[&(4, 0xf08)], 0x81);
    }

    #[test]
    fn actual_widget_and_control_authority_refuse_forged_graph_and_owned_tags() {
        for rejection in 0..5 {
            let mut fixture = Fixture::new();
            let model = jack_model();
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let mut graph = controller.enumerate_codec(0).unwrap();
            {
                let mut m = model.borrow_mut();
                match rejection {
                    0 => *m.parameters.get_mut(&(4, 9)).unwrap() &= !(1 << 7),
                    1 => *m.parameters.get_mut(&(4, 0x0c)).unwrap() &= !(1 << 2),
                    2 => {
                        m.pin_defaults.insert(4, 0x0221_4110);
                    } // firmware no-presence override
                    3 => *m.parameters.get_mut(&(4, 9)).unwrap() |= 1 << 9,
                    _ => {
                        m.route_controls.insert((4, 0xf08), 0x9f);
                    } // preexisting enabled owner
                }
            }
            // Caller-supplied favorable capabilities are no write authority.
            graph.groups[0]
                .widgets
                .iter_mut()
                .find(|w| w.node == 4)
                .unwrap()
                .capabilities |= 1 << 7;
            assert!(controller.enable_jack_notifications(&graph, 4).is_err());
            assert_eq!(model.borrow().get(GCTL, 4) & GCTL_UNSOL, 0);
            assert!(
                model
                    .borrow()
                    .commands
                    .iter()
                    .all(|command| (command >> 8) & 0xfff != 0x708)
            );
        }
        let mut fixture = Fixture::new();
        let model = jack_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        for _ in 0..63 {
            let id = controller.enable_jack_notifications(&graph, 4).unwrap();
            controller.disable_jack_notifications(id).unwrap();
        }
        assert_eq!(
            controller.enable_jack_notifications(&graph, 4),
            Err(Error::JackNotificationTagsExhausted)
        );
        assert_eq!(model.borrow().get(GCTL, 4) & GCTL_UNSOL, 0);
    }

    #[test]
    fn uncertain_jack_enable_or_disable_retains_real_effects_until_full_reset() {
        for disable in [false, true] {
            let mut fixture = Fixture::new();
            let model = jack_model();
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let id = if disable {
                Some(controller.enable_jack_notifications(&graph, 4).unwrap())
            } else {
                None
            };
            {
                let mut m = model.borrow_mut();
                m.reject_route_control = Some(0xf08);
                m.reject_route_after_write = true;
                m.reject_route_write_threshold = if disable { 2 } else { 1 };
            }
            let result = if let Some(id) = id {
                controller.disable_jack_notifications(id)
            } else {
                controller.enable_jack_notifications(&graph, 4).map(|_| ())
            };
            assert_eq!(result, Err(Error::RouteRejected));
            assert_eq!(controller.next_unsolicited(), Err(Error::NeedsReset));
            assert_ne!(model.borrow().get(GCTL, 4) & GCTL_UNSOL, 0);
            assert_eq!(
                model.borrow().route_controls[&(4, 0xf08)],
                if disable { 0 } else { 0x81 }
            );
            model.borrow_mut().reject_route_control = None;
            controller.reinitialize().unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.enable_jack_notifications(&graph, 4).unwrap();
        }
    }

    #[test]
    fn a_corb_memory_fault_refuses_even_cached_notifications_and_requires_reset() {
        let mut fixture = Fixture::new();
        let model = jack_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.enable_jack_notifications(&graph, 4).unwrap();
        model.borrow_mut().emit(1 << 26, RESPONSE_UNSOL);
        controller
            .verb(Verb::short(0, 0, 0xf00, 0).unwrap())
            .unwrap();
        model.borrow_mut().set(CORBSTS, u32::from(CORB_MEMORY), 1);
        assert_eq!(controller.next_unsolicited(), Err(Error::CorbMemory));
        assert_eq!(controller.next_unsolicited(), Err(Error::NeedsReset));
        assert_eq!(model.borrow().get(CORBCTL, 1) & u32::from(COMMAND_RUN), 0);
        model.borrow_mut().set(CORBSTS, 0, 1);
        controller.reinitialize().unwrap();
        assert_eq!(controller.next_unsolicited(), Ok(None));
    }

    #[test]
    #[ignore = "requires unchanged-source HDA unsolicited oracle trace"]
    fn hda_unsolicited_matches_original_linux_admission_and_queue_dispatch() {
        use sha2::{Digest, Sha256};
        let path = std::env::var("STELA_HDA_UNSOLICITED_ORACLE")
            .expect("set STELA_HDA_UNSOLICITED_ORACLE to source trace.txt");
        let trace = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "5b6fe00368dabd063794c3c0a26b5b3803f3ad94e0b3d455f5ef8c562e4d566d"
        );
        let mut lines = trace.lines();
        assert_eq!(
            lines.next(),
            Some("linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8")
        );
        let mut fixture = Fixture::new();
        let model = jack_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller.enable_jack_notifications(&graph, 4).unwrap();
        let (mut admission, mut native_admission, mut queue, mut native_responses) = (0, 0, 0, 0);
        for line in lines {
            let fields: Vec<_> = line.split_whitespace().collect();
            let values: Vec<u32> = fields[1..]
                .iter()
                .map(|value| value.parse().unwrap())
                .collect();
            match fields[0] {
                "D" => {
                    let [no_jack, poll, present, unsol, disabled, accepted] = values[..] else {
                        panic!("original admission row")
                    };
                    if no_jack == 0 && poll == 0 {
                        // This API is the actual notification path. Linux OEM
                        // no-jack policy and polling fallback are separate inputs.
                        let mut case_fixture = Fixture::new();
                        let case_model = jack_model();
                        {
                            let mut m = case_model.borrow_mut();
                            let caps = m.parameters.get_mut(&(4, 9)).unwrap();
                            *caps = (*caps & !(1 << 7)) | (unsol << 7);
                            let caps = m.parameters.get_mut(&(4, 0x0c)).unwrap();
                            *caps = (*caps & !(1 << 2)) | (present << 2);
                            *m.pin_defaults.get_mut(&4).unwrap() |= disabled << 8;
                        }
                        let mut case = create(&case_model, &mut case_fixture, config()).unwrap();
                        let case_graph = case.enumerate_codec(0).unwrap();
                        assert_eq!(
                            case.enable_jack_notifications(&case_graph, 4).is_ok(),
                            accepted != 0
                        );
                        native_admission += 1;
                    }
                    admission += 1;
                }
                "Q" => {
                    let [response, extra, callbacks, last] = values[..] else {
                        panic!("original queue row")
                    };
                    if extra & RESPONSE_UNSOL != 0 {
                        model.borrow_mut().emit(response, extra);
                        let observed = event(&mut controller);
                        assert_eq!(
                            (
                                observed.response,
                                observed.extra,
                                observed.codec,
                                observed.tag
                            ),
                            (response, extra, (extra & 15) as u8, (response >> 26) as u8)
                        );
                        if callbacks != 0 {
                            assert_eq!(observed.response, last);
                        }
                        native_responses += 1;
                    } else {
                        assert_eq!(callbacks, 0);
                    }
                    queue += 1;
                }
                kind => panic!("unknown HDA source oracle record {kind}"),
            }
        }
        assert_eq!(
            (admission, native_admission, queue, native_responses),
            (32, 8, 600, 480)
        );
    }
}
