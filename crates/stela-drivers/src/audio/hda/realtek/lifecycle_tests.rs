// SPDX-License-Identifier: GPL-2.0-only
// Included inside hda::tests to exercise the real CORB/RIRB and DMA model.
// Authored source-only; execution is assigned centrally and remains UNRUN here.
mod realtek_owned_models {
    use super::*;

    const IDS: &[u32] = &[
        0x10ec_0272,
        0x10ec_0662,
        0x10ec_0663,
        0x10ec_0665,
        0x10ec_0667,
        0x10ec_0668,
        0x10ec_0670,
        0x10ec_0671,
        0x10ec_0867,
        0x10ec_0882,
        0x10ec_0883,
        0x10ec_0885,
        0x10ec_0887,
        0x10ec_0888,
        0x10ec_0889,
        0x10ec_0892,
        0x10ec_0897,
        0x10ec_0899,
        0x10ec_0900,
        0x10ec_0b00,
        0x10ec_1168,
        0x10ec_1220,
    ];
    fn family_model(id: u32) -> Rc<RefCell<Model>> {
        let model = realtek_desktop_model(id);
        let mut m = model.borrow_mut();
        m.parameters.insert(
            (0, 2),
            if id == 0x10ec_0662 {
                0x100300
            } else {
                0x100100
            },
        );
        m.coefficients.insert((0x20, 0), 0x30);
        m.coefficients.insert((0x20, 0x0d), 0x0011);
        drop(m);
        model
    }
    fn playback() -> PinOptions {
        PinOptions::Playback {
            headphone: false,
            eapd: Some(true),
        }
    }

    include!("capture_tests.rs");

    #[test]
    fn all_family_silicon_runs_real_duplex_dma_restarts_and_quiets() {
        for &id in IDS {
            let mut fixture = Fixture::new();
            let model = family_model(id);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_realtek_codec(&graph).unwrap();
            assert_eq!(report.common.codec_id, id);
            assert_eq!(report.coefficient_zero, 0x30);
            assert_eq!(report.oem, RealtekOem::Firmware);
            assert_eq!(report.pci_subsystem, None);
            assert_eq!(controller.realtek_codecs.len(), 1);
            let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
            let out = controller
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
                .configure_analog_route(&graph, &output, out, 0, playback())
                .unwrap();
            controller
                .configure_realtek_route(
                    &graph,
                    &input,
                    capture,
                    0,
                    PinOptions::Capture {
                        vref: Vref::EightyPercent,
                    },
                )
                .unwrap();
            controller.write_pcm(out, 0, &[0x5a; 256]).unwrap();
            for _ in 0..2 {
                controller.start(capture).unwrap();
                controller.start(out).unwrap();
                model.borrow_mut().dma_step_bytes = 128;
                advance(&model, 8);
                assert!(controller.status(out).unwrap().period_completed);
                controller
                    .set_realtek_output_gain(&graph, 2, 7, true)
                    .unwrap();
                assert_eq!(model.borrow().amplifiers[&(2, true, 0, 0)], 0x87);
                controller
                    .set_realtek_output_gain(&graph, 2, 9, false)
                    .unwrap();
                controller.stop(out).unwrap();
                controller.stop(capture).unwrap();
            }
            assert!(model.borrow().playback.iter().all(|value| *value == 0x5a));
            let mut captured = [0u8; 64];
            controller.read_pcm(capture, 0, &mut captured).unwrap();
            assert!(captured.iter().any(|value| *value != 0));
            controller.shutdown().unwrap();
            assert_eq!(model.borrow().route_controls[&(4, 0xf07)], 0);
            assert_eq!(model.borrow().route_controls[&(5, 0xf07)], 0);
            assert_eq!(controller.realtek_codecs.len(), 1);
            controller.reinitialize().unwrap();
            assert!(controller.realtek_codecs.is_empty());
            assert_eq!(
                controller.initialize_realtek_codec(&graph),
                Err(Error::InvalidCodecGraph)
            );
        }
    }

    #[test]
    fn source_masks_and_668_literal_restore_are_actual_observed_verbs() {
        for &id in IDS {
            let mut fixture = Fixture::new();
            let model = family_model(id);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_realtek_codec(&graph).unwrap();
            let m = model.borrow();
            match id {
                0x10ec_0662 | 0x10ec_0867 => {
                    assert_eq!(m.coefficients[&(0x20, 4)] & ((1 << 15) | (1 << 10)), 0)
                }
                0x10ec_0272 | 0x10ec_0663 | 0x10ec_0665 | 0x10ec_0670 | 0x10ec_0671 => {
                    assert_eq!(m.coefficients[&(0x20, 0x0d)], 0x4011)
                }
                0x10ec_0668 => {
                    assert_eq!(m.coefficients[&(0x20, 1)], 0xbebe);
                    assert_eq!(m.coefficients[&(0x20, 4)], 0x0180);
                    assert_eq!(m.coefficients[&(0x20, 7)], 0x0f80);
                    assert_eq!(m.coefficients[&(0x20, 0xc1)], 0x0fa6);
                    assert!(m.coefficient_events.iter().any(|&(node, index, value, _)| (
                        node, index, value
                    ) == (
                        0x20, 0xb6, 0xd697
                    )));
                }
                0x10ec_0882 | 0x10ec_0883 | 0x10ec_0885 => {
                    assert_eq!(m.coefficients[&(0x20, 7)] & 0x2030, 0x2030)
                }
                0x10ec_0888 | 0x10ec_0892 | 0x10ec_0897 => {
                    assert_eq!(m.coefficients[&(0x20, 7)] & (1 << 5), 0)
                }
                0x10ec_0899 | 0x10ec_0900 | 0x10ec_0b00 | 0x10ec_1168 | 0x10ec_1220 => {
                    assert_eq!(m.coefficients[&(0x20, 7)] & 2, 0)
                }
                _ => {}
            }
        }
    }

    fn default_amp_model(id: u32, zero: u16) -> Rc<RefCell<Model>> {
        let model = family_model(id);
        {
            let mut m = model.borrow_mut();
            // An actual source-listed EAPD endpoint, independent of the
            // ordinary PCM path at pin4. Start coefficient7 with bit controls
            // clear so every positive default-amplifier case performs a write.
            m.parameters.insert((0x14, 9), (4 << 20) | 1);
            m.parameters.insert((0x14, 0x0c), 0x10010);
            m.pin_defaults.insert(0x14, 0x01014010);
            m.coefficients.insert((0x20, 0), zero);
            m.coefficients.insert((0x20, 7), 0);
        }
        model
    }

    #[test]
    fn default_amp_follows_actual_eapd_write_and_ack_after_family_pll() {
        for (id, zero, default_amp) in [
            (0x10ec_0882, 0, true),
            (0x10ec_0883, 0, true),
            (0x10ec_0885, 0, true),
            (0x10ec_0888, 0, true),
            (0x10ec_0888, 0x10, true),
            (0x10ec_0888, 0x20, false),
            (0x10ec_0888, 0x30, false),
        ] {
            let mut fixture = Fixture::new();
            let model = default_amp_model(id, zero);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_realtek_codec(&graph).unwrap();
            assert_eq!(report.eapd_pins, [0x14]);
            let m = model.borrow();
            let eapd = Verb::short(0, 0x14, 0x70c, 2).unwrap().raw();
            let ack = Verb::short(0, 0x14, 0xf0c, 0).unwrap().raw();
            let amplifier = Verb::long(0, 0x20, 4, 0x2030).unwrap().raw();
            let enable = m
                .command_times
                .iter()
                .position(|(command, _)| *command == eapd)
                .unwrap();
            let observed = m
                .command_times
                .iter()
                .enumerate()
                .find(|(index, (command, _))| *index > enable && *command == ack)
                .map(|(index, _)| index)
                .unwrap();
            let amp = m
                .command_times
                .iter()
                .position(|(command, _)| *command == amplifier);
            if default_amp {
                let amp = amp.unwrap();
                assert!(enable < observed && observed < amp);
                assert!(m.command_times[observed].1 <= m.command_times[amp].1);
                assert_eq!(m.coefficients[&(0x20, 7)], 0x2030);
            } else {
                assert_eq!(amp, None);
                assert_eq!(m.coefficients[&(0x20, 7)], 0);
            }
            if matches!(id, 0x10ec_0883 | 0x10ec_0888) {
                // These original alc882_probe profiles clear PLL index0a bit10.
                let pll = Verb::long(0, 0x20, 4, 0xfbff).unwrap().raw();
                let pll_write = m
                    .command_times
                    .iter()
                    .position(|(command, _)| *command == pll)
                    .unwrap();
                assert!(pll_write < enable);
            }
        }
    }

    #[test]
    fn unacknowledged_eapd_blocks_default_amp_and_retains_codec_owner() {
        for (id, zero) in [
            (0x10ec_0882, 0),
            (0x10ec_0883, 0),
            (0x10ec_0885, 0),
            (0x10ec_0888, 0),
            (0x10ec_0888, 0x10),
        ] {
            for failed_verb in [0x70c, 0xf0c] {
                let mut fixture = Fixture::new();
                let model = default_amp_model(id, zero);
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                model.borrow_mut().drop_reply_command = Some(
                    Verb::short(
                        0,
                        0x14,
                        failed_verb,
                        if failed_verb == 0x70c { 2 } else { 0 },
                    )
                    .unwrap()
                    .raw(),
                );
                assert!(controller.initialize_realtek_codec(&graph).is_err());
                assert_eq!(controller.realtek_codecs.len(), 1);
                let amplifier = Verb::long(0, 0x20, 4, 0x2030).unwrap().raw();
                assert!(!model.borrow().commands.contains(&amplifier));
                assert_eq!(model.borrow().coefficients[&(0x20, 7)], 0);
                assert_eq!(
                    controller.initialize_realtek_codec(&graph),
                    Err(Error::NeedsReset)
                );
                model.borrow_mut().drop_reply_command = None;
                controller.reinitialize().unwrap();
                assert!(controller.realtek_codecs.is_empty());
            }
        }
    }

    #[test]
    fn mutated_graph_or_lost_codec_authority_never_authorizes_live_amp() {
        for fault in 0..7 {
            let mut fixture = Fixture::new();
            let model = family_model(0x10ec_0887);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let mut graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_realtek_codec(&graph).unwrap();
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
                .configure_realtek_route(&graph, &route, stream, 0, playback())
                .unwrap();
            match fault {
                0 => graph.groups[0].widgets[0].output_amplifier = Some(0x80007f00),
                1 => graph.groups[0].widgets[0].pcm.rates_and_bits = u32::MAX,
                2 => {
                    model.borrow_mut().coefficients.insert((0x20, 10), 0);
                }
                3 => {
                    model.borrow_mut().parameters.insert((0, 0), 0x10ec_0892);
                }
                4 => {
                    model.borrow_mut().pin_defaults.insert(4, 0xdeadbeef);
                }
                5 => {
                    model.borrow_mut().parameters.insert((1, 0x12), 0x80000101);
                }
                _ => {
                    model.borrow_mut().connection_words.insert((4, 0), 2);
                }
            }
            let writes = model.borrow().amplifiers.clone();
            assert!(
                controller
                    .set_realtek_output_gain(&graph, 2, 1, false)
                    .is_err()
            );
            assert_eq!(model.borrow().amplifiers, writes);
            assert_eq!(controller.realtek_codecs.len(), 1);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            controller.reinitialize().unwrap();
            assert!(controller.realtek_codecs.is_empty());
        }
    }

    #[test]
    fn failed_coefficient_programming_retains_address_until_acknowledged_reset() {
        for fault in 0..4 {
            let mut fixture = Fixture::new();
            let model = family_model(0x10ec_0892);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            match fault {
                0 => model.borrow_mut().coefficient_index_failed = true,
                1 => model.borrow_mut().reject_coefficient_write = true,
                2 => model.borrow_mut().coefficient_read_fault = Some(u32::MAX),
                _ => model.borrow_mut().power_stuck = true,
            }
            assert!(controller.initialize_realtek_codec(&graph).is_err());
            assert_eq!(controller.realtek_codecs.len(), 1);
            assert_eq!(
                controller.initialize_realtek_codec(&graph),
                Err(Error::NeedsReset)
            );
            model.borrow_mut().coefficient_index_failed = false;
            model.borrow_mut().reject_coefficient_write = false;
            model.borrow_mut().coefficient_read_fault = None;
            model.borrow_mut().power_stuck = false;
            controller.reinitialize().unwrap();
            assert!(controller.realtek_codecs.is_empty());
        }
    }
    struct OemRegisters {
        inner: ModelRegisters,
        subsystem: Rc<Cell<Option<u32>>>,
    }
    impl Registers for OemRegisters {
        fn region_bytes(&self) -> usize {
            self.inner.region_bytes()
        }
        fn codec_pci_subsystem(&mut self) -> Result<Option<u32>, Error> {
            Ok(self.subsystem.get())
        }
        fn read8(&mut self, o: usize) -> u8 {
            self.inner.read8(o)
        }
        fn read16(&mut self, o: usize) -> u16 {
            self.inner.read16(o)
        }
        fn read32(&mut self, o: usize) -> u32 {
            self.inner.read32(o)
        }
        fn write8(&mut self, o: usize, v: u8) {
            self.inner.write8(o, v)
        }
        fn write16(&mut self, o: usize, v: u16) {
            self.inner.write16(o, v)
        }
        fn write32(&mut self, o: usize, v: u32) {
            self.inner.write32(o, v)
        }
    }
    fn oem_model() -> Rc<RefCell<Model>> {
        let model = family_model(0x10ec_1220);
        {
            let mut m = model.borrow_mut();
            for pin in [0x14, 0x1b] {
                m.parameters.insert((pin, 9), (4 << 20) | 1 | 4 | (1 << 8));
                m.parameters.insert((pin, 0x0c), 0x10018);
                m.parameters.insert((pin, 0x0e), 1);
                m.connection_words.insert((pin, 0), 0x0c);
                m.pin_defaults.insert(pin, 0x01014010);
            }
            m.parameters.insert((0x0c, 9), (2 << 20) | 1 | (1 << 8));
            m.parameters.insert((0x0c, 0x0e), 1);
            m.connection_words.insert((0x0c, 0), 2);
        }
        model
    }
    #[test]
    fn original_pci_oem_fixups_have_real_coefficients_routes_and_board_retirement() {
        for subsystem in [0xa0cd1458, 0xa0ce1458, 0xa0d51458, 0x95011558, 0x12931462] {
            let mut fixture = Fixture::new();
            let model = oem_model();
            let pci = Rc::new(Cell::new(Some(subsystem)));
            let timer = model.borrow().clock.clone();
            // SAFETY: this model is the exclusive register/DMA owner.
            let mut controller = unsafe {
                Controller::new(
                    OemRegisters {
                        inner: ModelRegisters(model.clone()),
                        subsystem: pci.clone(),
                    },
                    timer,
                    &mut fixture.allocator,
                    config(),
                )
            }
            .unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let report = controller.initialize_realtek_oem_codec(&graph).unwrap();
            assert_eq!(report.pci_subsystem, Some(subsystem));
            assert_eq!(report.eapd_pins, [0x14]);
            if subsystem as u16 == 0x1458 {
                for (index, value) in [(7, 0x03c0), (0x1a, 0x01c1), (0x1b, 0x0202), (0x43, 0x3005)]
                {
                    assert_eq!(model.borrow().coefficients[&(0x20, index)], value);
                }
            } else {
                assert_eq!(model.borrow().coefficients[&(0x20, 7)] & 0x03c3, 0x03c3);
            }
            assert_eq!(model.borrow().route_controls[&(0x14, 0xf0c)], 2);
            let route = graph.analog_route(Direction::Playback, 0x14, 2).unwrap();
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
                .configure_realtek_route(&graph, &route, stream, 0, playback())
                .unwrap();
            assert_eq!(route.nodes(), &[0x14, 0x0c, 2]);
            // The donor's sole observed connection needs no selector write.
            // Read the actual peer through CORB/RIRB rather than assuming a
            // successful GET inserted an entry in its sparse write map.
            assert_eq!(
                controller
                    .verb(Verb::short(graph.address, 0x14, 0xf01, 0).unwrap())
                    .unwrap(),
                0
            );
            assert!(!model.borrow().command_times.iter().any(|(command, _)| {
                (command >> 20) & 127 == 0x14 && (command >> 8) & 0xfff == 0x701
            }));
            controller.shutdown().unwrap();
            assert_eq!(model.borrow().route_controls[&(0x14, 0xf0c)], 0);
            controller.reinitialize().unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            controller.initialize_realtek_oem_codec(&graph).unwrap();
            pci.set(Some(0xa0cc1458));
            assert!(controller.poll_realtek_pin_sense(&graph, 0x14).is_err());
            assert_eq!(controller.realtek_codecs.len(), 1);
            controller.reinitialize().unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            assert_eq!(
                controller.initialize_realtek_oem_codec(&graph),
                Err(Error::UnsupportedTopology)
            );
            assert!(controller.realtek_codecs.is_empty());
        }
    }
    #[test]
    fn absent_pci_authority_and_unobserved_oem_connection_refuse_before_coefficient_programming() {
        let mut fixture = Fixture::new();
        let model = oem_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        assert_eq!(
            controller.initialize_realtek_oem_codec(&graph),
            Err(Error::UnsupportedTopology)
        );
        assert_eq!(model.borrow().coefficient_writes, 0);
        let pci = Rc::new(Cell::new(Some(0xa0cd1458)));
        let timer = model.borrow().clock.clone();
        controller.shutdown().unwrap();
        // SAFETY: prior owner is stopped; the retained model has exclusive DMA.
        let mut controller = unsafe {
            Controller::new(
                OemRegisters {
                    inner: ModelRegisters(model.clone()),
                    subsystem: pci,
                },
                timer,
                &mut fixture.allocator,
                config(),
            )
        }
        .unwrap();
        model.borrow_mut().connection_words.insert((0x14, 0), 2);
        let graph = controller.enumerate_codec(0).unwrap();
        assert_eq!(
            controller.initialize_realtek_oem_codec(&graph),
            Err(Error::UnsupportedTopology)
        );
        assert_eq!(model.borrow().coefficient_writes, 0);
    }
    #[test]
    fn laptop_managed_startup_duplex_restart_and_exact_timed_shutup() {
        for (id, zero) in [
            (0x10ec_0269, 0),
            (0x10ec_0269, 0x18),
            (0x10ec_0269, 0x20),
            (0x10ec_0269, 0x30),
            (0x10ec_0255, 0),
            (0x10ec_0256, 0),
            (0x10ec_0257, 0),
            (0x10ec_0298, 0),
            (0x10ec_0285, 0),
            (0x10ec_0285, 0x10),
            (0x10ec_0295, 0),
        ] {
            let mut fixture = Fixture::new();
            let model = if matches!(id, 0x10ec_0285 | 0x10ec_0295) {
                let m = realtek_two_sense_model(id, true, true);
                m.borrow_mut().parameters.insert((0x16, 0x12), 0x80001f1f);
                m
            } else {
                realtek_headphone_model(id, true)
            };
            model.borrow_mut().coefficients.insert((0x20, 0), zero);
            if matches!(id, 0x10ec_0255..=0x10ec_0257) {
                // Force the real startup clear and preserve unrelated bits.
                // ALC257 later skips the shutdown set, as in alc256_shutup.
                model.borrow_mut().coefficients.insert((0x20, 0x46), 0xb5a5);
            }
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
            let out = controller
                .allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator,
                )
                .unwrap();
            let report = controller
                .configure_realtek_laptop_headphones(&graph, headphone_binding(&route, out), None)
                .unwrap();
            assert_eq!(report.common.codec_id, id);
            assert_eq!(report.coefficient_zero, zero);
            assert_eq!(report.family, RealtekFamily::Alc269);
            let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
            let capture = controller
                .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
                .unwrap();
            controller
                .configure_realtek_route(
                    &graph,
                    &input,
                    capture,
                    0,
                    PinOptions::Capture {
                        vref: Vref::EightyPercent,
                    },
                )
                .unwrap();
            for _ in 0..2 {
                controller.start(out).unwrap();
                controller.start(capture).unwrap();
                advance(&model, 4);
                controller.stop(capture).unwrap();
                controller.stop(out).unwrap();
            }
            let pull_writes_before_shutdown = model
                .borrow()
                .coefficient_events
                .iter()
                .filter(|(node, index, _, _)| *node == 0x20 && *index == 0x46)
                .count();
            if matches!(id, 0x10ec_0255..=0x10ec_0257) {
                assert_eq!(model.borrow().coefficients[&(0x20, 0x46)], 0x85a5);
                assert_eq!(pull_writes_before_shutdown, 1);
            }
            let shutdown_start = model.borrow().clock.now_us();
            controller.shutdown().unwrap();
            let elapsed = model.borrow().clock.now_us().wrapping_sub(shutdown_start);
            assert_eq!(model.borrow().route_controls[&(4, 0xf07)], 0);
            if id == 0x10ec_0269 && zero == 0x18 {
                assert!(elapsed >= 150000);
                assert_eq!(model.borrow().coefficients[&(0x20, 4)] & (1 << 11), 0);
            } else if id != 0x10ec_0269 {
                assert!(elapsed >= 152000);
            }
            // Source bus.shutdown preserves external mic configuration on
            // 256/257/285/295/298; ordinary255 and269 clear pin controls.
            assert_eq!(
                model.borrow().route_controls[&(5, 0xf07)],
                if matches!(id, 0x10ec_0255 | 0x10ec_0269) {
                    0
                } else {
                    0x24
                }
            );
            if matches!(id, 0x10ec_0255..=0x10ec_0257) {
                let retained = model.borrow();
                assert_eq!(
                    retained.coefficients[&(0x20, 0x46)],
                    if id == 0x10ec_0257 { 0x85a5 } else { 0xb5a5 }
                );
                let pull_writes_after_shutdown = retained
                    .coefficient_events
                    .iter()
                    .filter(|(node, index, _, _)| *node == 0x20 && *index == 0x46)
                    .count();
                assert_eq!(
                    pull_writes_after_shutdown - pull_writes_before_shutdown,
                    usize::from(id != 0x10ec_0257)
                );
            }
            controller.reinitialize().unwrap();
            assert!(controller.realtek_codecs.is_empty());
        }
    }
    #[test]
    fn laptop_lost_hidden_bank_and_failed_depop_shutdown_keep_owner() {
        for fault in 0..2 {
            let mut fixture = Fixture::new();
            let model = realtek_headphone_model(0x10ec_0256, true);
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
            controller
                .configure_realtek_laptop_headphones(
                    &graph,
                    headphone_binding(&route, stream),
                    None,
                )
                .unwrap();
            if fault == 0 {
                model.borrow_mut().coefficients.insert((0x57, 4), 0xffff);
                assert!(controller.poll_realtek_pin_sense(&graph, 4).is_err());
                assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            } else {
                model.borrow_mut().reject_amplifier_channel = Some((4, 1));
                assert_eq!(controller.shutdown(), Err(Error::RouteRejected));
                assert!(controller.stopped);
            }
            assert_eq!(controller.realtek_codecs.len(), 1);
            controller.reinitialize().unwrap();
            assert!(controller.realtek_codecs.is_empty());
        }
    }
}
