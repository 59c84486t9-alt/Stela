// SPDX-License-Identifier: GPL-2.0-only
//! commands behavior tests.
use super::*;

#[test]
fn actual_modern_pci_preparation_composes_reset_links_routes_and_finite_duplex_dma() {
    for device in [
        0xa170, 0x34c8, 0x3dc8, 0xa0c8, 0x43c8, 0x7ad0, 0x51c8, 0x51c9, 0x51cd, 0x51cc, 0x54c8,
        0x7e28,
    ] {
        let mut fixture = Fixture::new();
        let model = with_extended(analog_model());
        let gate = Rc::new(Cell::new(true));
        model.borrow_mut().reset_gate = Some(gate.clone());
        let (mut function, pci_timer, bar) = pci::tests::modern_pci_model_for(device);
        pci::tests::connect_reset_gate(&mut function, gate.clone());
        let registers = unsafe {
            pci::prepare_with_registers(
                &mut function,
                bar,
                &pci_timer,
                pci::Ownership::ExclusiveLegacy,
                ModelRegisters(model.clone()),
            )
        }
        .unwrap();
        let selected = registers.config();
        let timer = model.borrow().clock.clone();
        let mut controller =
            unsafe { Controller::new(registers, timer, &mut fixture.allocator, selected) }.unwrap();
        assert!(gate.get()); //The model asserts every CRST write occurs with gate clear.
        assert_eq!(controller.link_clock().unwrap().unwrap().mhz, 24);
        let graph = controller.enumerate_codec(0).unwrap();
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
        assert_eq!(playback.tag(), 1);
        assert_eq!(capture.tag(), 1);
        assert_ne!(playback, capture);
        let output = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
        controller
            .configure_analog_route(
                &graph,
                &output,
                playback,
                0,
                PinOptions::Playback {
                    headphone: false,
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
        controller.write_pcm(playback, 0, &[0x5a; 256]).unwrap();
        controller.fill_capture(capture, 0xa5).unwrap();
        controller.start(capture).unwrap();
        controller.start(playback).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 16);
        assert!(controller.status(playback).unwrap().period_completed);
        assert!(controller.status(capture).unwrap().period_completed);
        controller.stop(playback).unwrap();
        controller.stop(capture).unwrap();
        assert!(model.borrow().playback.len() >= 256);
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x5a));
        let mut captured = [0; 256];
        controller.read_pcm(capture, 0, &mut captured).unwrap();
        assert_eq!(captured, core::array::from_fn(|index| index as u8));
        model.borrow_mut().dma_step_bytes = 0;
        controller.reinitialize().unwrap();
        assert_eq!(model.borrow().link_initializations, 2);
        assert!(gate.get());
        let before = access_counts(&model);
        assert_eq!(controller.start(playback), Err(Error::InvalidStream));
        assert_eq!(
            controller.read_pcm(capture, 0, &mut captured),
            Err(Error::InvalidStream)
        );
        assert_eq!(access_counts(&model), before);
        controller.shutdown().unwrap();
    }
}

#[test]
fn command_rings_wrap_at_all_finite_sizes_with_delayed_hardware() {
    for size in [2, 16, 256] {
        let mut fixture = Fixture::new();
        let model = Model::new(size);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        assert_eq!(controller.codec_mask(), 1);
        for _ in 0..600 {
            assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
        }
        let m = model.borrow();
        assert_eq!(m.commands.len(), 600);
        assert_eq!(m.get(CORBWP, 2), 600 % u32::from(size));
        assert_eq!(m.get(RIRBWP, 2), 600 % u32::from(size));
        assert_eq!(m.get(INTCTL, 4), 0);
        assert_eq!(m.get(GCTL, 4) & GCTL_UNSOL, 0);
    }
}

#[test]
fn spurious_and_duplicate_replies_are_dropped_like_snd_hdac_bus_update_rirb() {
    let mut fixture = Fixture::new();
    let model = Model::new(16);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    model.borrow_mut().inject_unsolicited = true;
    assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
    // Nothing awaits this answer.
    model.borrow_mut().emit(0x9999, 0);
    model.borrow_mut().duplicate_reply = true;
    assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
    assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
    assert_eq!(model.borrow().commands.len(), 3);
}

#[test]
fn a_late_answer_completes_the_next_verb_and_a_stuck_rirb_reset_fails() {
    let mut fixture = Fixture::new();
    let model = Model::new(16);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    // While probing a timeout neither resets nor falls back; the late
    // answer counts toward the codec's next verb.
    model.borrow_mut().response_delay = 40;
    controller.probing = true;
    assert_eq!(controller.verb(verb()), Err(Error::Timeout(Phase::Verb)));
    controller.probing = false;
    model.borrow_mut().response_delay = 3;
    assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
    assert_eq!(controller.outstanding[0], 0);
    let model = Model::new(16);
    model.borrow_mut().rirb_reset_stuck = true;
    model.borrow_mut().set(RIRBWP, 8, 2);
    assert!(matches!(
        create(&model, &mut fixture, config()),
        Err(Error::Timeout(Phase::RirbReset))
    ));
}

#[test]
fn a_timed_out_verb_falls_back_to_single_commands_like_azx_rirb_get_response() {
    let mut fixture = Fixture::new();
    let model = Model::new(16);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    model.borrow_mut().response_delay = 80;
    assert_eq!(controller.verb(verb()), Err(Error::Timeout(Phase::Verb)));
    assert_eq!(model.borrow().get(CORBCTL, 1), 0);
    assert_eq!(model.borrow().get(RIRBCTL, 1), 0);
    // Later verbs use the immediate command interface.
    assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
    assert_eq!(model.borrow().commands.len(), 2);
    assert_eq!(model.borrow().get(IC, 4), verb().raw());
    model.borrow_mut().drop_reply = true;
    assert_eq!(controller.verb(verb()), Err(Error::Timeout(Phase::Verb)));
}

#[test]
fn a_bus_reset_restores_codec_writes_then_retries_like_snd_hda_bus_reset() {
    let mut fixture = Fixture::new();
    let model = Model::new(16);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    controller.allow_bus_reset = true;
    let write = Verb::short(0, 2, 0x701, 1).unwrap();
    assert!(controller.verb(write).is_ok());
    let resets = model.borrow().link_initializations;
    model.borrow_mut().drop_reply_until_resets = resets + 1;
    let count = model.borrow().commands.len();
    assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
    let m = model.borrow();
    assert_eq!(m.link_initializations, resets + 1);
    assert_eq!(
        m.commands[count..],
        [verb().raw(), write.raw(), verb().raw()]
    );
    assert!(!controller.single_command && !controller.response_reset);
}

#[test]
fn command_faults_and_invalid_pointers_are_explicit_and_poison() {
    for (offset, value, expected) in [
        (CORBSTS, 1, Error::CorbMemory),
        (CORBRP, 0xffff, Error::InvalidRingPointer),
    ] {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        model.borrow_mut().set(
            offset,
            value,
            if offset == CORBRP || offset == RIRBWP {
                2
            } else {
                1
            },
        );
        assert_eq!(controller.verb(verb()), Err(expected));
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
    }
}

#[test]
fn link_reset_and_command_quiesce_fail_bounded_before_dma_start() {
    for (enter, expected) in [(true, Phase::LinkResetEnter), (false, Phase::LinkResetExit)] {
        let mut fixture = Fixture::new();
        let model = Model::new(16);
        model.borrow_mut().reset_enter_stuck = enter;
        model.borrow_mut().reset_exit_stuck = !enter;
        assert!(
            matches!(create(&model, &mut fixture, config()), Err(Error::Timeout(phase)) if phase == expected)
        );
        assert_eq!(model.borrow().address(CORBLBASE, CORBUBASE), 0);
        assert!(model.borrow().clock.now_us() < 2000);
    }
    let mut fixture = Fixture::new();
    let model = Model::new(16);
    {
        let mut m = model.borrow_mut();
        m.command_stop_stuck = true;
        m.set(CORBCTL, u32::from(COMMAND_RUN), 1);
    }
    assert!(matches!(
        create(&model, &mut fixture, config()),
        Err(Error::Timeout(Phase::CommandStop))
    ));
    assert_eq!(model.borrow().address(CORBLBASE, CORBUBASE), 0);
}

#[test]
fn corb_reset_quirk_is_explicit_and_no_timeout_fallback_guesses_it() {
    let mut fixture = Fixture::new();
    let model = Model::new(16);
    model.borrow_mut().self_clear = true;
    assert!(matches!(
        create(&model, &mut fixture, config()),
        Err(Error::Timeout(Phase::CorbResetEnter))
    ));
    let model = Model::new(16);
    model.borrow_mut().self_clear = true;
    let controller = create(
        &model,
        &mut fixture,
        Config {
            corb_reset: CorbReset::SelfClearing,
            ..config()
        },
    )
    .unwrap();
    assert_eq!(controller.codec_mask(), 1);
}
