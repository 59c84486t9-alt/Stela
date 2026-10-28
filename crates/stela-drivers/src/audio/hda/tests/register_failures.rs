// SPDX-License-Identifier: GPL-2.0-only
//! register failures behavior tests.
use super::*;

#[test]
fn rirb_ack_releases_backpressure() {
    for enable_status in [true, false] {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        model.borrow_mut().response_backpressure = true;
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        assert_eq!(model.borrow().get(INTCTL, 4), 0);
        assert_eq!(model.borrow().bytes[RIRBCTL], RIRB_RUN_STATUS);
        if !enable_status {
            model.borrow_mut().bytes[RIRBCTL] = COMMAND_RUN;
        }
        assert_eq!(controller.verb(verb()).unwrap(), 0x1234_abcd);
        let result = controller.verb(verb());
        if enable_status {
            assert_eq!(result, Ok(0x1234_abcd));
            assert_eq!(controller.verb(verb()), Ok(0x1234_abcd));
            assert_eq!(model.borrow().response_count, 0);
            assert_eq!(model.borrow().commands.len(), 3);
        } else {
            assert_eq!(result, Err(Error::Timeout(Phase::Verb)));
            assert_eq!(model.borrow().commands.len(), 1);
        }
    }
}

#[test]
fn final_control_read_failure_attempts_cleanup() {
    for offset in [CORBCTL, RIRBCTL] {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        model.borrow_mut().command_start_read_failure = Some(offset);
        assert!(matches!(
            create(&model, &mut fixture, config()),
            Err(Error::Timeout(Phase::CommandStart))
        ));
        let m = model.borrow();
        assert!(m.command_started_once);
        assert_eq!(m.bytes[VMAJ], 1);
        assert!(m.commands.is_empty());
        assert_eq!(m.get(CORBWP, 2), 0);
        let enabled = m
            .writes
            .iter()
            .rposition(|(off, value, bytes)| {
                *off == CORBCTL && *value == u32::from(COMMAND_RUN) && *bytes == 1
            })
            .unwrap();
        let cleanup = &m.writes[enabled + 1..];
        assert!(
            cleanup
                .iter()
                .any(|(off, value, bytes)| *off == CORBCTL && *value == 0 && *bytes == 1)
        );
        assert!(
            cleanup
                .iter()
                .any(|(off, value, bytes)| *off == RIRBCTL && *value == 0 && *bytes == 1)
        );
    }
}

#[test]
fn failed_reads_do_not_acknowledge_controls() {
    for case in 0..5 {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        let expected = {
            let mut m = model.borrow_mut();
            match case {
                0 => {
                    m.control_read_failure = Some((GCTL, 4));
                    m.control_failure_active = true;
                    Error::RegisterUnavailable { offset: GCTL }
                }
                1 => {
                    m.control_read_failure = Some((GCTL, 4));
                    m.control_failure_after_write = Some((GCTL, GCTL_RESET, 4));
                    Error::Timeout(Phase::LinkResetExit)
                }
                2 => {
                    m.control_read_failure = Some((CORBRP, 2));
                    m.control_failure_after_write = Some((CORBRP, u32::from(POINTER_RESET), 2));
                    Error::Timeout(Phase::CorbResetEnter)
                }
                3 => {
                    m.control_read_failure = Some((STATESTS, 2));
                    m.control_failure_after_write = Some((GCTL, GCTL_RESET, 4));
                    Error::RegisterUnavailable { offset: STATESTS }
                }
                _ => {
                    m.control_read_failure = Some((CORBSIZE, 1));
                    m.control_failure_active = true;
                    Error::UnsupportedRingSize
                }
            }
        };
        assert!(matches!(create(&model,&mut fixture,config()),Err(error) if error==expected));
        assert!(model.borrow().commands.is_empty());
        if case == 0 {
            assert!(
                !model
                    .borrow()
                    .writes
                    .iter()
                    .any(|(offset, _, _)| *offset == GCTL)
            );
        }
    }
}

#[test]
fn failed_stream_reads_retain_buffer_ownership() {
    for case in 0..4 {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let base = stream_base(controller.capabilities.input_streams);
        if case == 0 {
            {
                let mut m = model.borrow_mut();
                m.control_read_failure = Some((base + SD_CTL, 1));
                m.control_failure_after_write = Some((base + SD_CTL, u32::from(SD_RESET), 1));
            }
            assert_eq!(
                controller.allocate_stream(
                    Direction::Playback,
                    stereo(),
                    128,
                    2,
                    &mut fixture.allocator
                ),
                Err(Error::Timeout(Phase::StreamResetEnter))
            );
            continue;
        }
        let id = controller
            .allocate_stream(
                Direction::Playback,
                stereo(),
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        if case == 1 {
            {
                let mut m = model.borrow_mut();
                m.control_read_failure = Some((base + SD_CTL, 1));
                m.control_failure_after_write = Some((base + SD_CTL, u32::from(SD_RUN), 1));
            }
            assert_eq!(
                controller.start(id),
                Err(Error::Timeout(Phase::StreamStart))
            );
        } else {
            controller.start(id).unwrap();
            let before = model.borrow().writes.len();
            {
                let mut m = model.borrow_mut();
                m.control_read_failure = Some((base + SD_CTL, 1));
                if case == 2 {
                    m.control_failure_active = true;
                } else {
                    m.control_failure_after_write = Some((base + SD_CTL, 0, 1));
                }
            }
            assert_eq!(
                controller.stop(id),
                Err(if case == 2 {
                    Error::RegisterUnavailable {
                        offset: base + SD_CTL,
                    }
                } else {
                    Error::Timeout(Phase::StreamStop)
                })
            );
            if case == 2 {
                assert_eq!(model.borrow().writes.len(), before);
            }
        }
        assert_eq!(controller.write_pcm(id, 0, &[1]), Err(Error::NeedsReset));
    }
}

#[test]
fn converter_ff_value_and_failed_response() {
    for failed_read in [false, true] {
        let mut fixture = Fixture::new();
        let model = graph_model();
        model.borrow_mut().set(GCAP, (15 << 12) | 1, 2);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let mut graph = controller.enumerate_codec(0).unwrap();
        graph.groups[0]
            .widgets
            .iter_mut()
            .find(|widget| widget.node == 2)
            .unwrap()
            .capabilities &= !1;
        let small = PcmFormat {
            rate: 8_000,
            bits: 8,
            channels: 1,
        };
        for _ in 0..14 {
            controller
                .allocate_stream(Direction::Playback, small, 128, 2, &mut fixture.allocator)
                .unwrap();
        }
        let id = controller
            .allocate_stream(
                Direction::Playback,
                PcmFormat {
                    channels: 16,
                    ..stereo()
                },
                128,
                2,
                &mut fixture.allocator,
            )
            .unwrap();
        assert_eq!(id.tag(), 15);
        model.borrow_mut().binding_read_failure = failed_read;
        let result = controller.bind_converter(&graph, 2, id, 15);
        assert_eq!(
            result,
            if failed_read {
                Err(Error::ConverterRejected)
            } else {
                Ok(())
            }
        );
        assert_eq!(model.borrow().bindings[&2], 0xff);
    }
}

#[test]
fn dma_address_ceiling_extents() {
    for bits in [32, 40, 48] {
        let limit = 1u64 << bits;
        assert_eq!(check_dma_range(limit - 4096, 4096, 4096, bits), Ok(()));
        assert_eq!(
            check_dma_range(limit - 4096, 4097, 4096, bits),
            Err(Error::DmaAddress)
        );
        assert_eq!(
            check_dma_range(limit, 4096, 4096, bits),
            Err(Error::DmaAddress)
        );
        assert_eq!(check_dma_range(limit - 4096, 4096, 4096, 64), Ok(()));
    }
    assert_eq!(check_dma_range(0, 4096, 4096, 64), Err(Error::DmaAddress));
    assert_eq!(
        check_dma_range(4097, 4096, 4096, 64),
        Err(Error::DmaAddress)
    );
    assert_eq!(
        check_dma_range(u64::MAX - 4095, 4096, 4096, 64),
        Err(Error::DmaAddress)
    );
}

#[test]
fn dma_ceiling_precedes_ring_programming() {
    for bits in [0, 31, 65, u8::MAX] {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        assert!(matches!(
            create(
                &model,
                &mut fixture,
                Config {
                    dma_address_bits: bits,
                    ..config()
                }
            ),
            Err(Error::InvalidConfiguration)
        ));
        assert!(model.borrow().writes.is_empty());
    }
    let mut fixture = Fixture::new();
    let model = Model::new(256);
    let mut controller = create(
        &model,
        &mut fixture,
        Config {
            dma_address_bits: 48,
            ..config()
        },
    )
    .unwrap();
    assert_eq!(controller.capabilities().dma_address_bits, 48);
    controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    controller.shutdown().unwrap();
    // A valid allocator's CPU address can exceed a controller's identity
    // width even when GCAP advertises 64-bit addressing. Never start DMA.
    let next = fixture.allocator.allocate(128, 128).unwrap();
    if next.physical() >= 1u64 << 40 {
        let mut fixture = Fixture::new();
        let model = Model::new(256);
        assert!(matches!(
            create(
                &model,
                &mut fixture,
                Config {
                    dma_address_bits: 40,
                    ..config()
                }
            ),
            Err(Error::DmaAddress)
        ));
        assert!(model.borrow().writes.is_empty());
    }
}
