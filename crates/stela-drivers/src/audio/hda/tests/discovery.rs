// SPDX-License-Identifier: GPL-2.0-only
//! discovery behavior tests.
use super::*;

#[test]
fn invalid_budget_precedes_register_access() {
    for (attempts, delay_us) in [(0, 1), (61, 1), (1, 0), (1, 1_000_001)] {
        let mut fixture = Fixture::new();
        let model = graph_model();
        assert!(matches!(
            create(
                &model,
                &mut fixture,
                Config {
                    probe_policy: ProbePolicy::Retry { attempts, delay_us },
                    ..config()
                }
            ),
            Err(Error::InvalidConfiguration)
        ));
        assert_eq!(access_counts(&model), (0, 0, 0));
    }
    let mut fixture = Fixture::new();
    let model = graph_model();
    let mut controller = create(&model, &mut fixture, retry_config(2)).unwrap();
    // Manual enumeration does not bypass an identity-required discovery gate.
    controller.enumerate_codec(0).unwrap();
    let before = access_counts(&model);
    let remaining = fixture.allocator.remaining();
    assert_eq!(
        controller.allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator
        ),
        Err(Error::NeedsDiscovery)
    );
    assert_eq!(access_counts(&model), before);
    assert_eq!(fixture.allocator.remaining(), remaining);
    let result = controller.discover_codecs().unwrap();
    assert_eq!(result.attempts, 1);
    assert_eq!(result.codecs.len(), 1);
    assert!(result.failures.is_empty());
    controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let before = access_counts(&model);
    let failure = controller.discover_codecs().unwrap_err();
    assert_eq!(failure.attempts, 0);
    assert_eq!(failure.error, Error::StreamsAllocated);
    assert_eq!(access_counts(&model), before);
    controller.reinitialize().unwrap();
    assert_eq!(
        controller.allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator
        ),
        Err(Error::NeedsDiscovery)
    );
}

#[test]
fn retry_retains_codec_failures() {
    for ready_after in [2, 4] {
        let mut fixture = Fixture::new();
        let model = graph_model();
        model.borrow_mut().codec_ready_after_resets = ready_after;
        let mut controller = create(&model, &mut fixture, retry_config(3)).unwrap();
        let start = model.borrow().clock.now_us();
        let result = controller.discover_codecs();
        let failures = if ready_after == 2 {
            let result = result.unwrap();
            assert_eq!(result.attempts, 2);
            assert_eq!(result.codecs.len(), 1);
            assert_eq!(result.codecs[0].token, controller.token);
            assert_eq!(controller.token.generation, 2);
            result.failures
        } else {
            let failure = result.unwrap_err();
            assert_eq!(failure.attempts, 3);
            assert_eq!(failure.error, Error::InvalidCodecGraph);
            assert_eq!(controller.token.generation, 3);
            failure.failures
        };
        assert!(model.borrow().clock.now_us() - start >= 80);
        assert_eq!(failures.len(), if ready_after == 2 { 1 } else { 3 });
        for (index, failure) in failures.iter().enumerate() {
            assert_eq!(
                *failure,
                CodecFailure {
                    attempt: index as u8 + 1,
                    address: 0,
                    error: Error::InvalidCodecGraph
                }
            );
        }
    }
    let mut fixture = Fixture::new();
    let model = graph_model();
    model.borrow_mut().advertised_codecs = 0;
    let mut controller = create(&model, &mut fixture, retry_config(2)).unwrap();
    let failure = controller.discover_codecs().unwrap_err();
    assert_eq!(failure.attempts, 2);
    assert_eq!(failure.error, Error::CodecAbsent);
    assert!(failure.failures.is_empty());
    assert!(model.borrow().commands.is_empty());
}

#[test]
fn partial_failures_reset_poison() {
    let mut fixture = Fixture::new();
    let model = graph_model();
    model.borrow_mut().advertised_codecs = 3;
    model
        .borrow_mut()
        .codec_vendor_overrides
        .insert(1, u32::MAX);
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let result = controller.discover_codecs().unwrap();
    assert_eq!(result.codecs.len(), 1);
    assert_eq!(result.codecs[0].address, 0);
    assert_eq!(
        result.failures,
        [CodecFailure {
            attempt: 1,
            address: 1,
            error: Error::InvalidCodecGraph
        }]
    );

    let model = graph_model();
    model.borrow_mut().advertised_codecs = 3;
    model.borrow_mut().drop_reply_until_resets = 2;
    let mut controller = create(&model, &mut fixture, retry_config(2)).unwrap();
    // azx_probe_codecs disables the silent slot and resets the chip.
    let result = controller.discover_codecs().unwrap();
    assert_eq!(result.attempts, 1);
    assert_eq!(result.codecs.len(), 1);
    assert_eq!(result.codecs[0].address, 1);
    assert_eq!(
        result.failures,
        [CodecFailure {
            attempt: 1,
            address: 0,
            error: Error::Timeout(Phase::Verb)
        }]
    );
    assert_eq!(model.borrow().commands[0] >> 28, 0);
    assert_eq!(model.borrow().commands[1] >> 28, 1);
    assert_eq!(model.borrow().link_initializations, 2);
    assert_eq!(controller.codec_mask(), 2);
    assert!(!controller.command_poisoned);
}

#[test]
fn retry_quiescence_failure_is_final() {
    let mut fixture = Fixture::new();
    let model = graph_model();
    model.borrow_mut().codec_ready_after_resets = 2;
    let mut controller = create(&model, &mut fixture, retry_config(3)).unwrap();
    model.borrow_mut().command_stop_stuck = true;
    let failure = controller.discover_codecs().unwrap_err();
    assert_eq!(failure.attempts, 1);
    assert_eq!(failure.error, Error::Timeout(Phase::CommandStop));
    assert_eq!(
        failure.failures,
        [CodecFailure {
            attempt: 1,
            address: 0,
            error: Error::InvalidCodecGraph
        }]
    );
    // The vendor ID probe, then enumeration's own read.
    assert_eq!(model.borrow().commands.len(), 2);
    let before = access_counts(&model);
    assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
    assert_eq!(
        controller.discover_codecs().unwrap_err().error,
        Error::NeedsReset
    );
    assert_eq!(access_counts(&model), before);
}

#[test]
fn reinitialize_stales_streams_and_routes() {
    let mut fixture = Fixture::new();
    let model = analog_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let graph = controller.enumerate_codec(0).unwrap();
    let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
    let old = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    let options = PinOptions::Playback {
        headphone: false,
        eapd: None,
    };
    controller
        .configure_analog_route(&graph, &route, old, 0, options)
        .unwrap();
    controller.start(old).unwrap();
    controller.reinitialize().unwrap();
    assert!(controller.routes.is_empty());
    assert!(controller.streams.iter().all(Option::is_none));
    let fresh_graph = controller.enumerate_codec(0).unwrap();
    let fresh = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    assert_eq!(fresh.descriptor_index(), old.descriptor_index());
    assert_eq!(fresh.tag(), old.tag());
    assert_ne!(fresh, old);
    let before = access_counts(&model);
    assert_eq!(controller.start(old), Err(Error::InvalidStream));
    assert_eq!(controller.stop(old), Err(Error::InvalidStream));
    assert_eq!(controller.status(old), Err(Error::InvalidStream));
    assert_eq!(controller.position(old), Err(Error::InvalidStream));
    assert_eq!(
        controller.write_pcm(old, 0, &[1]),
        Err(Error::InvalidStream)
    );
    assert_eq!(
        controller.bind_converter(&graph, 2, fresh, 0),
        Err(Error::InvalidCodecGraph)
    );
    assert_eq!(
        controller.configure_analog_route(&graph, &route, fresh, 0, options),
        Err(Error::InvalidCodecGraph)
    );
    assert_eq!(
        controller.configure_analog_route(&fresh_graph, &route, fresh, 0, options),
        Err(Error::InvalidCodecGraph)
    );
    assert_eq!(access_counts(&model), before);
    let fresh_route = fresh_graph.analog_route(Direction::Playback, 4, 2).unwrap();
    controller
        .configure_analog_route(&fresh_graph, &fresh_route, fresh, 0, options)
        .unwrap();
    controller.start(fresh).unwrap();
}

#[test]
fn failed_quiescence_retains_reservations() {
    for command_stop in [false, true] {
        let mut fixture = Fixture::new();
        let model = analog_model();
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        let route = graph.analog_route(Direction::Playback, 4, 2).unwrap();
        let id = controller
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
                id,
                0,
                PinOptions::Playback {
                    headphone: false,
                    eapd: None,
                },
            )
            .unwrap();
        controller.start(id).unwrap();
        let token = controller.token;
        let descriptor = stream_base(id.descriptor_index());
        let bdl = model
            .borrow()
            .address(descriptor + SD_BDLPL, descriptor + SD_BDLPU);
        if command_stop {
            model.borrow_mut().command_stop_stuck = true;
        } else {
            model.borrow_mut().stream_stop_stuck = true;
        }
        assert_eq!(
            controller.reinitialize(),
            Err(Error::Timeout(if command_stop {
                Phase::CommandStop
            } else {
                Phase::StreamStop
            }))
        );
        assert_eq!(controller.token, token);
        assert_eq!(controller.routes.len(), 1);
        let stream = controller.streams[usize::from(id.descriptor_index())]
            .as_ref()
            .unwrap();
        assert_eq!(
            model
                .borrow()
                .address(descriptor + SD_BDLPL, descriptor + SD_BDLPU),
            bdl
        );
        assert!(stream.poisoned);
        let before = access_counts(&model);
        let remaining = fixture.allocator.remaining();
        assert_eq!(controller.write_pcm(id, 0, &[1]), Err(Error::NeedsReset));
        assert_eq!(controller.start(id), Err(Error::NeedsReset));
        assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
        assert_eq!(
            controller.enumerate_codec(0).unwrap_err(),
            Error::NeedsReset
        );
        assert_eq!(
            controller.allocate_stream(
                Direction::Capture,
                stereo(),
                128,
                2,
                &mut fixture.allocator
            ),
            Err(Error::NeedsReset)
        );
        assert_eq!(fixture.allocator.remaining(), remaining);
        assert_eq!(access_counts(&model), before);
        model.borrow_mut().command_stop_stuck = false;
        model.borrow_mut().stream_stop_stuck = false;
        controller.reinitialize().unwrap();
        assert!(controller.routes.is_empty());
        assert_eq!(controller.start(id), Err(Error::InvalidStream));
        controller.enumerate_codec(0).unwrap();
    }
}

#[test]
fn failed_reset_requires_explicit_recovery() {
    let mut fixture = Fixture::new();
    let model = graph_model();
    let mut controller = create(&model, &mut fixture, config()).unwrap();
    let id = controller
        .allocate_stream(
            Direction::Playback,
            stereo(),
            128,
            2,
            &mut fixture.allocator,
        )
        .unwrap();
    model.borrow_mut().reset_exit_stuck = true;
    assert_eq!(
        controller.reinitialize(),
        Err(Error::Timeout(Phase::LinkResetExit))
    );
    assert_eq!(controller.token.generation, 2);
    let before = access_counts(&model);
    assert_eq!(controller.start(id), Err(Error::InvalidStream));
    assert_eq!(controller.verb(verb()), Err(Error::NeedsReset));
    assert_eq!(access_counts(&model), before);
    model.borrow_mut().reset_exit_stuck = false;
    controller.reinitialize().unwrap();
    controller.enumerate_codec(0).unwrap();
    controller.token.generation = u64::MAX;
    let before = access_counts(&model);
    assert_eq!(controller.reinitialize(), Err(Error::NeedsReset));
    assert_eq!(access_counts(&model), before);
}
