// SPDX-License-Identifier: GPL-2.0-only
//! realtek fixed headphone behavior tests.
use super::*;

#[test]
fn alc255_depop_preserves_eapd_passthrough_until_the_final_literal_and_reserves_real_pcm() {
    for present in [false, true] {
        let mut fixture = Fixture::new();
        let model = realtek_headphone_model(0x10ec0255, present);
        {
            let mut m = model.borrow_mut();
            m.coefficients.insert((0x20, 0x36), 0xaaff);
            m.coefficients.insert((0x20, 0x46), 0xb5a5);
            m.coefficients.insert((0x57, 4), 0xab07);
            m.coefficients.insert((0x53, 2), 0x9234);
        }
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
        let options = PinOptions::Playback {
            headphone: true,
            eapd: Some(true),
        };
        let before = access_counts(&model);
        assert_eq!(
            controller.configure_realtek_alc256_headphone(&graph, &route, stream, 0, options),
            Err(Error::UnsupportedTopology)
        );
        assert_eq!(access_counts(&model), before);
        let start = model.borrow().clock.now_us();
        let report = controller
            .configure_realtek_alc255_headphone(&graph, &route, stream, 0, options)
            .unwrap();
        assert_eq!(report.common.codec_id, 0x10ec0255);
        assert_eq!(report.initial_sense.present, present);
        assert_eq!(
            report
                .common
                .coefficients
                .iter()
                .map(|c| c.index)
                .collect::<Vec<_>>(),
            [0x10, 0x46, 0x36]
        );
        assert_eq!(report.common.coefficients[2].previous, 0xaaff);
        assert_eq!(report.common.coefficients[2].current, 0x5757);
        {
            let m = model.borrow();
            let events = &m.coefficient_events;
            let literal: Vec<_> = events
                .iter()
                .filter(|(node, index, _, _)| *node == 0x20 && *index == 0x36)
                .collect();
            assert_eq!(literal.len(), 1);
            let reset: Vec<_> = events
                .iter()
                .filter(|(node, _, _, _)| *node == 0x53)
                .collect();
            assert_eq!(reset.len(), 2);
            assert_eq!((reset[0].2, reset[1].2), (0x9234, 0x1234));
            assert!(reset[0].3 < reset[1].3 && reset[1].3 < literal[0].3);
            let hp: Vec<_> = events
                .iter()
                .filter(|(node, _, _, _)| *node == 0x57)
                .collect();
            assert_eq!(hp.len(), if present { 2 } else { 0 });
            if present {
                assert_eq!((hp[0].2, hp[1].2), (0xab01, 0xab04));
                assert!(hp[0].3 >= start + 32_000);
                assert!(hp[1].3 >= hp[0].3 + 150_000);
            }
            assert_eq!(m.coefficients[&(0x20, 0x10)], 0xa5ff);
            assert_eq!(m.coefficients[&(0x20, 0x46)], 0x85a5);
        }
        assert_eq!(controller.routes.len(), 1);
        controller.write_pcm(stream, 0, &[0x5b; 256]).unwrap();
        controller.start(stream).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 4);
        assert!(controller.status(stream).unwrap().period_completed);
        controller.stop(stream).unwrap();
        assert!(model.borrow().playback.len() >= 256);
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x5b));
        controller.shutdown().unwrap();
    }
}

#[test]
fn alc255_live_identity_and_late_depop_failure_do_not_publish_a_route() {
    for fault in 0..3 {
        let mut fixture = Fixture::new();
        let model = realtek_headphone_model(0x10ec0255, true);
        model.borrow_mut().coefficients.insert((0x53, 2), 0x1234);
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
        {
            let mut m = model.borrow_mut();
            if fault == 0 {
                m.parameters.insert((0, 0), 0x10ec0256);
            } else {
                m.coefficient_read_fault = Some(u32::MAX);
                m.coefficient_fault_node = Some(0x53);
                m.coefficient_fault_after_write = true;
                m.coefficient_fault_write_threshold = fault;
            }
        }
        let result = controller.configure_realtek_alc255_headphone(
            &graph,
            &route,
            stream,
            0,
            PinOptions::Playback {
                headphone: true,
                eapd: None,
            },
        );
        assert_eq!(
            result,
            Err(if fault == 0 {
                Error::InvalidCodecGraph
            } else {
                Error::CoefficientRejected {
                    node: 0x53,
                    index: 2,
                }
            })
        );
        assert!(controller.routes.is_empty());
        if fault == 0 {
            assert!(model.borrow().coefficient_events.is_empty());
            assert!(!controller.routing_failed);
        } else {
            assert!(controller.routing_failed);
            assert_eq!(model.borrow().coefficient_write_nodes[&0x53], fault);
            let before = access_counts(&model);
            assert_eq!(controller.start(stream), Err(Error::NeedsReset));
            assert_eq!(access_counts(&model), before);
        }
    }
}

#[test]
fn alc256_and_257_depop_use_fixed_nodes_ordered_reset_edges_and_timed_stereo_route() {
    for id in [0x10ec0256, 0x10ec0257] {
        for present in [false, true] {
            for reset_already_high in [false, true] {
                let mut fixture = Fixture::new();
                let model = realtek_headphone_model(id, present);
                {
                    let mut m = model.borrow_mut();
                    m.coefficients.insert((0x57, 4), 0xab07);
                    m.coefficients
                        .insert((0x53, 2), if reset_already_high { 0x9234 } else { 0x1234 });
                    m.coefficients.insert((0x20, 0x36), 0xaaff);
                    m.coefficients.insert((0x20, 0x46), 0xb5a5);
                }
                let mut controller = create(&model, &mut fixture, config()).unwrap();
                let graph = controller.enumerate_codec(0).unwrap();
                let route = graph
                    .analog_endpoints(Direction::Playback, stereo())
                    .unwrap()
                    .remove(0)
                    .route;
                let stream = controller
                    .allocate_stream(
                        Direction::Playback,
                        stereo(),
                        128,
                        2,
                        &mut fixture.allocator,
                    )
                    .unwrap();
                let start = model.borrow().clock.now_us();
                let report = controller
                    .configure_realtek_alc256_headphone(
                        &graph,
                        &route,
                        stream,
                        0,
                        PinOptions::Playback {
                            headphone: true,
                            eapd: Some(true),
                        },
                    )
                    .unwrap();
                assert_eq!(report.common.codec_id, id);
                assert_eq!(report.initial_sense.present, present);
                let m = model.borrow();
                assert_eq!(m.coefficients[&(0x20, 0x36)], 0x5757);
                assert_eq!(m.coefficients[&(0x20, 0x46)], 0x85a5);
                assert_eq!(m.coefficients[&(0x20, 0x10)], 0xa5ff);
                assert_eq!(m.coefficients[&(0x53, 2)], 0x1234);
                assert_eq!(
                    m.coefficients[&(0x57, 4)],
                    if present { 0xab04 } else { 0xab07 }
                );
                let reset: Vec<_> = m
                    .coefficient_events
                    .iter()
                    .filter(|(node, _, _, _)| *node == 0x53)
                    .collect();
                // Do not optimize away an already-high first write.
                assert_eq!(reset.len(), 2);
                assert_eq!((reset[0].1, reset[0].2), (2, 0x9234));
                assert_eq!((reset[1].1, reset[1].2), (2, 0x1234));
                assert!(reset[0].3 < reset[1].3);
                let hp: Vec<_> = m
                    .coefficient_events
                    .iter()
                    .filter(|(node, _, _, _)| *node == 0x57)
                    .collect();
                assert_eq!(hp.len(), if present { 2 } else { 0 });
                let sense = m
                    .command_times
                    .iter()
                    .find(|(command, _)| {
                        (command >> 20) & 127 == 4 && (command >> 8) & 0xfff == 0xf09
                    })
                    .unwrap()
                    .1;
                assert!(sense >= start + 30_000);
                if present {
                    assert_eq!((hp[0].1, hp[0].2), (4, 0xab01));
                    assert_eq!((hp[1].1, hp[1].2), (4, 0xab04));
                    let pin = m
                        .command_times
                        .iter()
                        .find(|(command, _)| {
                            (command >> 20) & 127 == 4
                                && (command >> 8) & 0xfff == 0x707
                                && *command as u8 == 0x40
                        })
                        .unwrap()
                        .1;
                    let amp = m
                        .command_times
                        .iter()
                        .find(|(command, _)| {
                            (command >> 20) & 127 == 4
                                && (command >> 16) & 15 == 3
                                && *command as u16 == 0xb000
                        })
                        .unwrap()
                        .1;
                    assert!(hp[0].3 >= sense + 2_000 && pin > hp[0].3);
                    assert!(amp >= pin + 75_000);
                    assert!(hp[1].3 >= amp + 75_000);
                    assert!(reset[0].3 > hp[1].3);
                }
                let final_36 = m
                    .coefficient_events
                    .iter()
                    .rfind(|(node, index, _, _)| *node == 0x20 && *index == 0x36)
                    .unwrap();
                assert_eq!(final_36.2, 0x5757);
                assert!(final_36.3 > reset[1].3);
                assert!(
                    m.coefficient_events
                        .iter()
                        .all(|(node, _, _, _)| matches!(node, 0x20 | 0x53 | 0x57))
                );
                drop(m);
                assert_eq!(controller.routes.len(), 1);
                // Add capture after startup: the existing common reservation
                // scheme still permits a separate explicit ADC/pin path.
                let capture = controller
                    .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
                    .unwrap();
                let input = graph.analog_route(Direction::Capture, 5, 3).unwrap();
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
                controller.fill_capture(capture, 0xa5).unwrap();
                controller.write_pcm(stream, 0, &[0x69; 256]).unwrap();
                controller.start(stream).unwrap();
                controller.start(capture).unwrap();
                model.borrow_mut().dma_step_bytes = 128;
                advance(&model, 4);
                assert!(controller.status(stream).unwrap().period_completed);
                controller.stop(stream).unwrap();
                controller.stop(capture).unwrap();
                assert!(model.borrow().playback.len() >= 256);
                assert!(model.borrow().playback.iter().all(|byte| *byte == 0x69));
                let mut bytes = [0; 256];
                controller.read_pcm(capture, 0, &mut bytes).unwrap();
                assert_eq!(bytes, core::array::from_fn(|index| index as u8));
                controller.shutdown().unwrap();
            }
        }
    }
}

#[test]
fn alc256_fixed_power_reset_index_data_and_each_pulse_readback_failure_quarantine_start() {
    for fault in 0..10 {
        let mut fixture = Fixture::new();
        let model = realtek_headphone_model(0x10ec0256, true);
        {
            let mut m = model.borrow_mut();
            m.coefficients.insert((0x57, 4), 0xab07);
            m.coefficients.insert((0x53, 2), 0x1234);
            if fault < 6 {
                m.coefficient_read_fault = Some(if fault == 5 { 0x1ffff } else { u32::MAX });
                m.coefficient_fault_node = Some(if fault == 0 || fault == 1 || fault == 5 {
                    0x57
                } else {
                    0x53
                });
                m.coefficient_fault_after_write = matches!(fault, 1 | 3 | 4);
                m.coefficient_fault_write_threshold = if fault == 4 { 2 } else { 1 };
            } else if fault < 8 {
                m.reject_coefficient_node = Some(if fault == 6 { 0x57 } else { 0x53 });
            } else {
                m.coefficient_index_reply = Some((
                    if fault == 8 { 0x57 } else { 0x53 },
                    if fault == 8 { 0 } else { u32::MAX },
                ));
            }
        }
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
        let node = if matches!(fault, 0 | 1 | 5 | 6 | 8) {
            0x57
        } else {
            0x53
        };
        assert_eq!(
            controller
                .configure_realtek_alc256_headphone(
                    &graph,
                    &route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None
                    }
                )
                .unwrap_err(),
            Error::CoefficientRejected {
                node,
                index: if node == 0x57 { 4 } else { 2 }
            }
        );
        assert!(controller.routing_failed);
        assert!(controller.routes.is_empty());
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(
            controller.configure_realtek_alc256_headphone(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd: None
                }
            ),
            Err(Error::NeedsReset)
        );
        assert_eq!(access_counts(&model), before);
        if fault == 3 {
            {
                let mut m = model.borrow_mut();
                m.coefficient_read_fault = None;
                m.coefficient_index_reply = None;
                m.reject_coefficient_node = None;
            }
            controller.reinitialize().unwrap();
            let fresh = controller.enumerate_codec(0).unwrap();
            let route = fresh.analog_route(Direction::Playback, 4, 2).unwrap();
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
                .configure_realtek_alc256_headphone(
                    &fresh,
                    &route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None,
                    },
                )
                .unwrap();
            assert_eq!(controller.routes.len(), 1);
        }
    }
}
