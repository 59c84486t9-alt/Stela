// SPDX-License-Identifier: GPL-2.0-only
//! headset behavior tests.
use super::*;

#[test]
fn cold_trim_and_duplex() {
    for id in [0x14f1_1f86, 0x14f1_1f87] {
        for present in [false, true] {
            let mut fixture = Fixture::new();
            let model = headset_device(id, present);
            let mut controller = create(&model, &mut fixture, config()).unwrap();
            let graph = controller.enumerate_codec(0).unwrap();
            assert_eq!(
                controller.initialize_conexant_codec(&graph),
                Err(Error::UnsupportedTopology)
            );
            let report = controller
                .initialize_conexant_headset_codec(&graph)
                .unwrap();
            assert_eq!(model.borrow().conexant_trim, Some(0xe10));
            assert_eq!(
                report.headset.kind,
                if present {
                    ConexantHeadsetKind::Unclassified
                } else {
                    ConexantHeadsetKind::Disconnected
                }
            );
            assert_eq!(
                report.headset.microphone_control,
                if present { 0x24 } else { 0x20 }
            );
            let m = model.borrow();
            assert!(m.commands.contains(&((0x1c << 20) | 0x3be10)));
            assert_eq!(m.conexant_detection_reads, 0);
            drop(m);
            let output = graph.analog_route(Direction::Playback, 0x16, 2).unwrap();
            let input = graph.analog_route(Direction::Capture, 0x19, 3).unwrap();
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
            assert_eq!(
                controller.configure_analog_route(
                    &graph,
                    &output,
                    playback,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: None
                    }
                ),
                Err(Error::InvalidPinControl)
            );
            controller
                .configure_analog_route(
                    &graph,
                    &output,
                    playback,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None,
                    },
                )
                .unwrap();
            let vref = if present {
                Vref::EightyPercent
            } else {
                Vref::HighImpedance
            };
            let wrong = if present {
                Vref::HighImpedance
            } else {
                Vref::EightyPercent
            };
            assert_eq!(
                controller.configure_analog_route(
                    &graph,
                    &input,
                    capture,
                    0,
                    PinOptions::Capture { vref: wrong }
                ),
                Err(Error::InvalidPinControl)
            );
            assert!(!controller.routing_failed);
            controller
                .configure_analog_route(&graph, &input, capture, 0, PinOptions::Capture { vref })
                .unwrap();
            controller
                .set_conexant_outputs_enabled(&graph, true)
                .unwrap();
            controller.write_pcm(playback, 0, &[0x39; 256]).unwrap();
            controller.fill_capture(capture, 0xa5).unwrap();
            controller.start(capture).unwrap();
            controller.start(playback).unwrap();
            model.borrow_mut().dma_step_bytes = 128;
            advance(&model, 16);
            assert!(controller.status(playback).unwrap().period_completed);
            assert!(controller.status(capture).unwrap().period_completed);
            model
                .borrow_mut()
                .pin_senses
                .insert(0x19, if present { 0 } else { 1 << 31 });
            let changed = controller.poll_conexant_headset(&graph).unwrap();
            assert_eq!(
                changed.microphone_control,
                if present { 0x20 } else { 0x24 }
            );
            assert!(controller.status(capture).unwrap().running);
            controller.stop(capture).unwrap();
            let mut actual = [0; 256];
            controller.read_pcm(capture, 0, &mut actual).unwrap();
            assert_eq!(actual, core::array::from_fn(|index| index as u8));
            controller.shutdown().unwrap();
            assert!(model.borrow().playback.iter().all(|byte| *byte == 0x39));
            assert!(model.borrow().playback.len() >= 256);
        }
    }
}

#[test]
fn headphone_detection_precedence() {
    for (raw, kind) in [
        (0, ConexantHeadsetKind::Headphone),
        (0x400, ConexantHeadsetKind::Omtp),
        (0x800, ConexantHeadsetKind::Ctia),
        (0xc00, ConexantHeadsetKind::Ctia),
    ] {
        let mut fixture = Fixture::new();
        let model = headset_device(0x14f1_1f87, false);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller
            .initialize_conexant_headset_codec(&graph)
            .unwrap();
        {
            let mut m = model.borrow_mut();
            m.pin_senses.insert(0x19, 0x8000_005a);
            m.conexant_type = raw;
            m.conexant_detection_ready = Some(m.clock.now_us() + 25_000);
        }
        let writes_before = model.borrow().conexant_mic_writes;
        let before = model.borrow().clock.now_us();
        let report = controller.poll_conexant_headset(&graph).unwrap();
        assert_eq!(report.kind, kind);
        assert_eq!(
            model.borrow().conexant_mic_writes - writes_before,
            if raw == 0 { 1 } else { 2 }
        );
        assert_eq!(report.sense, 0x8000_005a);
        assert_eq!(report.detection_status, Some(0x80));
        assert_eq!(report.type_status, Some(raw));
        assert_eq!(report.microphone_control, 0x24);
        assert_eq!(model.borrow().conexant_detection_reads, 3);
        assert!(model.borrow().clock.now_us() - before >= 40_000);
        let before = model.borrow().conexant_detection_reads;
        model.borrow_mut().pin_senses.insert(0x19, 0);
        let report = controller.poll_conexant_headset(&graph).unwrap();
        assert_eq!(report.kind, ConexantHeadsetKind::Disconnected);
        assert_eq!(report.microphone_control, 0x20);
        assert_eq!(model.borrow().conexant_detection_reads, before);
    }
}

#[test]
fn detection_failure_keeps_routes() {
    for fault in 0..6 {
        let mut fixture = Fixture::new();
        let model = headset_device(0x14f1_1f86, true);
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        controller
            .initialize_conexant_headset_codec(&graph)
            .unwrap();
        let route = graph.analog_route(Direction::Capture, 0x19, 3).unwrap();
        let stream = controller
            .allocate_stream(Direction::Capture, stereo(), 128, 2, &mut fixture.allocator)
            .unwrap();
        controller
            .configure_analog_route(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Capture {
                    vref: Vref::EightyPercent,
                },
            )
            .unwrap();
        {
            let mut m = model.borrow_mut();
            match fault {
                0 => m.conexant_detection_ready = None,
                1 => m.conexant_vendor_fault = Some(0xca0),
                2 => m.conexant_vendor_fault = Some(0xcb0),
                3 => {
                    m.reject_route_control = Some(0xf07);
                    m.reject_route_node = Some(0x19);
                }
                4 => {
                    m.pin_senses.insert(0x19, u32::MAX);
                }
                _ => {
                    m.conexant_mic_fault_after = Some(m.conexant_mic_writes + 2);
                }
            }
        }
        let before = model.borrow().clock.now_us();
        let expected = if fault == 0 {
            Error::Timeout(crate::audio::Phase::CodecHeadsetDetection)
        } else {
            Error::RouteRejected
        };
        assert_eq!(controller.poll_conexant_headset(&graph), Err(expected));
        if fault == 0 {
            assert_eq!(model.borrow().conexant_detection_reads, 3);
            assert!(model.borrow().clock.now_us() - before >= 60_000);
        }
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(access_counts(&model), before);
        assert_eq!(controller.routes.len(), 1);
        assert_eq!(controller.conexant_codecs.len(), 1);
        {
            let mut m = model.borrow_mut();
            m.conexant_vendor_fault = None;
            m.reject_route_control = None;
            m.conexant_mic_fault_after = None;
        }
        controller.reinitialize().unwrap();
        assert!(controller.conexant_codecs.is_empty());
    }
}

#[test]
fn cold_failure_blocks_readiness() {
    for fault in 0..6 {
        let mut fixture = Fixture::new();
        let model = headset_device(0x14f1_1f87, true);
        if fault == 0 {
            model.borrow_mut().parameters.insert((0x19, 0x0c), 0x120);
        }
        let mut controller = create(&model, &mut fixture, config()).unwrap();
        let graph = controller.enumerate_codec(0).unwrap();
        if fault == 1 {
            model.borrow_mut().parameters.insert((0x1c, 9), u32::MAX);
        }
        if fault == 2 {
            model.borrow_mut().pin_senses.insert(0x19, u32::MAX);
        }
        if fault == 3 {
            model.borrow_mut().reject_route_control = Some(0xf07);
        }
        if fault == 4 {
            model.borrow_mut().drop_reply_command = Some((0x1c << 20) | 0x3be10);
        }
        if fault == 5 {
            model.borrow_mut().conexant_vendor_fault = Some(0x3be);
        }
        let before = model.borrow().commands.len();
        assert!(
            controller
                .initialize_conexant_headset_codec(&graph)
                .is_err()
        );
        if fault < 2 {
            assert!(controller.conexant_codecs.is_empty());
            assert!(
                model.borrow().commands[before..]
                    .iter()
                    .all(|v| ((v >> 8) & 0xfff) >= 0xf00)
            );
        } else {
            assert_eq!(controller.conexant_codecs.len(), 1);
            assert!(controller.routing_failed);
            assert_eq!(
                controller.poll_conexant_headset(&graph),
                Err(Error::NeedsReset)
            );
        }
    }
}
