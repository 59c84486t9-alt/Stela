// SPDX-License-Identifier: GPL-2.0-only
//! realtek alc298 behavior tests.
use super::*;

#[test]
fn headphone_startup_timing() {
    for present in [false, true] {
        let mut fixture = Fixture::new();
        let model = realtek_headphone_model(0x10ec0298, present);
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
            .configure_realtek_alc298_headphone(
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
        assert_eq!(report.common.codec_id, 0x10ec0298);
        assert_eq!(report.headphone_pin, 4);
        assert_eq!(report.initial_sense.present, present);
        assert_eq!(report.common.coefficients[0].current, 0xa5ff);
        let m = model.borrow();
        let find = |predicate: fn(u32) -> bool| {
            m.command_times
                .iter()
                .find(|(command, _)| predicate(*command))
                .map(|(_, time)| *time)
        };
        let sense_time =
            find(|command| (command >> 20) & 127 == 4 && (command >> 8) & 0xfff == 0xf09).unwrap();
        assert!(sense_time >= start + 30_000);
        let pin_time = find(|command| {
            (command >> 20) & 127 == 4 && (command >> 8) & 0xfff == 0x707 && command as u8 == 0x40
        });
        let amp_time = find(|command| {
            (command >> 20) & 127 == 4 && (command >> 16) & 15 == 3 && command as u16 == 0xb000
        });
        assert_eq!(pin_time.is_some(), present);
        assert_eq!(amp_time.is_some(), present);
        if present {
            assert!(pin_time.unwrap() >= sense_time + 2_000);
            assert!(amp_time.unwrap() >= pin_time.unwrap() + 75_000);
            let generic_power = m
                .command_times
                .iter()
                .find(|(command, time)| {
                    *time > amp_time.unwrap() && (command >> 8) & 0xfff == 0x705
                })
                .unwrap()
                .1;
            assert!(generic_power >= amp_time.unwrap() + 75_000);
        }
        assert!(m.power_ready.contains_key(&4));
        assert_eq!(m.route_controls[&(4, 0xf07)], 0xc0);
        assert_eq!(m.route_controls[&(4, 0xf0c)], 7);
        drop(m);
        assert_eq!(controller.routes.len(), 1);
        let before = access_counts(&model);
        assert_eq!(
            controller.configure_realtek_alc298_headphone(
                &graph,
                &route,
                stream,
                0,
                PinOptions::Playback {
                    headphone: true,
                    eapd: None
                }
            ),
            Err(Error::RouteInUse)
        );
        assert_eq!(access_counts(&model), before);
        controller.write_pcm(stream, 0, &[0x46; 256]).unwrap();
        controller.start(stream).unwrap();
        model.borrow_mut().dma_step_bytes = 128;
        advance(&model, 4);
        assert!(controller.status(stream).unwrap().period_completed);
        controller.stop(stream).unwrap();
        assert!(model.borrow().playback.len() >= 256);
        assert!(model.borrow().playback.iter().all(|byte| *byte == 0x46));
        controller.shutdown().unwrap();
    }
}

#[test]
fn stale_route_rejected() {
    for fault in 0..7 {
        let mut fixture = Fixture::new();
        let model = realtek_headphone_model(0x10ec0298, true);
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
        let mut options = PinOptions::Playback {
            headphone: true,
            eapd: None,
        };
        match fault {
            0 => {
                options = PinOptions::Playback {
                    headphone: false,
                    eapd: None,
                }
            }
            1 => {
                model.borrow_mut().pin_defaults.insert(4, 0x0101_4010);
            }
            2 => {
                model.borrow_mut().parameters.insert((4, 0x0c), 0x10);
            }
            3 => {
                model.borrow_mut().parameters.insert((0, 0), 0x10ec0256);
            }
            4 => {
                model.borrow_mut().parameters.insert((0x51, 0), 0x10ec5505);
            }
            5 => {
                model.borrow_mut().parameters.insert((1, 0x12), 0);
            }
            6 => {
                controller.reinitialize().unwrap();
            }
            _ => unreachable!(),
        }
        let fresh = if fault == 6 {
            Some(controller.enumerate_codec(0).unwrap())
        } else {
            None
        };
        let graph = fresh.as_ref().unwrap_or(&graph);
        let route = if fault == 6 {
            graph.analog_route(Direction::Playback, 4, 2).unwrap()
        } else {
            route
        };
        let before = access_counts(&model);
        assert!(
            controller
                .configure_realtek_alc298_headphone(graph, &route, stream, 0, options)
                .is_err()
        );
        if fault == 6 {
            assert_eq!(access_counts(&model), before);
        }
        assert!(
            model.borrow().commands[before.2..]
                .iter()
                .all(|command| (command >> 16) & 15 >= 8)
        );
        assert!(model.borrow().coefficient_indexes.is_empty());
        assert!(!controller.routing_failed);
    }
}

#[test]
fn startup_failure_quarantines_routes() {
    for fault in 0..4 {
        let mut fixture = Fixture::new();
        let model = realtek_headphone_model(0x10ec0298, true);
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
        match fault {
            0 => model.borrow_mut().coefficient_index_failed = true,
            1 => model.borrow_mut().reject_route_control = Some(0xf07),
            2 => model.borrow_mut().reject_amplifier = true,
            3 => model.borrow_mut().power_stuck = true,
            _ => unreachable!(),
        }
        assert!(
            controller
                .configure_realtek_alc298_headphone(
                    &graph,
                    &route,
                    stream,
                    0,
                    PinOptions::Playback {
                        headphone: true,
                        eapd: None
                    }
                )
                .is_err()
        );
        assert!(controller.routing_failed);
        assert!(controller.routes.is_empty());
        let before = access_counts(&model);
        assert_eq!(controller.start(stream), Err(Error::NeedsReset));
        assert_eq!(
            controller.configure_realtek_alc298_headphone(
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
    }
}
