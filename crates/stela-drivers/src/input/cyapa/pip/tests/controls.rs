//! Actual command effects, asynchronous responses and retained failure ownership.
use super::*;
fn target(generation: Generation) -> (Rc<RefCell<Hardware>>, Device<Wire, Irq, Time>) {
    let (h, mut d) = if generation == Generation::Gen6 {
        let h = gen6_tests::hardware6(false, 2);
        let d = gen6_tests::device6(&h);
        (h, d)
    } else {
        let h = hardware(false, 2);
        let d = device(&h);
        (h, d)
    };
    d.initialize().unwrap();
    (h, d)
}
fn commands(h: &Rc<RefCell<Hardware>>, first: usize) -> Vec<Vec<u8>> {
    h.borrow().effects[first..]
        .iter()
        .filter(|(bytes, _)| !bytes.is_empty())
        .map(|(bytes, _)| bytes.clone())
        .collect()
}
#[test]
fn both_generations_acknowledge_scan_intervals_and_keep_reporting_wake_and_stop() {
    for generation in [Generation::Gen5, Generation::Gen6] {
        for interval in [20, 30, 50, 51, 80, 255, 256, 1000] {
            let (h, mut d) = target(generation);
            let first = h.borrow().effects.len();
            assert_eq!(d.low_power(interval), Ok(interval));
            assert_eq!(
                d.state(),
                State::LowPower {
                    interval_ms: interval
                }
            );
            assert_eq!(
                h.borrow().power,
                if generation == Generation::Gen5 {
                    if interval <= 50 { 3 } else { 4 }
                } else {
                    if interval == 30 { 2 } else { 3 }
                }
            );
            let issued = commands(&h, first);
            if generation == Generation::Gen5 {
                let [low, high] = interval.to_le_bytes();
                assert_eq!(
                    issued,
                    [
                        vec![4, 0, 9, 0, 0x2f, 0, 6, 0x4c, 2, low, high, 0, 0],
                        vec![4, 0, 6, 0, 0x2f, 0, 5, 0x4c],
                        vec![4, 0, 6, 0, 0x2f, 0, 8, if interval <= 50 { 3 } else { 4 }],
                    ]
                );
            } else {
                let writes = issued
                    .iter()
                    .filter(|bytes| bytes.get(6) == Some(&0x47))
                    .count();
                assert_eq!(writes, usize::from(![30, 50].contains(&interval)));
                let actual = d.capabilities().unwrap().power_intervals.unwrap();
                assert_eq!(actual.0, 8);
                assert_eq!(actual.1, 30);
                assert_eq!(actual.2, if interval == 30 { 50 } else { interval });
            }
            let original = touch(1, 7, 1, 123);
            h.borrow_mut().queue.push_back(original.clone());
            let Some(Frame::Touches { raw, .. }) = d.poll().unwrap() else {
                panic!()
            };
            assert_eq!(raw.as_bytes(), original);
            d.wake().unwrap();
            assert_eq!(d.state(), State::Ready);
            assert_eq!(h.borrow().power, 1);
            d.low_power(interval).unwrap();
            d.stop().unwrap();
            assert_eq!(d.state(), State::Stopped);
            assert!(h.borrow().deep);
        }
    }
}
#[test]
fn gen6_empty_slot_actual_applied_intervals_and_readback_own_power_admission() {
    let (h, mut d) = target(Generation::Gen6);
    h.borrow_mut().intervals = (9, 0, 77);
    h.borrow_mut().set_intervals = Some((9, 66, 77));
    assert_eq!(d.low_power(65), Ok(66));
    assert_eq!(h.borrow().power, 2);
    assert_eq!(d.state(), State::LowPower { interval_ms: 66 });
    assert_eq!(d.capabilities().unwrap().power_intervals, Some((9, 66, 77)));
    d.wake().unwrap();
    let previous = d.capabilities().unwrap().power_intervals;
    h.borrow_mut().interval_readback = Some((9, 66, 77));
    h.borrow_mut().set_intervals = Some((9, 66, 90));
    assert_eq!(
        d.low_power(90).unwrap_err().kind,
        ErrorKind::IntervalReadback {
            expected: (9, 66, 90),
            actual: (9, 66, 77),
        }
    );
    assert_eq!(d.state(), State::Uncertain);
    assert_eq!(h.borrow().power, 1);
    assert!(!h.borrow().command_irq);
    assert_eq!(d.capabilities().unwrap().power_intervals, previous);
    assert_eq!(h.borrow().intervals, (9, 66, 90));
    assert_eq!(
        d.interval_update(),
        Some(&IntervalUpdate {
            requested: (9, 66, 90),
            applied: Some((9, 66, 90)),
            readback: Some((9, 66, 77)),
        })
    );
}
#[test]
fn gen6_applied_set_observation_survives_every_later_get_failure_and_timeout() {
    let (sample, mut owner) = target(Generation::Gen6);
    owner.low_power(120).unwrap();
    let get_write = sample
        .borrow()
        .effects
        .iter()
        .rposition(|(bytes, _)| bytes.get(6) == Some(&0x48))
        .unwrap()
        + 1;
    // Six idle drain reads, then GET write, response peek and complete body.
    for step in get_write - 6..=get_write + 2 {
        let (h, mut d) = target(Generation::Gen6);
        let previous = d.capabilities().unwrap().power_intervals;
        h.borrow_mut().fail = Some(step);
        assert!(matches!(
            d.low_power(120).unwrap_err().kind,
            ErrorKind::Bus(_)
        ));
        assert_eq!(
            d.interval_update(),
            Some(&IntervalUpdate {
                requested: (8, 30, 120),
                applied: Some((8, 30, 120)),
                readback: None,
            })
        );
        assert_eq!(d.capabilities().unwrap().power_intervals, previous);
        assert_eq!(d.state(), State::Uncertain);
        assert_eq!(h.borrow().power, 1);
        assert_eq!(h.borrow().effects.len(), step);
        let update = d.interval_update().copied();
        assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
        assert_eq!(d.interval_update().copied(), update);
    }
    for step in [get_write + 1, get_write + 2] {
        let (h, mut d) = target(Generation::Gen6);
        h.borrow_mut().jump = Some((step, 500_000));
        assert_eq!(d.low_power(120).unwrap_err().kind, ErrorKind::Timeout);
        assert_eq!(
            d.interval_update(),
            Some(&IntervalUpdate {
                requested: (8, 30, 120),
                applied: Some((8, 30, 120)),
                readback: None,
            })
        );
        assert_eq!(
            d.take_failed_packet().unwrap().as_bytes().len(),
            if step == get_write + 1 { 2 } else { 11 }
        );
        assert_eq!(d.state(), State::Uncertain);
        assert_eq!(h.borrow().power, 1);
    }
}
#[test]
fn interval_validation_is_effect_free_and_parameter_reply_identity_is_mandatory() {
    for generation in [Generation::Gen5, Generation::Gen6] {
        let (h, mut d) = target(generation);
        let first = h.borrow().effects.len();
        for interval in [0, 1, 19, 1001, u16::MAX] {
            assert_eq!(
                d.low_power(interval).unwrap_err().kind,
                ErrorKind::InvalidScanInterval(interval)
            );
        }
        assert_eq!(h.borrow().effects.len(), first);
        assert_eq!(d.state(), State::Ready);
    }
    for response in [(0x4d, 2), (0x4c, 0), (0x4c, 1), (0x4c, 4)] {
        let (h, mut d) = target(Generation::Gen5);
        h.borrow_mut().parameter_reply = Some(response);
        assert_eq!(
            d.low_power(100).unwrap_err().kind,
            ErrorKind::ParameterReply {
                id: response.0,
                size: response.1
            }
        );
        assert_eq!(h.borrow().low_interval, 100);
        assert_eq!(h.borrow().power, 1);
        assert_eq!(
            d.take_failed_packet().unwrap().as_bytes()[5..],
            [response.0, response.1]
        );
        assert_eq!(d.state(), State::Uncertain);
    }
}
#[test]
fn calibration_uses_both_sensing_modes_and_preserves_reports_around_scan_commands() {
    for generation in [Generation::Gen5, Generation::Gen6] {
        let (h, mut d) = target(generation);
        let first = h.borrow().effects.len();
        let original = touch(1, 6, 1, 7);
        h.borrow_mut().queue.push_back(original.clone());
        h.borrow_mut().inject = Some((0x28, vec![vec![6, 0, 3, 0, 0, 1]]));
        d.calibrate().unwrap();
        assert_eq!(
            commands(&h, first),
            [
                vec![4, 0, 5, 0, 0x2f, 0, 3],
                vec![4, 0, 6, 0, 0x2f, 0, 0x28, 0],
                vec![4, 0, 6, 0, 0x2f, 0, 0x28, 2],
                vec![4, 0, 5, 0, 0x2f, 0, 4],
            ]
        );
        assert_eq!(h.borrow().calibrations, [0, 2]);
        assert!(h.borrow().scanning);
        assert_eq!(d.state(), State::Ready);
        assert_eq!(d.take_pending_packet().unwrap().as_bytes(), original);
        assert_eq!(
            d.take_pending_packet().unwrap().as_bytes(),
            [6, 0, 3, 0, 0, 1]
        );
    }
}
#[test]
fn calibration_rejection_resumes_once_and_keeps_primary_and_cleanup_failures() {
    for generation in [Generation::Gen5, Generation::Gen6] {
        for mode in [0, 2] {
            for reject_resume in [false, true] {
                let (h, mut d) = target(generation);
                let first = h.borrow().effects.len();
                h.borrow_mut().calibration_status = Some((mode, 7));
                if reject_resume {
                    h.borrow_mut().bad_status = Some((4, 9));
                }
                let failure = d.calibrate().unwrap_err();
                assert_eq!(
                    failure.phase,
                    if mode == 0 {
                        CalibrationPhase::MutualCapacitance
                    } else {
                        CalibrationPhase::SelfCapacitance
                    }
                );
                assert_eq!(
                    failure.error.kind,
                    ErrorKind::CommandStatus {
                        command: 0x28,
                        status: 7
                    }
                );
                assert_eq!(
                    failure.response.unwrap().as_bytes(),
                    [6, 0, 0x1f, 0, 0xa8, 7]
                );
                assert_eq!(
                    failure.resume_error.map(|e| e.kind),
                    reject_resume.then_some(ErrorKind::CommandStatus {
                        command: 4,
                        status: 9
                    })
                );
                assert_eq!(
                    d.state(),
                    if reject_resume {
                        State::Uncertain
                    } else {
                        State::Ready
                    }
                );
                assert_eq!(
                    h.borrow().calibrations,
                    if mode == 0 { vec![0] } else { vec![0, 2] }
                );
                assert_eq!(
                    commands(&h, first)
                        .iter()
                        .filter(|bytes| bytes.get(6) == Some(&4))
                        .count(),
                    1
                );
                assert!(h.borrow().scanning);
            }
        }
    }
}
#[test]
fn calibration_timeout_and_late_bus_effects_never_replay_or_resume_uncertain_commands() {
    for generation in [Generation::Gen5, Generation::Gen6] {
        let (h, mut d) = target(generation);
        h.borrow_mut().omit = Some(0x28);
        let start = h.borrow().clock.get();
        let failure = d.calibrate().unwrap_err();
        assert_eq!(failure.phase, CalibrationPhase::MutualCapacitance);
        assert_eq!(failure.error.kind, ErrorKind::Timeout);
        assert!(failure.resume_error.is_none());
        assert!(h.borrow().clock.get().wrapping_sub(start) >= 5_000_000);
        assert!(!h.borrow().scanning);
        assert_eq!(d.state(), State::Uncertain);
        let (sample, mut owner) = target(generation);
        let first = sample.borrow().effects.len();
        owner.calibrate().unwrap();
        let count = sample.borrow().effects.len() - first;
        for offset in 1..=count {
            let (h, mut d) = target(generation);
            let original = d.capabilities().cloned();
            let next = h.borrow().effects.len() + offset;
            h.borrow_mut().fail = Some(next);
            let failure = d.calibrate().unwrap_err();
            assert!(matches!(failure.error.kind, ErrorKind::Bus(_)));
            assert!(failure.resume_error.is_none());
            assert_eq!(d.state(), State::Uncertain);
            assert_eq!(h.borrow().effects.len(), next);
            assert_eq!(d.capabilities(), original.as_ref());
            assert_eq!(d.calibrate().unwrap_err().error.kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), next);
        }
    }
}
#[test]
fn every_low_power_late_failure_retains_owner_and_refuses_replay() {
    for generation in [Generation::Gen5, Generation::Gen6] {
        let (sample, mut owner) = target(generation);
        let first = sample.borrow().effects.len();
        owner.low_power(120).unwrap();
        let count = sample.borrow().effects.len() - first;
        for offset in 1..=count {
            let (h, mut d) = target(generation);
            let first = h.borrow().effects.len();
            h.borrow_mut().fail = Some(first + offset);
            assert!(matches!(
                d.low_power(120).unwrap_err().kind,
                ErrorKind::Bus(_)
            ));
            assert_eq!(d.state(), State::Uncertain);
            assert!(d.capabilities().is_some());
            assert_eq!(h.borrow().effects.len(), first + offset);
            assert_eq!(d.low_power(120).unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(d.wake().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(d.stop().unwrap_err().kind, ErrorKind::NeedsReset);
            assert_eq!(h.borrow().effects.len(), first + offset);
        }
        let (h, mut d) = target(generation);
        let original = touch(1, 9, 1, 5);
        h.borrow_mut().queue.push_back(original.clone());
        h.borrow_mut().omit = Some(if generation == Generation::Gen5 {
            6
        } else {
            0x42
        });
        assert_eq!(d.low_power(120).unwrap_err().kind, ErrorKind::Timeout);
        assert_eq!(d.take_pending_packet().unwrap().as_bytes(), original);
    }
}

#[test]
#[ignore = "oracle: STELA_CYAPA_CONTROL_ORACLE"]
fn retained_linux_control_commands_match_actual_native_device_operations() {
    extern crate std;
    let path = std::env::var("STELA_CYAPA_CONTROL_ORACLE").expect("source records path");
    let records = std::fs::read_to_string(path).expect("source records");
    let mut count = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 5);
        let value: u16 = fields[1].parse().unwrap();
        let bytes: Vec<u8> = fields[2]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let generation = if fields[0].starts_with("g6") {
            Generation::Gen6
        } else {
            Generation::Gen5
        };
        let (h, mut d) = target(generation);
        let first = h.borrow().effects.len();
        let actual = if fields[0] == "calibrate" || fields[0] == "scan" {
            d.calibrate().unwrap();
            let code = if fields[0] == "calibrate" {
                0x28
            } else {
                value as u8
            };
            assert_eq!(fields[3], if code == 0x28 { "5000" } else { "500" });
            assert_eq!(fields[4], "1");
            commands(&h, first)
                .into_iter()
                .find(|bytes| bytes[6] == code && (code != 0x28 || bytes[7] == value as u8))
                .unwrap()
        } else {
            assert_eq!(fields[3..], ["500", "0"]);
            d.low_power(value).unwrap();
            let code = match fields[0] {
                "g5set" => 6,
                "g5get" => 5,
                "g6set" => 0x47,
                "g6get" => 0x48,
                _ => panic!("unknown source record"),
            };
            commands(&h, first)
                .into_iter()
                .find(|bytes| bytes[6] == code)
                .unwrap()
        };
        assert_eq!(actual, bytes, "source record {line}");
        count += 1;
    }
    assert_eq!(count, 3924);
}
