use super::*;
use crate::{Clock, ClockError};

struct Untouched;
impl Registers for Untouched {
    fn status(&mut self) -> u8 {
        panic!("invalid native clock read status")
    }
    fn read_data(&mut self) -> u8 {
        panic!("invalid native clock consumed data")
    }
    fn write_command(&mut self, _: u8) {
        panic!("invalid native clock wrote command")
    }
    fn write_data(&mut self, _: u8) {
        panic!("invalid native clock wrote data")
    }
}

#[test]
fn native_clock_and_duration_refusal_precedes_every_i8042_profile_effect() {
    type Factory = fn(Untouched, Clock, Config) -> Result<Controller<Untouched, Clock>, Error>;
    let factories: [Factory; 3] = [
        Controller::new,
        |r, t, c| Controller::new_synaptics(r, t, c, false),
        Controller::new_elantech,
    ];
    for factory in factories {
        for (rate, expected) in [
            (0, ClockError::Uncalibrated),
            (u64::MAX, ClockError::DurationOverflow),
        ] {
            assert_eq!(
                factory(
                    Untouched,
                    Clock {
                        ticks_per_microsecond: rate
                    },
                    Config::default()
                )
                .err()
                .unwrap()
                .kind,
                ErrorKind::Clock(expected)
            );
        }
        assert_eq!(
            factory(
                Untouched,
                Clock {
                    ticks_per_microsecond: 1
                },
                Config {
                    packet_timeout_us: u64::MAX / 2 + 1,
                    ..Config::default()
                }
            )
            .err()
            .unwrap()
            .kind,
            ErrorKind::Clock(ClockError::DurationTooLong)
        );
    }
    let config = Config {
        io_timeout_us: 1,
        command_timeout_us: 1,
        reset_timeout_us: 1,
        packet_timeout_us: 1,
        ..Config::default()
    };
    assert_eq!(
        Controller::new_synaptics(
            Untouched,
            Clock {
                ticks_per_microsecond: u64::MAX / 10_000
            },
            config,
            false
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Clock(ClockError::DurationOverflow)
    );
    assert_eq!(
        Controller::new_elantech(
            Untouched,
            Clock {
                ticks_per_microsecond: u64::MAX / 100_000
            },
            config
        )
        .err()
        .unwrap()
        .kind,
        ErrorKind::Clock(ClockError::DurationOverflow)
    );
}

/// Model100ns raw timer: legacy quotient access fails. This is a
/// test service, not an invented native clock calibration or platform fact.
struct RawTimer(Rc<Cell<u64>>);
impl Timer for RawTimer {
    fn now_us(&self) -> u64 {
        panic!("native input used the legacy quotient")
    }
    fn start(&self) -> u64 {
        self.0.get()
    }
    fn elapsed_us(&self, marker: u64) -> u64 {
        self.0.get().wrapping_sub(marker) / 10
    }
    fn check_duration(&self, us: u64) -> Result<(), ClockError> {
        let ticks = us.checked_mul(10).ok_or(ClockError::DurationOverflow)?;
        if ticks > u64::MAX / 2 {
            Err(ClockError::DurationTooLong)
        } else {
            Ok(())
        }
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(10));
    }
}
#[test]
fn raw_counter_rollover_survives_real_commands_and_receipt_times_stay_owner_microseconds() {
    let (_, h) = controller(Config::default());
    let time = h.borrow().time.clone();
    time.set(u64::MAX - 50);
    h.borrow_mut().delay_at_read.insert(1, 600);
    let mut c =
        Controller::new(Model(h.clone()), RawTimer(time.clone()), Config::default()).unwrap();
    c.initialize().unwrap();
    assert!(c.is_ready());
    assert!(
        time.get() < 100_000,
        "actual modeled counter crossed raw rollover"
    );
    assert!(!h.borrow().delay_at_read.contains_key(&1));
    time.set(time.get().wrapping_add(70));
    let earliest_us = time.get().wrapping_sub(u64::MAX - 50) / 10;
    h.borrow_mut().inject_led = [8, 1, 0, 0].into_iter().map(|b| (Port::Mouse, b)).collect();
    c.set_leds(7).unwrap();
    let latest_us = time.get().wrapping_sub(u64::MAX - 50) / 10;
    let receipts: Vec<_> = c.retained_bytes().collect();
    assert_eq!(receipts.len(), 4);
    assert!(
        receipts
            .iter()
            .all(|(_, _, us)| (earliest_us..=latest_us).contains(us))
    );
    assert!(c.poll().unwrap().contains(&Input::Motion { dx: 1, dy: 0 }));
}

#[test]
fn late_ready_status_cannot_authorize_any_command_or_containment_write() {
    let (mut c, h) = controller(Config::default());
    h.borrow_mut().status_delay_us = c.config.io_timeout_us + 1;
    let error = c.initialize().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout(Phase::InputReady));
    assert_eq!(
        error.recovery_error,
        Some(ErrorKind::Timeout(Phase::InputReady))
    );
    assert!(h.borrow().writes.is_empty());
    assert_eq!(h.borrow().consumed, 0);
    assert!(c.needs_reset());
}
