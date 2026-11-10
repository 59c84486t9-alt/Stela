use super::*;

const TSC_HZ: u128 = 4_699_999_000;
const PM_HZ: u128 = 3_579_545;
const HPET_PERIOD_FS: u128 = 69_841_279;

/// A fake machine: each read advances time by `step_ns`; the reference is
/// read 200 ns into a 400 ns bracket, `offset` ticks from zero.
struct Clock {
    now_ns: u128,
    step_ns: u128,
    offset: u128,
    mask: u128,
    /// Reference ticks per second, as a ratio of `numerator / denominator`.
    numerator: u128,
    denominator: u128,
}

impl Clock {
    fn pm(offset: u128) -> Self {
        Self {
            now_ns: 1_000_000,
            step_ns: 1_000,
            offset,
            mask: 0x00ff_ffff,
            numerator: PM_HZ,
            denominator: 1,
        }
    }
    fn tsc(ns: u128) -> u64 {
        (ns * TSC_HZ / 1_000_000_000) as u64
    }
    fn read(&mut self) -> Sample {
        let t = self.now_ns;
        self.now_ns += self.step_ns;
        let ticks = (t + 200) * self.numerator / (self.denominator * 1_000_000_000);
        Sample {
            tsc_before: Self::tsc(t),
            reference: ((ticks + self.offset) & self.mask) as u64,
            tsc_after: Self::tsc(t + 400),
        }
    }
}

fn within(measured: Measured) -> bool {
    let error = ppm_between(TSC_HZ as u64, measured.hz());
    error <= measured.uncertainty_ppm()
}

#[test]
fn pm_timer_window_across_a_24_bit_wrap_gives_the_rate() {
    let mut clock = Clock::pm(0x00ff_ff00);
    let reference = Reference {
        mask: 0x00ff_ffff,
        scale: ReferenceScale::Hertz(PM_HZ as u64),
    };
    let measured = measure(reference, || clock.read()).unwrap();
    assert!(within(measured), "{measured:?}");
    assert!(measured.uncertainty_ppm() <= 20, "{measured:?}");
    assert!(clock.now_ns >= 50_000_000);
}

#[test]
fn hpet_period_scale_gives_the_rate() {
    // Ticks per second are 10^15 / period: keep the ratio exact.
    let mut clock = Clock {
        mask: 0xffff_ffff,
        numerator: 1_000_000_000_000_000,
        denominator: HPET_PERIOD_FS,
        ..Clock::pm(0xffff_f000)
    };
    let reference = Reference {
        mask: 0xffff_ffff,
        scale: ReferenceScale::PeriodFemtoseconds(HPET_PERIOD_FS as u32),
    };
    let measured = measure(reference, || clock.read()).unwrap();
    assert!(within(measured), "{measured:?}");
}

#[test]
fn a_stopped_reference_is_refused_without_waiting_for_the_window() {
    let mut tsc = 0;
    let reference = Reference {
        mask: 0x00ff_ffff,
        scale: ReferenceScale::Hertz(PM_HZ as u64),
    };
    let result = measure(reference, || {
        tsc += 1000;
        Sample {
            tsc_before: tsc,
            reference: 5,
            tsc_after: tsc + 10,
        }
    });
    assert_eq!(result, Err(Error::NoProgress));
    assert!(tsc < 1000 * (START_POLLS as u64 + 4));
}

#[test]
fn a_reference_that_goes_back_is_refused() {
    let mut clock = Clock::pm(0);
    let mut reads = 0;
    let reference = Reference {
        mask: 0x00ff_ffff,
        scale: ReferenceScale::Hertz(PM_HZ as u64),
    };
    let result = measure(reference, || {
        reads += 1;
        let mut sample = clock.read();
        if reads == 100 {
            sample.reference = sample.reference.wrapping_sub(1000) & 0x00ff_ffff;
        }
        sample
    });
    assert_eq!(result, Err(Error::Disturbed));
}

#[test]
fn a_disturbed_bracket_is_read_again_and_the_rate_holds() {
    let mut clock = Clock::pm(0);
    let mut reads = 0;
    let reference = Reference {
        mask: 0x00ff_ffff,
        scale: ReferenceScale::Hertz(PM_HZ as u64),
    };
    let measured = measure(reference, || {
        reads += 1;
        let mut sample = clock.read();
        if reads == 7 {
            // An SMI inside the bracket.
            sample.tsc_after += 10_000_000;
        }
        sample
    })
    .unwrap();
    assert!(within(measured), "{measured:?}");
}

fn window(hz: u64, ppm: u64) -> Measured {
    let half = hz / 1_000_000 * ppm;
    Measured {
        window: RateWindow::from_bounds(hz - half, hz + half).unwrap(),
    }
}

#[test]
fn agreeing_windows_settle_on_their_intersection() {
    let mut asked = alloc::vec::Vec::new();
    let settled = settle(|which| {
        asked.push(which);
        Ok(match which {
            Window::Primary => window(4_700_000_000, 10),
            _ => window(4_700_020_000, 10),
        })
    })
    .unwrap();
    assert_eq!(asked, [Window::Primary, Window::CrossCheck]);
    assert!(settled.agreed);
    assert_eq!(settled.disagreement_ppm, 5);
    assert!(settled.hz.abs_diff(4_700_010_000) <= 47_000);
    assert!(settled.uncertainty_ppm <= 10);
}

#[test]
fn a_disagreeing_cross_check_is_decided_by_a_third_window() {
    let mut asked = alloc::vec::Vec::new();
    let settled = settle(|which| {
        asked.push(which);
        Ok(match which {
            Window::Primary => window(4_700_000_000, 10),
            Window::CrossCheck => window(4_506_689_000, 10),
            Window::TieBreak => window(4_700_004_700, 10),
        })
    })
    .unwrap();
    assert_eq!(
        asked,
        [Window::Primary, Window::CrossCheck, Window::TieBreak]
    );
    assert!(!settled.agreed);
    assert_eq!(settled.hz, 4_700_000_000);
    assert_eq!(settled.uncertainty_ppm, 10);
    assert!(settled.disagreement_ppm > 40_000);
}

#[test]
fn a_failed_window_fails_the_calibration() {
    let result = settle(|which| match which {
        Window::Primary => Ok(window(4_700_000_000, 10)),
        _ => Err(Error::NoProgress),
    });
    assert_eq!(result, Err(Error::NoProgress));
}
