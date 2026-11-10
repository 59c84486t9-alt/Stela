//! The TSC's rate measured before ExitBootServices against a fixed-rate
//! reference counter (the ACPI PM timer or the HPET), as Linux's
//! `pit_hpet_ptimer_calibrate_cpu` measures it, but over one long window
//! whose two ends are each bracketed by TSC reads. Interrupts and SMIs
//! between the ends cost the TSC and the reference the same real time, so
//! only a disturbed bracket matters, and [`stable_sample`] rejects it. A
//! cross-check window, on a second reference where one exists, must agree;
//! otherwise a third window on the first reference decides by median.
use super::{Error, RateWindow, ReferenceScale, Sample, measurement::stable_sample};

/// The shortest window: 50 ms, which keeps a few microseconds of bracket
/// width under 100 ppm.
pub const WINDOW_NS: u64 = 50_000_000;
/// Samples taken before a reference that never moves is refused.
const START_POLLS: usize = 1 << 16;
/// Samples one window may take: far more than 50 ms of the slowest reads.
const MAX_POLLS: usize = 1 << 24;
/// Rate difference two references may show beyond their own bracket
/// uncertainty: chipsets clock the PM timer and the HPET from one crystal.
const AGREEMENT_PPM: u64 = 100;
const PPM: u128 = 1_000_000;

/// A fixed-rate counter of `mask` width the TSC is measured against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
    pub mask: u64,
    pub scale: ReferenceScale,
}

impl Reference {
    /// Reference ticks in at least [`WINDOW_NS`].
    fn window_ticks(self) -> Result<u64, Error> {
        let ticks = match self.scale {
            ReferenceScale::Hertz(0) | ReferenceScale::PeriodFemtoseconds(0) => {
                return Err(Error::InvalidRate);
            }
            ReferenceScale::Hertz(hz) => {
                (u128::from(WINDOW_NS) * u128::from(hz)).div_ceil(1_000_000_000)
            }
            ReferenceScale::PeriodFemtoseconds(period) => {
                (u128::from(WINDOW_NS) * 1_000_000).div_ceil(u128::from(period))
            }
        };
        u64::try_from(ticks).map_err(|_| Error::Overflow)
    }
}

/// One window's rate bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measured {
    pub window: RateWindow,
}

impl Measured {
    /// The middle of the bounds.
    pub fn hz(self) -> u64 {
        let (low, high) = (self.window.minimum_hz(), self.window.maximum_hz());
        low + (high - low) / 2
    }
    /// The bounds' half-width, in parts per million of [`Self::hz`],
    /// rounded up.
    pub fn uncertainty_ppm(self) -> u64 {
        let half = u128::from(self.window.maximum_hz() - self.window.minimum_hz()).div_ceil(2);
        (half * PPM).div_ceil(u128::from(self.hz())) as u64
    }
}

/// Count reference ticks from a first sample until at least [`WINDOW_NS`]
/// have passed, summing each step between consecutive samples so that any
/// number of wraps is counted. A step of half the mask or more could hide
/// a wrap and is refused.
pub fn measure(reference: Reference, mut read: impl FnMut() -> Sample) -> Result<Measured, Error> {
    if !matches!(reference.mask, 0x00ff_ffff | 0xffff_ffff | u64::MAX) {
        return Err(Error::InvalidMask);
    }
    let target = reference.window_ticks()?;
    let mut read = || Ok::<_, Error>(read());
    let start = stable_sample(&mut read)?;
    let mut previous = start;
    let mut ticks = 0u64;
    for poll in 0..MAX_POLLS {
        let sample = stable_sample(&mut read)?;
        if sample.tsc_before < previous.tsc_after {
            return Err(Error::Backwards);
        }
        let step = sample.reference.wrapping_sub(previous.reference) & reference.mask;
        if step > reference.mask / 2 {
            return Err(Error::Disturbed);
        }
        ticks = ticks.checked_add(step).ok_or(Error::Overflow)?;
        if ticks == 0 && poll >= START_POLLS {
            return Err(Error::NoProgress);
        }
        previous = sample;
        if ticks >= target {
            let window = RateWindow::from_ticks(
                start,
                sample,
                ticks,
                reference.scale,
                super::measurement::MAX_READ_CYCLES,
            )?;
            return Ok(Measured { window });
        }
    }
    Err(Error::NoProgress)
}

/// Which window [`settle`] asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Window {
    /// The first reference.
    Primary,
    /// The second reference where one exists, else the first again.
    CrossCheck,
    /// The first reference again, when the two disagree.
    TieBreak,
}

/// The settled rate and how far it may be off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calibrated {
    pub hz: u64,
    /// The worst-case error of `hz` from the windows' brackets and their
    /// disagreement; the reference's own crystal error is not included.
    pub uncertainty_ppm: u64,
    /// How far the cross-check's rate was from the primary's.
    pub disagreement_ppm: u64,
    /// Whether the cross-check agreed, or a tie-break decided.
    pub agreed: bool,
}

fn ppm_between(a: u64, b: u64) -> u64 {
    (u128::from(a.abs_diff(b)) * PPM).div_ceil(u128::from(a.max(1))) as u64
}

/// Measure the primary and cross-check windows. When they agree within
/// their brackets and [`AGREEMENT_PPM`], their intersection's middle (or,
/// with disjoint brackets, the primary's) is the rate. Otherwise a third
/// window decides: the median of the three, uncertain by its distance to
/// the nearer of the other two.
pub fn settle(
    mut measure: impl FnMut(Window) -> Result<Measured, Error>,
) -> Result<Calibrated, Error> {
    let primary = measure(Window::Primary)?;
    let check = measure(Window::CrossCheck)?;
    let disagreement_ppm = ppm_between(primary.hz(), check.hz());
    let allowed = primary.uncertainty_ppm() + check.uncertainty_ppm() + AGREEMENT_PPM;
    if disagreement_ppm <= allowed {
        let settled = primary
            .window
            .intersect(check.window)
            .map_or(primary, |window| Measured { window });
        return Ok(Calibrated {
            hz: settled.hz(),
            uncertainty_ppm: settled.uncertainty_ppm().max(disagreement_ppm.div_ceil(2)),
            disagreement_ppm,
            agreed: true,
        });
    }
    let third = measure(Window::TieBreak)?;
    let mut rates = [primary.hz(), check.hz(), third.hz()];
    rates.sort_unstable();
    let [low, median, high] = rates;
    Ok(Calibrated {
        hz: median,
        // The median and the window nearest it agree; the third is the
        // outlier the tie-break overruled.
        uncertainty_ppm: ppm_between(median, low)
            .min(ppm_between(median, high))
            .max(primary.uncertainty_ppm()),
        disagreement_ppm,
        agreed: false,
    })
}

#[cfg(test)]
mod tests;
