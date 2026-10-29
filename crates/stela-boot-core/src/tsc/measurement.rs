// SPDX-License-Identifier: GPL-2.0-only
//! Bounded calibration arithmetic; callbacks/model input confer no hardware
//! access, continuity, source identity or native clock admission. The caller
//! keeps the ordered CPU and full64 HPET/control/resource owners.
use super::{Error, RateWindow, ReferenceScale, Sample};
const WINDOWS: usize = 5;
const RETRIES: usize = 5;
const MAX_POLLS: usize = 65_536;
// Pinned Linux tsc.c tsc_read_refs default disturbance threshold. No bootstrap
// or nominal frequency is required to decide whether a bracket is disturbed.
const MAX_READ_CYCLES: u64 = 0x20000;
const WINDOW_FS: u64 = 1_000_000_000_000; // one millisecond, active spin only
#[derive(Clone, Copy, Debug)]
pub struct WindowEvidence {
    pub start: Sample,
    pub end: Sample,
    pub rate: RateWindow,
}
#[derive(Debug)]
pub struct Calibration {
    windows: [WindowEvidence; WINDOWS],
    intersection: RateWindow,
}
impl Calibration {
    pub fn windows(&self) -> &[WindowEvidence; WINDOWS] {
        &self.windows
    }
    pub fn rate_window(&self) -> RateWindow {
        self.intersection
    }
}
fn stable_sample<E: From<Error>>(
    read: &mut impl FnMut() -> Result<Sample, E>,
) -> Result<Sample, E> {
    for _ in 0..RETRIES {
        let sample = read()?;
        let width = sample
            .tsc_after
            .checked_sub(sample.tsc_before)
            .ok_or(Error::Backwards)?;
        if width < MAX_READ_CYCLES {
            return Ok(sample);
        }
    }
    Err(Error::Disturbed.into())
}
/// Collect five independently bounded active-spin windows and preserve their
/// exact uncertainty intersection. No timestamp-derived deadline is trusted.
/// Every read bracket has at most5 attempts; every window at most65536 polls.
/// Stopped references/TSCs, changed rates and backwards data explicitly refuse.
/// The full64 reference must not wrap/reset or change period/control
/// during this bounded operation. This function does not check that promise.
pub fn calibrate_hpet<E: From<Error>>(
    period_fs: u32,
    mut read: impl FnMut() -> Result<Sample, E>,
) -> Result<Calibration, E> {
    if !(100_000..=100_000_000).contains(&period_fs) {
        return Err(Error::InvalidRate.into());
    }
    let target = WINDOW_FS.div_ceil(u64::from(period_fs));
    let empty = WindowEvidence {
        start: Sample {
            tsc_before: 0,
            reference: 0,
            tsc_after: 0,
        },
        end: Sample {
            tsc_before: 0,
            reference: 0,
            tsc_after: 0,
        },
        rate: RateWindow::from_bounds(1, 1)?,
    };
    let mut windows = [empty; WINDOWS];
    let mut intersection = None;
    for window in &mut windows {
        let start = stable_sample(&mut read)?;
        let mut found = None;
        for _ in 0..MAX_POLLS {
            let end = stable_sample(&mut read)?;
            let delta = end
                .reference
                .checked_sub(start.reference)
                .ok_or(Error::Backwards)?;
            if end.tsc_before < start.tsc_after {
                return Err(Error::Backwards.into());
            }
            if delta >= target {
                let rate = RateWindow::from_samples(
                    start,
                    end,
                    u64::MAX,
                    ReferenceScale::PeriodFemtoseconds(period_fs),
                    MAX_READ_CYCLES,
                )?;
                found = Some(WindowEvidence { start, end, rate });
                break;
            }
        }
        let evidence = found.ok_or(Error::NoProgress)?;
        intersection = Some(match intersection {
            None => evidence.rate,
            Some(previous) => RateWindow::intersect(previous, evidence.rate)?,
        });
        *window = evidence;
    }
    Ok(Calibration {
        windows,
        intersection: intersection.ok_or(Error::NoProgress)?,
    })
}
#[cfg(test)]
mod tests;
