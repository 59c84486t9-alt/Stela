//! Counter joins for one native controller clock.
use super::{Authority, Error, Image, Observation};
use alloc::vec::Vec;

const SYSTEM_HZ: u128 = 24_000_000;

/// Complete native-cycle phase at a system counter instant. Captured
/// and explicitly initialized Stela phase are different permissions. Unknown
/// phase never acquires an implicit zero fractional cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Unknown,
    Captured {
        at: u64,
        cycles: u128,
        fraction: u32,
    },
    DeclaredStela {
        at: u64,
        cycles: u128,
        fraction: u32,
    },
}
/// Read-only observations, never a replacement/restore operation.
pub struct Snapshot {
    pub input_authority: Authority,
    pub inputs: Vec<Observation>,
    pub initial_phase: Phase,
    pub frequency: u32,
    pub at: u64,
    pub cycles: u128,
    pub fraction: u32,
    pub fault: Option<Error>,
}
pub(in crate::platform::apple::power::t6000) struct Clock {
    image: Image,
    initial_phase: Phase,
    frequency: u32,
    at: u64,
    cycles: u128,
    fraction: u32,
    fault: Option<Error>,
}
impl Clock {
    pub(in crate::platform::apple::power::t6000) fn new(
        image: Image,
        phase: Phase,
    ) -> Result<Self, Error> {
        let (at, cycles, fraction) = match phase {
            Phase::Unknown => return Err(Error::UnknownPhase),
            Phase::Captured {
                at,
                cycles,
                fraction,
            }
            | Phase::DeclaredStela {
                at,
                cycles,
                fraction,
            } => (at, cycles, fraction),
        };
        if u128::from(fraction) >= SYSTEM_HZ {
            return Err(Error::InvalidPhase);
        }
        let frequency = image.execution_frequency()?;
        Ok(Self {
            image,
            initial_phase: phase,
            frequency,
            at,
            cycles,
            fraction,
            fault: None,
        })
    }
    pub(in crate::platform::apple::power::t6000) fn observe(
        &mut self,
        now: u64,
        running: bool,
    ) -> Result<u128, Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        let result = (|| {
            let elapsed = now.checked_sub(self.at).ok_or(Error::Regressed)?;
            let scaled = u128::from(self.fraction)
                + if running {
                    u128::from(elapsed) * u128::from(self.frequency)
                } else {
                    0
                };
            let cycles = self
                .cycles
                .checked_add(scaled / SYSTEM_HZ)
                .ok_or(Error::Exhausted)?;
            Ok((cycles, (scaled % SYSTEM_HZ) as u32))
        })();
        match result {
            Ok((cycles, fraction)) => {
                self.at = now;
                self.cycles = cycles;
                self.fraction = fraction;
                Ok(cycles)
            }
            Err(error) => {
                self.fault = Some(error);
                Err(error)
            }
        }
    }
    pub(in crate::platform::apple::power::t6000) fn snapshot(&self) -> Snapshot {
        Snapshot {
            input_authority: self.image.authority(),
            inputs: self.image.observations().to_vec(),
            initial_phase: self.initial_phase,
            frequency: self.frequency,
            at: self.at,
            cycles: self.cycles,
            fraction: self.fraction,
            fault: self.fault,
        }
    }
    pub(in crate::platform::apple::power::t6000) fn cycles(&self) -> Result<u128, Error> {
        self.fault.map_or(Ok(self.cycles), Err)
    }
    pub(in crate::platform::apple::power::t6000) fn deadline(
        &self,
        remaining: u32,
    ) -> Result<Option<u64>, Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if remaining == 0 {
            return Ok(Some(self.at));
        }
        if self.frequency == 0 {
            return Ok(None);
        }
        let scaled = (u128::from(remaining) * SYSTEM_HZ).saturating_sub(u128::from(self.fraction));
        let ticks = scaled.div_ceil(u128::from(self.frequency));
        self.at
            .checked_add(u64::try_from(ticks).map_err(|_| Error::Exhausted)?)
            .map(Some)
            .ok_or(Error::Exhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Image {
        // Explicit test resource: source PLL0 bypass is32768Hz, not24MHz.
        super::super::tests::image(1 << 31, (1 << 31) | (1 << 27), 0, 0, 0)
    }
    #[test]
    fn real_counter_fraction_retention_pause_and_repeated_samples_do_not_create_cycles() {
        let mut clock = Clock::new(
            input(),
            Phase::DeclaredStela {
                at: 100,
                cycles: 9,
                fraction: 0,
            },
        )
        .unwrap();
        assert_eq!(clock.observe(101, true), Ok(9));
        assert_eq!(clock.snapshot().fraction, 32768);
        assert_eq!(clock.deadline(1), Ok(Some(833)));
        assert_eq!(clock.observe(101, true), Ok(9));
        assert_eq!(clock.observe(1101, false), Ok(9));
        assert_eq!(clock.snapshot().fraction, 32768);
        assert_eq!(clock.deadline(1), Ok(Some(1833)));
        assert_eq!(clock.observe(24_001_100, true), Ok(9 + 32768));
        assert_eq!(clock.snapshot().fraction, 0);
    }
    #[test]
    fn unknown_phase_regression_and_exhaustion_never_reset_a_counter_or_retry_a_fault() {
        assert!(matches!(
            Clock::new(input(), Phase::Unknown),
            Err(Error::UnknownPhase)
        ));
        assert!(matches!(
            Clock::new(
                input(),
                Phase::Captured {
                    at: 0,
                    cycles: 0,
                    fraction: 24_000_000
                }
            ),
            Err(Error::InvalidPhase)
        ));
        let mut clock = Clock::new(
            input(),
            Phase::Captured {
                at: 100,
                cycles: 9,
                fraction: 7,
            },
        )
        .unwrap();
        assert_eq!(clock.observe(99, true), Err(Error::Regressed));
        assert_eq!(clock.observe(101, true), Err(Error::Regressed));
        assert_eq!(
            (
                clock.snapshot().at,
                clock.snapshot().cycles,
                clock.snapshot().fraction
            ),
            (100, 9, 7)
        );
        let mut clock = Clock::new(
            input(),
            Phase::DeclaredStela {
                at: 0,
                cycles: u128::MAX,
                fraction: 0,
            },
        )
        .unwrap();
        assert_eq!(clock.observe(24_000_000, true), Err(Error::Exhausted));
        assert_eq!(clock.snapshot().cycles, u128::MAX);
    }
    #[test]
    fn source_computed_stopped_clock_has_no_timer_deadline_or_fabricated_cycles() {
        let input = super::super::tests::image(0, 0, 0, 0, 0);
        let mut clock = Clock::new(
            input,
            Phase::DeclaredStela {
                at: 0,
                cycles: 0,
                fraction: 0,
            },
        )
        .unwrap();
        assert_eq!(clock.observe(24_000_000, true), Ok(0));
        assert_eq!(clock.deadline(1), Ok(None));
        assert_eq!(clock.deadline(0), Ok(Some(24_000_000)));
        for (input, error) in [
            (
                super::super::tests::image((1 << 31) | (5 << 24), 0, 0, 0, 0),
                Error::UnqualifiedRoute,
            ),
            (
                super::super::tests::image(1 << 31, 1 << 31, 0, 0, 0),
                Error::UnqualifiedRate,
            ),
            (
                super::super::tests::image(
                    (1 << 31) | (1 << 24),
                    1 << 31,
                    1 << 31,
                    (1 << 20) | 16383,
                    7,
                ),
                Error::UnqualifiedRate,
            ),
        ] {
            assert!(input.frequency().is_ok()); // preserve the native query outcome
            assert!(
                matches!(Clock::new(input,Phase::DeclaredStela{at:0,cycles:0,fraction:0}),Err(actual) if actual==error)
            );
        }
    }
}
