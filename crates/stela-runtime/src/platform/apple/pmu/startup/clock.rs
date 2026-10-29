//! Actual private native-PMIC execution time, not the shared RTC oscillator.
use crate::platform::apple::counter::FREQUENCY_HZ;

use stela_soc_data::pmu::PmicEpoch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Time {
    counter: u64,
    cycles: u64,
    fraction: u64,
}

/// Deliberately non-Clone and retained by the actual PMIC control/SRAM owner.
pub(super) struct Clock {
    time: Time,
    hz: u64,
}
impl Clock {
    pub fn new(epoch: PmicEpoch) -> Result<Self, &'static str> {
        epoch.validate()?;
        Ok(Self {
            time: Time {
                counter: epoch.counter,
                cycles: epoch.cycles,
                fraction: 0,
            },
            hz: epoch.hz,
        })
    }
    fn at(&self, now: u64) -> Result<Time, &'static str> {
        let delta = now
            .checked_sub(self.time.counter)
            .ok_or("native PMIC execution counter went backwards")?;
        let numerator = u128::from(delta)
            .checked_mul(u128::from(self.hz))
            .and_then(|value| value.checked_add(u128::from(self.time.fraction)))
            .ok_or("native PMIC oscillator conversion overflow")?;
        let elapsed = u64::try_from(numerator / u128::from(FREQUENCY_HZ))
            .map_err(|_| "native PMIC elapsed cycles exceed its retained counter")?;
        Ok(Time {
            counter: now,
            cycles: self
                .time
                .cycles
                .checked_add(elapsed)
                .ok_or("native PMIC execution counter overflow")?,
            fraction: (numerator % u128::from(FREQUENCY_HZ)) as u64,
        })
    }
    #[cfg(test)]
    pub(super) fn state(&self) -> (u64, u64, u64) {
        (self.time.counter, self.time.cycles, self.time.fraction)
    }
    pub fn check(&self, now: u64) -> Result<(), &'static str> {
        self.at(now).map(|_| ())
    }
    pub fn prepare(&mut self, now: u64) -> Result<Advance<'_>, &'static str> {
        let next = self.at(now)?;
        Ok(Advance { owner: self, next })
    }

    /// The first actual system-counter value at or after the target native
    /// cycle, preserving the retained fractional conversion. Due targets keep
    /// the current counter; no wrapping, zero fallback or truncated deadline.
    pub fn deadline(&self, now: u64, cycles: u64) -> Result<u64, &'static str> {
        let time = self.at(now)?;
        time.cycles
            .checked_add(cycles)
            .ok_or("native PMIC timer cycle deadline overflow")?;
        if cycles == 0 {
            return Ok(time.counter);
        }
        let numerator = u128::from(cycles) * u128::from(FREQUENCY_HZ) - u128::from(time.fraction);
        let delta = numerator.div_ceil(u128::from(self.hz));
        let deadline = time
            .counter
            .checked_add(u64::try_from(delta).map_err(|_| "native PMIC timer deadline overflow")?)
            .ok_or("native PMIC timer deadline exceeds the system counter")?;
        // A single system-counter step can advance multiple native cycles.
        // The target may fit while the first reachable time overshoots the
        // retained cycle horizon; do not publish that unusable deadline.
        self.at(deadline)?;
        Ok(deadline)
    }
}

/// A private consuming preparation that exclusively borrows the actual owner.
/// It cannot acknowledge another clock, outlive its PMIC or survive intervening
/// mutation/redispatch. Dropping it has no visible effect.
pub(in super::super) struct Advance<'a> {
    owner: &'a mut Clock,
    next: Time,
}
impl Advance<'_> {
    pub(in super::super) fn commit(self) {
        self.owner.time = self.next;
    }
}

/// Exact original Maverick image1 1ac0..1b2a reload conversion. These are
/// source register fields, not a measured physical oscillator rate. The native
/// timer consumes the caller's explicitly declared reference-clock cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Reload {
    pub field: u16,
    pub shift: u8,
}
impl Reload {
    pub fn from_request(request: u32) -> Self {
        let shift = if request >= 0x001f_ffe1 { 7 } else { 11 };
        let count = request.wrapping_shl(u32::from(shift)).wrapping_add(0x8000) >> 16;
        Self {
            field: (count as u16).wrapping_sub(1),
            shift,
        }
    }
    /// A declared native 16-bit countdown uses reload+1 cycles in its
    /// explicitly supplied timer clock. Source shifts alone do not prove a
    /// physical prescaler or select an Apple oscillator frequency.
    pub fn countdown_cycles(self) -> u64 {
        u64::from(self.field) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_publications_preserve_fraction_and_match_one_actual_owner_advance() {
        for hz in [1, 32768, 1_000_000, FREQUENCY_HZ + 1, u64::MAX] {
            let epoch = PmicEpoch {
                counter: 17,
                cycles: 0,
                hz,
            };
            let mut split = Clock::new(epoch).unwrap();
            let mut whole = Clock::new(epoch).unwrap();
            for counter in 18..=1000 {
                split.prepare(counter).unwrap().commit();
            }
            whole.prepare(1000).unwrap().commit();
            assert_eq!(split.time, whole.time);
            assert_eq!(
                split.time.fraction,
                ((983u128 * u128::from(hz)) % u128::from(FREQUENCY_HZ)) as u64
            );
        }
    }
    #[test]
    fn backwards_overflow_and_abandoned_preparations_never_mutate_the_owner() {
        assert!(
            Clock::new(PmicEpoch {
                counter: 0,
                cycles: 0,
                hz: 0
            })
            .is_err()
        );
        let mut owner = Clock::new(PmicEpoch {
            counter: 50,
            cycles: u64::MAX,
            hz: FREQUENCY_HZ,
        })
        .unwrap();
        let before = owner.time;
        assert!(owner.prepare(49).is_err());
        assert!(owner.prepare(51).is_err());
        assert!(owner.deadline(owner.time.counter, 1).is_err());
        assert_eq!(owner.time, before);
        let mut owner = Clock::new(PmicEpoch {
            counter: 0,
            cycles: 7,
            hz: 1,
        })
        .unwrap();
        let before = owner.time;
        {
            let _abandoned = owner.prepare(1000).unwrap();
        }
        assert_eq!(owner.time, before);
        owner.prepare(1000).unwrap().commit();
        assert_eq!(owner.time.cycles, 7);
        assert_ne!(owner.time.fraction, 0);
    }
    #[test]
    fn deadlines_are_first_reachable_counter_and_never_wrap_or_truncate() {
        for hz in [1, 32768, 1_000_000, FREQUENCY_HZ, 2 * FREQUENCY_HZ + 1] {
            let mut owner = Clock::new(PmicEpoch {
                counter: 10,
                cycles: 42,
                hz,
            })
            .unwrap();
            owner.prepare(13).unwrap().commit();
            for cycles in [0, 1, 17, 3125, 100000] {
                let deadline = owner.deadline(owner.time.counter, cycles).unwrap();
                let target = owner.time.cycles + cycles;
                assert!(owner.at(deadline).unwrap().cycles >= target);
                if deadline > owner.time.counter {
                    assert!(owner.at(deadline - 1).unwrap().cycles < target);
                }
            }
        }
        let owner = Clock::new(PmicEpoch {
            counter: u64::MAX,
            cycles: 0,
            hz: 1,
        })
        .unwrap();
        assert_eq!(owner.deadline(owner.time.counter, 0), Ok(u64::MAX));
        assert!(owner.deadline(owner.time.counter, 1).is_err());
        let owner = Clock::new(PmicEpoch {
            counter: 0,
            cycles: u64::MAX - 1,
            hz: FREQUENCY_HZ * 2,
        })
        .unwrap();
        assert!(owner.deadline(0, 1).is_err()); // target fits, reachable time does not
    }
    #[test]
    fn source_reload_boundaries_preserve_thumb_wrapping_and_full_16_bit_period() {
        let ordinary = Reload::from_request(100000);
        assert_eq!(
            ordinary,
            Reload {
                field: 3124,
                shift: 11
            }
        );
        assert_eq!(ordinary.countdown_cycles(), 3125);
        assert_eq!(Reload::from_request(0).field, u16::MAX);
        assert_eq!(Reload::from_request(0).countdown_cycles(), 65536);
        assert_eq!(Reload::from_request(0x1fffe0).shift, 11);
        assert_eq!(Reload::from_request(0x1fffe1).shift, 7);
        assert_eq!(Reload::from_request(0x1fffe0).field, 65534);
        assert_eq!(Reload::from_request(0x1fffe1).field, 4095);
        // These are exact source arithmetic fields, not a saturation/rounding
        // policy inferred from the generation name or nominal period.
        assert_eq!(Reload::from_request(u32::MAX).field, u16::MAX);
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_CRAM_J314S_LLB"]
    fn original_reload_branch_fields_and_first_arm_have_immutable_source_identity() {
        let llb = std::fs::read(std::env::var("STELA_TEST_CRAM_J314S_LLB").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&llb),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        for (range, hash) in [
            (
                0x1fb548..0x1fb5e0,
                "999a6fc9449d87a1ba01bb70d2295ad7c4df90712752decbe20e5b67e79b755e",
            ),
            (
                0x1fb5e0..0x1fb690,
                "26e85202f37ae9f96105e849cd1044210d17abe89d8def27a9a74dda1f66c0af",
            ),
            (
                0x1fa32e..0x1fa338,
                "d61b611fa1612d8d7cc4b910144e6904455b8e322ab63a73970971a8dd6399f9",
            ),
            (
                0x1fb2e8..0x1fb334,
                "cc9f198e19cd463c0697009f601f80ff9048b0c9c08002a36cd79fc673d9fc8f",
            ),
        ] {
            assert_eq!(stela_formats::sha256(&llb[range]), hash);
        }
        let image = &llb[0x1f9b20..0x1fbd90];
        assert_eq!(
            u32::from_le_bytes(image[0x1b5c..0x1b60].try_into().unwrap()),
            0x1fffe1
        );
        assert_eq!(&image[0x1ace..0x1ad4], &[7, 0x20, 0, 0xe0, 11, 0x20]);
        assert_eq!(
            u32::from_le_bytes(image[0x8b4..0x8b8].try_into().unwrap()),
            100000
        );
        assert_eq!(
            u32::from_le_bytes(image[0x1b68..0x1b6c].try_into().unwrap()),
            0x5aa50001
        );
    }
}
