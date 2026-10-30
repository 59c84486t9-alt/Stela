//! CPM throttler configuration (`enableThrottler`, kernel file
//! 0x2f9ea14/0x2fa4d90) at DT reg[7]/reg[16]. Full64 RMWs change bit63
//! at +250/+270/+8400/+8408 and P bit0 at +8b30. Stela hands off disabled
//! zero configuration; conditional iBoot threshold RMWs are not reproduced.
//! No physical overload or thermal cause is modeled, so no active throttle
//! or counter event is invented. Configuration keeps every written field.
//!
//! `restoreHW` (0x2f9cb9c, stores 0x2f9ce74..0x2f9ced8) writes full64 1
//! at +40f8. The restore request completes immediately against the already
//! configuration. Its completion is recorded; electrical effects and
//! command readback are not proved. Other values and reads of it refuse.
use super::regfile::Held;
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use stela_soc_data::cpm::RESTORE;
#[cfg(test)]
use stela_soc_data::cpm::{P_THROTTLER, THROTTLERS};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};
const NAME: &str = "cpm-power";
#[derive(Debug, Clone)]
pub struct Cpm {
    performance: bool,
    values: Held,
    restored: bool,
}
impl Cpm {
    pub fn new(performance: bool) -> Self {
        Self {
            performance,
            values: Held::default(),
            restored: false,
        }
    }
    pub fn offsets(&self) -> Vec<u64> {
        stela_soc_data::cpm::offsets(self.performance)
    }
    #[cfg(test)]
    pub fn restored(&self) -> bool {
        self.restored
    }
    fn check(&self, o: u64, w: Width) -> Result<()> {
        if w != Width::Double || !self.offsets().contains(&o) {
            Err(refuse!(
                "CPM register or width has no described power-control contract"
            ))
        } else {
            Ok(())
        }
    }
}
impl MmioDevice for Cpm {
    fn advance_policy(&self) -> super::bus::AdvancePolicy {
        super::bus::AdvancePolicy::Passive
    }
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, o: u64, w: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |r: Refusal| refuse(NAME, o, w, Direction::Read, r);
        self.check(o, w).map_err(fail)?;
        if o == RESTORE {
            return Err(fail(refuse!(
                "CPM restore command readback is not established"
            )));
        }
        Ok(self.values.get(o))
    }
    fn write(&mut self, o: u64, w: Width, v: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
        let fail = |r: Refusal| refuse(NAME, o, w, Direction::Write, r);
        self.check(o, w).map_err(fail)?;
        if o == RESTORE {
            if v != 1 {
                return Err(fail(refuse!(
                    "CPM restore accepts only the documented full64 command1"
                )));
            }
            self.restored = true;
        } else {
            self.values.set(o, v);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    #[test]
    fn throttlers_keep_configuration_and_restore_does_not_discard_it() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        for performance in [false, true] {
            let mut c = Cpm::new(performance);
            assert!(!c.restored());
            for o in c.offsets().into_iter().filter(|&o| o != RESTORE) {
                assert_eq!(c.read(o, Width::Double, &mut a), Ok(0));
                c.write(o, Width::Double, 0x8000_1234_5678_0001, &mut a)
                    .unwrap();
                assert_eq!(c.read(o, Width::Double, &mut a), Ok(0x8000_1234_5678_0001));
            }
            c.write(RESTORE, Width::Double, 1, &mut a).unwrap();
            assert!(c.restored());
            assert_eq!(
                c.read(THROTTLERS[0], Width::Double, &mut a),
                Ok(0x8000_1234_5678_0001)
            );
            assert!(c.read(RESTORE, Width::Double, &mut a).is_err());
            assert!(c.write(RESTORE, Width::Double, 2, &mut a).is_err());
            assert!(c.write(0x254, Width::Word, 0, &mut a).is_err());
            if !performance {
                assert!(c.read(P_THROTTLER, Width::Double, &mut a).is_err());
            }
        }
    }
}
