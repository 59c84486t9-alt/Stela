//! CPM throttler configuration (`enableThrottler`, kernel file
//! 0x2f9ea14/0x2fa4d90) at DT reg[7]/reg[16]. Full64 RMWs change bit63
//! at +250/+270/+8400/+8408 and P bit0 at +8b30. Stela hands off disabled
//! zero configuration; conditional iBoot threshold RMWs are not reproduced.
//! No physical overload or thermal cause is modeled, so no active throttle
//! or counter event is invented. Configuration keeps every written field.
//!
//! `restoreHW` (0x2f9cb9c, stores 0x2f9ce74..0x2f9ced8) and CLPC's
//! `ClusterPerfSampler::enableCluster` (0xfffffe0009f407a4) write full64 1 at
//! +40f8, the counter block's enable. Its completion is recorded; effects and
//! readback are not proved. Other values and reads of it refuse.
//!
//! `T8112CLPC::clusterPerfSamplerConfig` (0xfffffe0009f78be4) places eight
//! slots at +4000, 0x10 apart, each a count and at +8 its event selector;
//! `enableCluster` selects seven and `sample` reads them. And
//! `uncorePerfSamplerConfig` (0xfffffe0009f78c80) places the uncore counters:
//! eight pairs at +4100, 0x10 apart, and +4248, 8 apart, read by
//! `UncorePerfSampler::sampleCluster` (0xfffffe0009f41ca0), and ten control
//! words at +4180 that `enableCluster` (0xfffffe0009f41bf0) reads and writes,
//! its low byte of the first enabling the counters. These counters' events
//! are not documented and an emulated die has no event source, so like the
//! core counters ([`crate::core_counters`]) they hold what software writes,
//! 0 from reset (inference): no activity is invented, and CLPC sees none.
use crate::Result;
use crate::passive::Words;
use alloc::sync::Arc;
use alloc::vec::Vec;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use stela_soc_data::cpm::COUNTER_ENABLE;
#[cfg(test)]
use stela_soc_data::cpm::{P_THROTTLER, THROTTLERS};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};
const NAME: &str = "cpm-power";
#[derive(Debug)]
pub struct Cpm {
    performance: bool,
    /// The described offsets, sorted: CLPC's samplers read the counters
    /// thousands of times a second, and a check must not build the list.
    described: Vec<u64>,
    /// Each described word's value, by its index in `described`: PEs read
    /// them without the devices' lock ([`crate::passive`]).
    values: Arc<Words>,
    counting: bool,
}
impl Cpm {
    pub fn new(performance: bool) -> Self {
        let mut described = stela_soc_data::cpm::offsets(performance);
        described.sort_unstable();
        Self {
            performance,
            values: Words::new(described.len()),
            described,
            counting: false,
        }
    }
    /// The words a read needs no lock for, each as its offset, the cells
    /// and its index: every described word but the counter enable, whose
    /// read refuses.
    pub fn passive_words(&self) -> impl Iterator<Item = (u64, &Arc<Words>, usize)> {
        self.described
            .iter()
            .enumerate()
            .filter(|&(_, &offset)| offset != COUNTER_ENABLE)
            .map(|(index, &offset)| (offset, &self.values, index))
    }
    fn index(&self, o: u64) -> usize {
        self.described
            .binary_search(&o)
            .expect("a checked CPM offset is described")
    }
    pub fn offsets(&self) -> Vec<u64> {
        stela_soc_data::cpm::offsets(self.performance)
    }
    #[cfg(test)]
    pub fn counting(&self) -> bool {
        self.counting
    }
    fn check(&self, o: u64, w: Width) -> Result<()> {
        if w != Width::Double || self.described.binary_search(&o).is_err() {
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
        if o == COUNTER_ENABLE {
            return Err(fail(refuse!(
                "CPM counter enable readback is not established"
            )));
        }
        Ok(self.values.get(self.index(o)))
    }
    fn write(&mut self, o: u64, w: Width, v: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
        let fail = |r: Refusal| refuse(NAME, o, w, Direction::Write, r);
        self.check(o, w).map_err(fail)?;
        if o == COUNTER_ENABLE {
            if v != 1 {
                return Err(fail(refuse!(
                    "CPM counter enable accepts only the documented full64 1"
                )));
            }
            self.counting = true;
        } else {
            self.values.set(self.index(o), v);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    #[test]
    fn registers_keep_configuration_and_the_counter_enable_does_not_discard_it() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        for performance in [false, true] {
            let mut c = Cpm::new(performance);
            assert!(!c.counting());
            for o in c.offsets().into_iter().filter(|&o| o != COUNTER_ENABLE) {
                assert_eq!(c.read(o, Width::Double, &mut a), Ok(0));
                c.write(o, Width::Double, 0x8000_1234_5678_0001, &mut a)
                    .unwrap();
                assert_eq!(c.read(o, Width::Double, &mut a), Ok(0x8000_1234_5678_0001));
            }
            c.write(COUNTER_ENABLE, Width::Double, 1, &mut a).unwrap();
            assert!(c.counting());
            assert_eq!(
                c.read(THROTTLERS[0], Width::Double, &mut a),
                Ok(0x8000_1234_5678_0001)
            );
            assert!(c.read(COUNTER_ENABLE, Width::Double, &mut a).is_err());
            assert!(c.write(COUNTER_ENABLE, Width::Double, 2, &mut a).is_err());
            assert!(c.write(0x254, Width::Word, 0, &mut a).is_err());
            if !performance {
                assert!(c.read(P_THROTTLER, Width::Double, &mut a).is_err());
            }
        }
    }

    #[test]
    fn the_described_offsets_are_exactly_the_placed_ones() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        for performance in [false, true] {
            let mut c = Cpm::new(performance);
            let offsets = c.offsets();
            // Every word from 0 to past the last described one: described
            // words answer, every other offset refuses.
            for o in (0..0x9000).step_by(8) {
                let read = c.read(o, Width::Double, &mut a);
                assert_eq!(
                    read.is_ok(),
                    offsets.contains(&o) && o != COUNTER_ENABLE,
                    "{o:#x}"
                );
            }
            assert!(c.read(0x4004, Width::Double, &mut a).is_err());
        }
    }

    /// Host cost of a CLPC sampler read: `cargo test -p stela-soc --lib
    /// cpm::tests::read_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual: opt-in"]
    fn read_cost() {
        extern crate std;
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut c = Cpm::new(false);
        const READS: u64 = 1_000_000;
        let start = std::time::Instant::now();
        let mut sum = 0u64;
        for n in 0..READS {
            sum = sum.wrapping_add(
                c.read(0x4000 + (n % 8) * 0x10, Width::Double, &mut a)
                    .unwrap(),
            );
        }
        let ns = start.elapsed().as_nanos() as u64 / READS;
        std::println!("cpm read: {ns} ns each ({sum})");
    }

    #[test]
    fn clpcs_cluster_and_uncore_counters_are_placed_and_idle() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut c = Cpm::new(false);
        // The first of seven selectors, the last count and the uncore's
        // first control word, its last, and a slot's two banks.
        for o in [0x4008, 0x4060, 0x4180, 0x41c8, 0x4170, 0x4280] {
            assert_eq!(c.read(o, Width::Double, &mut a), Ok(0));
        }
        c.write(0x4008, Width::Double, 0x800f, &mut a).unwrap();
        assert_eq!(c.read(0x4008, Width::Double, &mut a), Ok(0x800f));
        assert!(c.read(0x4288, Width::Double, &mut a).is_err());
    }
}
