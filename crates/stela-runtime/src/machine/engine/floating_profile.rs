//! Opt-in sampling of serviced FP operations, never native-success counts.
mod classes;
mod observations;
mod operands;

use super::{Devices, Host, Machine};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use serde::Serialize;
use stela_compiler::{
    GuestState,
    aarch64::{FloatingPointOperation, floating::UnsupportedControl},
};

const STRATUM: u32 = 4096;
// Earlier real-app attribution contains over 2,000 distinct service words.
// Keep useful detail across workloads while retaining a fixed per-engine bound.
const ROW_LIMIT: usize = 4096;
const FAMILY_COUNT: usize = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum Family {
    Binary,
    Widening,
    BFloat16,
    Complex,
    Fused,
    Conversion,
    Comparison,
    ExtremaScale,
    MinMax,
    Rounding,
    SquareRoot,
    Estimate,
    Refinement,
}

impl Family {
    fn of(operation: &FloatingPointOperation) -> Self {
        match operation {
            FloatingPointOperation::Binary(_) => Self::Binary,
            FloatingPointOperation::Widening(_) => Self::Widening,
            FloatingPointOperation::BFloat16(_) => Self::BFloat16,
            FloatingPointOperation::Complex(_) => Self::Complex,
            FloatingPointOperation::Fused(_) => Self::Fused,
            FloatingPointOperation::Conversion(_) => Self::Conversion,
            FloatingPointOperation::Comparison(_) => Self::Comparison,
            FloatingPointOperation::ExtremaScale(_) => Self::ExtremaScale,
            FloatingPointOperation::MinMax(_) => Self::MinMax,
            FloatingPointOperation::Rounding(_) => Self::Rounding,
            FloatingPointOperation::SquareRoot(_) => Self::SquareRoot,
            FloatingPointOperation::Estimate(_) => Self::Estimate,
            FloatingPointOperation::Refinement(_) => Self::Refinement,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Key {
    word: u32,
    family: Family,
    fpcr_before: u32,
    fpcr_after: u32,
    fpsr_before: u32,
    fpsr_after: u32,
    refused_enabled_exceptions: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct Row {
    #[serde(flatten)]
    key: Key,
    samples: u64,
}

/// Cumulative within one engine epoch. FPSR differences reveal newly observable
/// sticky transitions only; already-set bits hide subsequent fresh exceptions.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Snapshot {
    algorithm: &'static str,
    seed: u64,
    stratum_events: u32,
    serviced_population: u64,
    population_exact: bool,
    population_when_inexact: &'static str,
    samples: u64,
    family_samples: [u64; FAMILY_COUNT],
    family_order: [Family; FAMILY_COUNT],
    detail_dropped: u64,
    detail_row_limit: usize,
    counter_saturated: bool,
    operand_classification: bool,
    native_success_covered: bool,
    rows: Vec<Row>,
    typed: observations::Snapshot,
}

#[cfg(test)]
impl Snapshot {
    pub(crate) fn maximum_test_fixture() -> Self {
        let mut sampler = Sampler::new(u64::MAX);
        sampler.scheduled = u64::MAX;
        sampler.samples = u64::MAX;
        sampler.families.fill(u64::MAX);
        sampler.dropped = u64::MAX;
        sampler.saturated = true;
        sampler.observations = observations::Observations::maximum_test_fixture();
        for word in (u32::MAX - ROW_LIMIT as u32)..u32::MAX {
            sampler.rows.insert(
                Key {
                    word,
                    family: Family::ExtremaScale,
                    fpcr_before: u32::MAX,
                    fpcr_after: u32::MAX,
                    fpsr_before: u32::MAX,
                    fpsr_after: u32::MAX,
                    refused_enabled_exceptions: Some(u32::MAX),
                },
                u64::MAX,
            );
        }
        sampler.snapshot()
    }
}

pub(super) struct Sampler {
    seed: u64,
    random: u64,
    slot: u32,
    remaining: u32,
    scheduled: u64,
    population_exact: bool,
    samples: u64,
    families: [u64; FAMILY_COUNT],
    dropped: u64,
    saturated: bool,
    rows: BTreeMap<Key, u64>,
    observations: observations::Observations,
}

fn increment(value: &mut u64, saturated: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *saturated = true;
    }
}

fn sample_gap(previous: u32, next: u32) -> u32 {
    STRATUM + next - previous
}

impl Sampler {
    fn new(seed: u64) -> Self {
        let mut sampler = Self {
            seed,
            random: seed,
            slot: 0,
            remaining: 0,
            scheduled: 0,
            population_exact: true,
            samples: 0,
            families: [0; FAMILY_COUNT],
            dropped: 0,
            saturated: false,
            rows: BTreeMap::new(),
            observations: observations::Observations::new(seed),
        };
        sampler.slot = sampler.next_slot();
        sampler.remaining = sampler.slot + 1;
        sampler.scheduled = u64::from(sampler.remaining);
        sampler
    }

    // SplitMix64; a diagnostic PRNG, independent of guest/security entropy.
    fn next_slot(&mut self) -> u32 {
        self.random = self.random.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.random;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        ((value ^ (value >> 31)) >> (u64::BITS - STRATUM.ilog2())) as u32
    }

    #[inline]
    pub(super) fn tick(&mut self) -> bool {
        self.remaining -= 1;
        if self.remaining != 0 {
            return false;
        }
        self.schedule_next();
        true
    }

    #[cold]
    #[inline(never)]
    fn schedule_next(&mut self) {
        let next = self.next_slot();
        self.remaining = sample_gap(self.slot, next);
        self.slot = next;
        if let Some(scheduled) = self.scheduled.checked_add(u64::from(self.remaining)) {
            self.scheduled = scheduled;
        } else {
            self.scheduled = u64::MAX;
            self.population_exact = false;
            self.saturated = true;
        }
    }

    #[cold]
    #[inline(never)]
    pub(super) fn complete_at(
        &mut self,
        cpu: &mut crate::machine::Cpu,
        word: u32,
        operation: &FloatingPointOperation,
    ) -> Result<(), UnsupportedControl> {
        self.complete_selected(&mut cpu.state, word, operation, cpu.pc, cpu.retired)
    }

    #[cfg(test)]
    fn complete(&mut self, state: &mut GuestState, word: u32, operation: &FloatingPointOperation) -> Result<(), UnsupportedControl> {
        self.complete_selected(state, word, operation, 0, 0)
    }

    fn complete_selected(
        &mut self, state: &mut GuestState, word: u32, operation: &FloatingPointOperation,
        guest_pc: u64, retired_before: u64,
    ) -> Result<(), UnsupportedControl> {
        let mut capture = operands::Capture::before(state, operation);
        let (fpcr_before, fpsr_before) = (state.fpcr, state.fpsr);
        let outcome = crate::floating::complete(state, operation);
        let outputs = capture.finish(state, outcome.is_ok());
        let family = Family::of(operation);
        self.observations.record(observations::Event { family, word, pc:guest_pc, retired:retired_before, fpcr:fpcr_before, fpsr_before, fpsr_after:state.fpsr }, &capture, outputs);
        let key = Key {
            word,
            family,
            fpcr_before,
            fpsr_before,
            fpcr_after: state.fpcr,
            fpsr_after: state.fpsr,
            refused_enabled_exceptions: outcome.as_ref().err().map(|e| e.enabled_exceptions),
        };
        increment(&mut self.samples, &mut self.saturated);
        increment(&mut self.families[family as usize], &mut self.saturated);
        if let Some(count) = self.rows.get_mut(&key) {
            increment(count, &mut self.saturated);
        } else if self.rows.len() < ROW_LIMIT {
            self.rows.insert(key, 1);
        } else {
            increment(&mut self.dropped, &mut self.saturated);
        }
        outcome
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            algorithm: "splitmix64_uniform_slot_per_4096_event_stratum_v1",
            seed: self.seed,
            stratum_events: STRATUM,
            serviced_population: self.scheduled.saturating_sub(u64::from(self.remaining)),
            population_exact: self.population_exact,
            population_when_inexact: "conservative lower bound after overflow; may cease to be monotonic",
            samples: self.samples,
            family_samples: self.families,
            family_order: [
                Family::Binary,
                Family::Widening,
                Family::BFloat16,
                Family::Complex,
                Family::Fused,
                Family::Conversion,
                Family::Comparison,
                Family::ExtremaScale,
                Family::MinMax,
                Family::Rounding,
                Family::SquareRoot,
                Family::Estimate,
                Family::Refinement,
            ],
            detail_dropped: self.dropped,
            detail_row_limit: ROW_LIMIT,
            counter_saturated: self.saturated,
            operand_classification: true,
            native_success_covered: false,
            typed: self.observations.snapshot(),
            rows: self
                .rows
                .iter()
                .map(|(&key, &samples)| Row { key, samples })
                .collect(),
        }
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    pub(crate) fn enable_floating_profile(&mut self, seed: u64) {
        self.floating_profile = Some(Box::new(Sampler::new(seed)));
    }

    pub(crate) fn disable_floating_profile(&mut self) {
        self.floating_profile = None;
    }

    pub(crate) fn floating_profile_snapshot(&self) -> Option<Snapshot> {
        self.floating_profile
            .as_ref()
            .map(|sampler| sampler.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomized_strata_sample_once_per_stratum_and_count_every_event() {
        for seed in [0, 1, u64::MAX, 0x1234_5678_9abc_def0] {
            let mut sampler = Sampler::new(seed);
            let mut per_stratum = [0; 32];
            for event in 0..(STRATUM * per_stratum.len() as u32) {
                if sampler.tick() {
                    per_stratum[(event / STRATUM) as usize] += 1;
                }
                assert_eq!(sampler.scheduled.saturating_sub(u64::from(sampler.remaining)), u64::from(event + 1));
            }
            assert_eq!(per_stratum, [1; 32]);
        }
    }

    #[test]
    fn gap_extremes_partial_epochs_and_saturation_are_explicit() {
        assert_eq!(sample_gap(STRATUM - 1, 0), 1);
        assert_eq!(sample_gap(0, STRATUM - 1), 2 * STRATUM - 1);
        let mut sampler = Sampler::new(17);
        let first_slot = sampler.slot;
        for event in 1..=17 {
            let sampled = sampler.tick();
            assert_eq!(sampled, event == first_slot + 1);
            assert_eq!(sampler.snapshot().serviced_population, u64::from(event));
        }
        sampler.scheduled = u64::MAX - 1;
        sampler.remaining = 1;
        sampler.slot = 0;
        assert!(sampler.tick());
        assert!(!sampler.snapshot().population_exact);
        assert!(sampler.snapshot().counter_saturated);
        assert_eq!(sampler.scheduled, u64::MAX);
        let mut count = u64::MAX;
        let mut saturated = false;
        increment(&mut count, &mut saturated);
        assert_eq!(count, u64::MAX);
        assert!(saturated);
    }

    #[test]
    fn typed_reservoir_does_not_advance_event_selection_and_cpu_site_is_before_completion() {
        let operation=FloatingPointOperation::decode(0x1e20_2820).unwrap().unwrap();
        let mut sampled=Sampler::new(11);
        let mut control=Sampler::new(11);
        let mut cpu=crate::machine::Cpu::new(0x4000,crate::machine::exception::Pstate::reset(0));
        cpu.retired=123;
        for _ in 0..STRATUM*128 {
            let selected=sampled.tick();
            assert_eq!(selected,control.tick());
            if selected { sampled.complete_at(&mut cpu,0x1e20_2820,&operation).unwrap(); }
            assert_eq!((sampled.random,sampled.remaining,sampled.scheduled),
                (control.random,control.remaining,control.scheduled));
        }
        let snapshot=serde_json::to_value(sampled.snapshot()).unwrap();
        assert_eq!(snapshot["samples"],128);
        assert_eq!(snapshot["typed"]["witness_population"],128);
        for witness in snapshot["typed"]["witnesses"].as_array().unwrap() {
            assert_eq!(witness["guest_pc"],0x4000);
            assert_eq!(witness["retired_before"],123);
        }
        assert_eq!(cpu.pc,0x4000);
        assert_eq!(cpu.retired,123);
    }

    #[test]
    fn sampled_completion_preserves_full_state_and_refusal() {
        let word = 0x1e20_2820; // FADD S0, S1, S0, including a source/destination alias.
        let operation = FloatingPointOperation::decode(word).unwrap().unwrap();
        for fpcr in [0, 1 << 24, 1 << 8] {
            let mut expected = GuestState {
                fpcr,
                fpsr: 0x0800_0097,
                ..Default::default()
            };
            expected.v[0] = [0x3f80_0000, u64::MAX];
            expected.v[1] = [0x4000_0000, u64::MAX];
            let mut actual = expected.clone();
            let outcome = crate::floating::complete(&mut expected, &operation);
            let mut sampler = Sampler::new(0);
            assert_eq!(sampler.complete(&mut actual, word, &operation), outcome);
            assert_eq!(actual, expected);
            let report = sampler.snapshot();
            assert_eq!(report.samples, 1);
            assert_eq!(report.rows[0].key.fpsr_before, 0x0800_0097);
            assert_eq!(
                report.rows[0].key.refused_enabled_exceptions,
                outcome.err().map(|e| e.enabled_exceptions)
            );
            assert!(report.operand_classification);
        }
    }

    #[test]
    fn selected_capture_matches_sole_completion_across_typed_families_and_controls() {
        use stela_compiler::aarch64::{Register, floating::{Format, fused::FusedOperation,
            integer::{IntegerFormat,IntegerWidth,IntegerRounding},minmax::MinMaxOperation,
            rounding::RoundingOperation,precision::PrecisionRounding},simd::{arithmetic::Shape,
            comparison,conversion,estimate,fused,minmax,rounding,sqrt}};
        let integer=conversion::IntegerConversion { integer:conversion::IntegerOperand::Simd {
            register:0,format:IntegerFormat { width:IntegerWidth::Bits16,signed:false },shape:Shape::Vector128,
        },float:1,format:Format::Half,frac_bits:0 };
        let mut operations=Vec::from([
            FloatingPointOperation::decode(0x1e20_2820).unwrap().unwrap(),
            FloatingPointOperation::Fused(fused::Operand { operation:FusedOperation::Add,format:Format::Half,
                shape:Shape::Vector64,destination:1,addend:1,left:0,right:1,right_lane:Some(7) }),
            FloatingPointOperation::Conversion(conversion::Operand::FromInteger(integer)),
            FloatingPointOperation::Conversion(conversion::Operand::ToInteger { operand:integer,rounding:IntegerRounding::TowardZero }),
            FloatingPointOperation::Conversion(conversion::Operand::JavaScript { destination:Register::X(0),source:1 }),
            FloatingPointOperation::Comparison(comparison::Operand::ConditionalFlags { format:Format::Double,
                left:1,right:0,signal_all_nans:true,condition:0,fallback:11 }),
            FloatingPointOperation::Comparison(comparison::Operand::Predicate { operation:stela_compiler::aarch64::floating::comparison::Predicate::Equal,
                format:Format::Half,shape:Shape::Vector128,destination:0,left:0,right:comparison::CompareSource::Register(1) }),
            FloatingPointOperation::MinMax(minmax::Operand::Reduction { operation:MinMaxOperation::Maximum,
                format:Format::Half,shape:Shape::Vector128,destination:1,source:1 }),
            FloatingPointOperation::Estimate(estimate::Operand { kind:estimate::Kind::UnsignedReciprocal,
                format:Format::Single,shape:Shape::Vector128,destination:0,source:1 }),
            FloatingPointOperation::Estimate(estimate::Operand { kind:estimate::Kind::Reciprocal,
                format:Format::Half,shape:Shape::Vector64,destination:1,source:1 }),
            FloatingPointOperation::Rounding(rounding::Operand { operation:RoundingOperation::TowardZero,
                format:Format::Single,shape:Shape::Scalar,destination:1,source:1 }),
            FloatingPointOperation::SquareRoot(sqrt::Operand { format:Format::Half,shape:Shape::Vector128,destination:0,source:1 }),
        ]);
        for mode in [conversion::PrecisionMode::Widen { source:Format::Half,upper:true },
            conversion::PrecisionMode::Narrow { destination:Format::Half,upper:true,rounding:PrecisionRounding::Fpcr }] {
            operations.push(FloatingPointOperation::Conversion(conversion::Operand::Precision(conversion::PrecisionOperand { mode,destination:1,source:1 })));
        }
        let mut sampler=Sampler::new(31);
        for operation in operations {
            for fpcr in [0,1<<24,1<<19,1<<26,1<<8,(1<<8)|(1<<1)] {
                for nzcv in [0,1<<30] {
                    let state=GuestState { fpcr,nzcv,fpsr:0x0800_009f,
                        x:core::array::from_fn(|i| (i as u64).wrapping_mul(0xdead_beef)),
                        v:core::array::from_fn(|i| [0x3c00_8000_0001_7c01 ^ i as u64,0x4000_7e00_0000_bc00]),
                        ..Default::default() };
                    let mut expected=state.clone();
                    let outcome=crate::floating::complete(&mut expected,&operation);
                    let mut actual=state;
                    assert_eq!(sampler.complete_selected(&mut actual,0x1234,&operation,0x1000,17),outcome,"{operation:?}");
                    assert_eq!(actual,expected,"{operation:?}, fpcr={fpcr:x}");
                }
            }
        }
        let json=serde_json::to_value(sampler.snapshot()).unwrap();
        assert!(json["typed"]["fresh_exceptions"].is_null());
        assert!(json["typed"]["observed_guard_branch"].is_null());
        assert!(json["typed"]["sites"].as_array().unwrap().iter().all(|row| row[0][0]==0x1000));
        assert!(json["typed"]["witnesses"].as_array().unwrap().iter().all(|row| row["retired_before"]==17));
    }

    #[test]
    fn row_cap_preserves_existing_keys_and_all_sample_totals() {
        let operation = FloatingPointOperation::decode(0x1e20_2820)
            .unwrap()
            .unwrap();
        let mut sampler = Sampler::new(7);
        for word in 0..ROW_LIMIT as u32 + 17 {
            sampler
                .complete(&mut GuestState::default(), word, &operation)
                .unwrap();
        }
        sampler
            .complete(&mut GuestState::default(), 0, &operation)
            .unwrap();
        let report = sampler.snapshot();
        assert_eq!(report.rows.len(), ROW_LIMIT);
        assert_eq!(report.detail_dropped, 17);
        assert_eq!(report.samples, ROW_LIMIT as u64 + 18);
        assert_eq!(
            report.family_samples[Family::Binary as usize],
            report.samples
        );
        assert_eq!(report.rows[0].samples, 2);
    }

    #[test]
    fn preset_sticky_bits_remain_distinct_and_existing_row_saturation_is_reported() {
        let word = 0x1e20_2820;
        let operation = FloatingPointOperation::decode(word).unwrap().unwrap();
        let mut sampler = Sampler::new(3);
        for fpsr in [0, 1 << 4] {
            let mut state = GuestState {
                fpsr,
                ..Default::default()
            };
            sampler.complete(&mut state, word, &operation).unwrap();
        }
        assert_eq!(sampler.rows.len(), 2);
        let key = *sampler.rows.keys().next().unwrap();
        assert_eq!(key.fpsr_before, 0);
        assert_eq!(key.fpsr_after, 0);
        *sampler.rows.get_mut(&key).unwrap() = u64::MAX;
        sampler.samples = u64::MAX;
        sampler.families[Family::Binary as usize] = u64::MAX;
        sampler
            .complete(&mut GuestState::default(), word, &operation)
            .unwrap();
        let report = sampler.snapshot();
        assert!(report.counter_saturated);
        assert_eq!(report.samples, u64::MAX);
        assert_eq!(report.rows[0].samples, u64::MAX);
    }
}
