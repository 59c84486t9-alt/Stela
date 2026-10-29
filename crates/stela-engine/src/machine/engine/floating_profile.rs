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
// Keep useful detail across workloads while keeping a fixed per-engine bound.
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
pub struct Snapshot {
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
impl Snapshot {}

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
    fn complete(
        &mut self,
        state: &mut GuestState,
        word: u32,
        operation: &FloatingPointOperation,
    ) -> Result<(), UnsupportedControl> {
        self.complete_selected(state, word, operation, 0, 0)
    }

    fn complete_selected(
        &mut self,
        state: &mut GuestState,
        word: u32,
        operation: &FloatingPointOperation,
        guest_pc: u64,
        retired_before: u64,
    ) -> Result<(), UnsupportedControl> {
        let mut capture = operands::Capture::before(state, operation);
        let (fpcr_before, fpsr_before) = (state.fpcr, state.fpsr);
        let outcome = crate::floating::complete(state, operation);
        let outputs = capture.finish(state, outcome.is_ok());
        let family = Family::of(operation);
        self.observations.record(
            observations::Event {
                family,
                word,
                pc: guest_pc,
                retired: retired_before,
                fpcr: fpcr_before,
                fpsr_before,
                fpsr_after: state.fpsr,
            },
            &capture,
            outputs,
        );
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
    pub fn enable_floating_profile(&mut self, seed: u64) {
        self.floating_profile = Some(Box::new(Sampler::new(seed)));
    }

    pub fn disable_floating_profile(&mut self) {
        self.floating_profile = None;
    }

    pub fn floating_profile_snapshot(&self) -> Option<Snapshot> {
        self.floating_profile
            .as_ref()
            .map(|sampler| sampler.snapshot())
    }
}

#[cfg(test)]
mod tests;
