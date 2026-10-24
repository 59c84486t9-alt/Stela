//! Optional selected-recipe metadata. This is separate from the serialized
//! native artifact and never supplies execution or recovery authority.
use alloc::vec::Vec;

/// Counts emitted guest-register-frame memory operands on covered successful
/// paths, not DRAM transactions. Rust helpers and host xstate entry are outside
/// these counts. Resident uses describe recipe values, not encoded ARM operands.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RegisterTraffic {
    pub gpr_frame_loads: u64,
    pub gpr_direct_stores: u64,
    pub gpr_pressure_stores: u64,
    pub gpr_boundary_stores: u64,
    pub gpr_lifetime_stores: u64,
    pub resident_source_uses: u64,
    /// A subset of resident_source_uses; do not add it a second time.
    pub in_place_source_uses: u64,
    /// Recorded propagated constant outputs, not every immediate instruction.
    pub constant_outputs: u64,
    pub callee_stack_saves: u64,
    pub callee_stack_restores: u64,
    pub nzcv_frame_loads: u64,
    pub nzcv_pressure_stores: u64,
    pub nzcv_boundary_stores: u64,
    pub nzcv_direct_stores: u64,
    /// Peak retained GPR/NZCV values, aggregated by maximum rather than sum.
    pub peak_resident: u64,
}

impl RegisterTraffic {
    /// Saturating observational aggregation; true means totals lost precision.
    pub fn accumulate(&mut self, other: Self) -> bool {
        let mut saturated = false;
        macro_rules! add {
            ($($field:ident),+ $(,)?) => {$(
                saturated |= self.$field.checked_add(other.$field).is_none();
                self.$field = self.$field.saturating_add(other.$field);
            )+};
        }
        add!(
            gpr_frame_loads,
            gpr_direct_stores,
            gpr_pressure_stores,
            gpr_boundary_stores,
            gpr_lifetime_stores,
            resident_source_uses,
            in_place_source_uses,
            constant_outputs,
            callee_stack_saves,
            callee_stack_restores,
            nzcv_frame_loads,
            nzcv_pressure_stores,
            nzcv_boundary_stores,
            nzcv_direct_stores
        );
        self.peak_resident = self.peak_resident.max(other.peak_resident);
        saturated
    }

    pub(crate) fn region(stats: &crate::x86_64::AllocationStats) -> Self {
        Self {
            gpr_frame_loads: stats.state_loads as u64,
            gpr_pressure_stores: (stats.pressure_stores - stats.nzcv_pressure_stores) as u64,
            gpr_boundary_stores: (stats.exit_stores - stats.nzcv_boundary_stores) as u64,
            gpr_lifetime_stores: stats.lifetime_stores as u64,
            resident_source_uses: (stats.cache_hits + stats.in_place_source_uses) as u64,
            in_place_source_uses: stats.in_place_source_uses as u64,
            constant_outputs: stats.constant_writes as u64,
            callee_stack_saves: stats.callee_saves as u64,
            callee_stack_restores: stats.callee_restores as u64,
            nzcv_frame_loads: stats.flag_loads as u64,
            nzcv_pressure_stores: stats.nzcv_pressure_stores as u64,
            nzcv_boundary_stores: stats.nzcv_boundary_stores as u64,
            nzcv_direct_stores: (stats.flag_stores
                - stats.nzcv_pressure_stores
                - stats.nzcv_boundary_stores) as u64,
            peak_resident: stats.peak_resident as u64,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterRecipe {
    Allocated,
    Retained,
    ScalarCallback,
    PairCallback,
    Prefetch,
    Terminal,
}

/// A nonfaulting integer span or one successfully completed callback/terminal.
/// A returned prefix intersecting a span cannot credit its entire traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterSpan {
    pub source_start: usize,
    pub source_end: usize,
    pub recipe: RegisterRecipe,
    pub traffic: RegisterTraffic,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompileProfile {
    /// Ordered, non-overlapping covered spans. Missing words remain unknown.
    pub register_spans: Vec<RegisterSpan>,
}

impl CompileProfile {
    pub fn retained_bytes(&self) -> Option<usize> {
        self.register_spans
            .capacity()
            .checked_mul(size_of::<RegisterSpan>())
    }
}

pub(crate) fn terminal_traffic(terminal: &super::Terminator) -> Option<RegisterTraffic> {
    use super::{ExitKind, Terminator};
    use crate::aarch64::{Operation, Register};
    let mut traffic = RegisterTraffic::default();
    match terminal {
        Terminator::DirectCall(_) => traffic.gpr_direct_stores = 1,
        Terminator::Register { source, kind } => {
            traffic.gpr_frame_loads = u64::from(*source != Register::Zero);
            traffic.gpr_direct_stores = u64::from(*kind == ExitKind::Call);
        }
        Terminator::Branch(
            Operation::BranchZero { source, .. } | Operation::BranchBit { source, .. },
        ) => {
            traffic.gpr_frame_loads = u64::from(*source != Register::Zero);
        }
        Terminator::Branch(Operation::BranchCondition { condition, .. }) => {
            traffic.nzcv_frame_loads = u64::from(*condition < 14);
        }
        Terminator::FloatingPoint => return None,
        _ => {}
    }
    Some(traffic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GuestAddress, TargetCpu,
        block::{BlockProfile, CheckedMemoryProfile, CompilationPlan},
    };
    use alloc::vec;

    #[test]
    fn selected_metadata_preserves_bytes_and_counts_only_admitted_register_and_callback_paths() {
        let mut words = vec![0x9100_0400u32; 8]; // ADD X0,X0,#1.
        words.extend([0x3940_0121, 0x3900_013f, 0xa942_4ff4, 0xb400_0040]);
        let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        for memory in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            let profile = BlockProfile::SystemModeSharedV1(memory);
            let plan = || {
                CompilationPlan::new(&source, GuestAddress(0x4000), profile, TargetCpu::Baseline)
                    .unwrap()
            };
            let baseline = plan().compile().unwrap();
            let (actual, metadata) = plan().compile_profiled().unwrap();
            assert_eq!(actual.native.x86_64_code, baseline.native.x86_64_code);
            assert_eq!(actual.native.source_map, baseline.native.source_map);
            assert_eq!(actual.source_bytes, baseline.source_bytes);
            assert_eq!(actual.fault_recovery, baseline.fault_recovery);
            assert_eq!(metadata.register_spans.len(), 5);
            let first = metadata.register_spans[0];
            assert_eq!((first.source_start, first.source_end), (0, 8));
            assert_eq!(
                (
                    first.traffic.gpr_frame_loads,
                    first.traffic.gpr_boundary_stores
                ),
                (1, 1)
            );
            assert_eq!(first.traffic.resident_source_uses, 7);
            assert_eq!(first.traffic.in_place_source_uses, 7);
            let scalar = metadata.register_spans[1];
            assert_eq!(scalar.recipe, RegisterRecipe::ScalarCallback);
            assert_eq!(
                (
                    scalar.traffic.gpr_frame_loads,
                    scalar.traffic.gpr_direct_stores
                ),
                (1, 1)
            );
            let zero_store = metadata.register_spans[2];
            assert_eq!(
                (
                    zero_store.traffic.gpr_frame_loads,
                    zero_store.traffic.gpr_direct_stores
                ),
                (1, 0)
            );
            let pair = metadata.register_spans[3];
            assert_eq!(pair.recipe, RegisterRecipe::PairCallback);
            assert_eq!(
                pair.traffic.gpr_frame_loads,
                if memory == CheckedMemoryProfile::SpAlignmentEnabled {
                    2
                } else {
                    1
                }
            );
            assert_eq!(pair.traffic.gpr_direct_stores, 2);
            assert_eq!(metadata.register_spans[4].traffic.gpr_frame_loads, 1);
            assert!(
                metadata.retained_bytes().unwrap()
                    >= metadata.register_spans.len() * size_of::<RegisterSpan>()
            );
        }
    }

    #[test]
    fn rejected_single_word_candidate_stays_uncovered_instead_of_reporting_trial_stats() {
        let source: Vec<_> = [0x9100_0400u32, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let (_, metadata) = CompilationPlan::new(
            &source,
            GuestAddress(0x4000),
            BlockProfile::SystemModeSharedV1(CheckedMemoryProfile::SpAlignmentEnabled),
            TargetCpu::Baseline,
        )
        .unwrap()
        .compile_profiled()
        .unwrap();
        assert_eq!(metadata.register_spans.len(), 1);
        assert_eq!(metadata.register_spans[0].recipe, RegisterRecipe::Terminal);
        assert_eq!(metadata.register_spans[0].source_start, 1);
    }

    #[test]
    fn pressure_and_flag_stores_are_disjoint_and_peak_aggregation_is_a_maximum() {
        let stats = crate::x86_64::AllocationStats {
            state_loads: 9,
            pressure_stores: 7,
            exit_stores: 8,
            nzcv_pressure_stores: 2,
            nzcv_boundary_stores: 3,
            flag_stores: 6,
            cache_hits: 10,
            in_place_source_uses: 4,
            peak_resident: 5,
            ..Default::default()
        };
        let mut traffic = RegisterTraffic::region(&stats);
        assert_eq!(
            (traffic.gpr_pressure_stores, traffic.gpr_boundary_stores),
            (5, 5)
        );
        assert_eq!(
            (
                traffic.nzcv_pressure_stores,
                traffic.nzcv_boundary_stores,
                traffic.nzcv_direct_stores
            ),
            (2, 3, 1)
        );
        assert_eq!(traffic.resident_source_uses, 14);
        assert!(!traffic.accumulate(RegisterTraffic {
            peak_resident: 3,
            gpr_frame_loads: 1,
            ..Default::default()
        }));
        assert_eq!((traffic.peak_resident, traffic.gpr_frame_loads), (5, 10));
        traffic.gpr_frame_loads = u64::MAX;
        assert!(traffic.accumulate(RegisterTraffic {
            gpr_frame_loads: 1,
            ..Default::default()
        }));
    }
}
